"""Privilege-escalation checks.

Each check is a small function with the signature (principal, account) ->
list[Edge]. It asks the evaluator a handful of yes/no questions about one
technique and turns any "yes" into an Edge -- "this principal can become
that target, using this technique." graph.py (step 5) runs every check
against every principal (users, groups, AND roles -- see
Account.all_principals) to build the full attack graph.

Techniques are numbered to match the plan and Rhino Security Labs' AWS
privilege-escalation research, which this list is based on:
https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

Only ALLOWED counts as an edge, not ALLOWED_WITH_CONDITION -- a condition's
truth depends on runtime request context we don't have (see evaluator.py),
so a conditional grant isn't a path we can claim actually exists. This is a
v1 limitation: conditional escalation paths are invisible to the graph,
though the evaluator still surfaces them for the report (step 7).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iam_paths.evaluator import Decision, can
from iam_paths.models import ADMIN, Edge, Group, PolicyDocument, Role, User

if TYPE_CHECKING:
    from iam_paths.models import Account


def _allowed(principal: User | Group | Role, action: str, resource: str, account: Account) -> bool:
    return can(principal, action, resource, account) == Decision.ALLOWED


def check_new_policy_version(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#1: iam:CreatePolicyVersion on a policy attached to self -> self can
    push a new default version of that policy granting themselves
    AdministratorAccess."""
    edges = []
    for ref in principal.attached_policies:
        if _allowed(principal, "iam:CreatePolicyVersion", ref.arn, account):
            edges.append(
                Edge(
                    source=principal.arn,
                    target=ADMIN,
                    technique="new_policy_version",
                    permissions_used=["iam:CreatePolicyVersion"],
                )
            )
    return edges


# Note on scope: iam:AttachUserPolicy's *target* (the Resource) must be a
# User, but the *caller* can be any principal type -- a Role like
# DeployRole can legitimately call it against some user. So this checks
# each of the three actions against every principal regardless of the
# caller's own type; what matters is whether the resource pattern reaches
# principal.arn, either as a literal self-match or via an unrestricted "*"
# grant. An unrestricted grant is flagged even though the caller's own ARN
# usually isn't a *valid* target for that specific action (e.g. DeployRole
# "attaching to itself" via AttachUserPolicy wouldn't actually work in real
# AWS) -- but a Resource: "*" grant can already reach every real, valid
# target of that type, which is equally dangerous, so v1 doesn't try to
# distinguish the two.
_ATTACH_ACTIONS = ("iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy")
_PUT_ACTIONS = ("iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy")


def check_attach_managed_policy(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#2: Attach{User,Group,Role}Policy where the principal can target
    itself (a specific match on its own ARN, or a wildcard resource broad
    enough to cover it) -> attach AdministratorAccess to itself."""
    edges = []
    for action in _ATTACH_ACTIONS:
        if _allowed(principal, action, principal.arn, account):
            edges.append(
                Edge(
                    source=principal.arn,
                    target=ADMIN,
                    technique="attach_managed_policy",
                    permissions_used=[action],
                )
            )
    return edges


def check_write_inline_policy(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#3: Put{User,Group,Role}Policy where the principal can target itself
    -> write a brand-new inline policy granting itself admin."""
    edges = []
    for action in _PUT_ACTIONS:
        if _allowed(principal, action, principal.arn, account):
            edges.append(
                Edge(
                    source=principal.arn,
                    target=ADMIN,
                    technique="write_inline_policy",
                    permissions_used=[action],
                )
            )
    return edges


def _trust_policy_allows(role: Role, principal: User | Group | Role) -> bool:
    """A role's trust policy is a resource-based policy on the role, not an
    identity policy on the principal -- can() can't evaluate it. Its
    Principal field names who's trusted directly, so match it by ARN
    instead of running it through the evaluator."""
    for statement in role.assume_role_policy.statements:
        if statement.effect != "Allow":
            continue
        trusted = statement.principal
        if isinstance(trusted, dict) and trusted.get("AWS") == principal.arn:
            return True
    return False


def check_assume_role(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#4: sts:AssumeRole granted AND the role's trust policy allows this
    principal -> self can become that role."""
    edges = []
    for role in account.roles:
        if role.arn == principal.arn:
            continue
        if _trust_policy_allows(role, principal) and _allowed(
            principal, "sts:AssumeRole", role.arn, account
        ):
            edges.append(
                Edge(
                    source=principal.arn,
                    target=role.arn,
                    technique="assume_role",
                    permissions_used=["sts:AssumeRole"],
                )
            )
    return edges


def check_create_access_key(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#5: iam:CreateAccessKey on another user -> mint that user's
    long-term credentials and act as them."""
    edges = []
    for user in account.users:
        if user.arn == principal.arn:
            continue
        if _allowed(principal, "iam:CreateAccessKey", user.arn, account):
            edges.append(
                Edge(
                    source=principal.arn,
                    target=user.arn,
                    technique="create_access_key",
                    permissions_used=["iam:CreateAccessKey"],
                )
            )
    return edges


def check_add_user_to_group(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#6: iam:AddUserToGroup -> join any group and inherit its
    permissions, including an admin group. Only a User can be a group
    member, so this doesn't apply to a Group or Role principal."""
    if not isinstance(principal, User):
        return []
    edges = []
    for group in account.groups:
        if _allowed(principal, "iam:AddUserToGroup", group.arn, account):
            edges.append(
                Edge(
                    source=principal.arn,
                    target=group.arn,
                    technique="add_user_to_group",
                    permissions_used=["iam:AddUserToGroup"],
                )
            )
    return edges


def check_console_password(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#7: iam:CreateLoginProfile / iam:UpdateLoginProfile on another user
    -> set (or reset) their console password and log in as them."""
    edges = []
    for user in account.users:
        if user.arn == principal.arn:
            continue
        matched = [
            action
            for action in ("iam:CreateLoginProfile", "iam:UpdateLoginProfile")
            if _allowed(principal, action, user.arn, account)
        ]
        if matched:
            edges.append(
                Edge(
                    source=principal.arn,
                    target=user.arn,
                    technique="console_password",
                    permissions_used=matched,
                )
            )
    return edges


def _grants_full_admin(document: PolicyDocument) -> bool:
    return any(
        s.effect == "Allow" and "*" in s.actions and "*" in s.resources for s in document.statements
    )


def check_rollback_policy_version(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#8: iam:SetDefaultPolicyVersion, where some non-default version of a
    policy attached to self grants full admin ("*" on "*") and the current
    default doesn't -- roll back to that version to regain it. Needs the
    policy's full version history, not just the currently-effective
    document, which is why Policy.versions exists."""
    edges = []
    for ref in principal.attached_policies:
        policy = account.managed_policies.get(ref.arn)
        if policy is None or _grants_full_admin(policy.document):
            continue
        broader_version_exists = any(
            v.document is not policy.document and _grants_full_admin(v.document)
            for v in policy.versions
        )
        can_rollback = _allowed(principal, "iam:SetDefaultPolicyVersion", ref.arn, account)
        if broader_version_exists and can_rollback:
            edges.append(
                Edge(
                    source=principal.arn,
                    target=ADMIN,
                    technique="rollback_policy_version",
                    permissions_used=["iam:SetDefaultPolicyVersion"],
                )
            )
    return edges


def check_rewrite_trust_policy(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#9: iam:UpdateAssumeRolePolicy + sts:AssumeRole on a role -- rewrite
    its trust policy to trust yourself, then assume it. Unlike
    check_assume_role, this doesn't require the *current* trust policy to
    already allow the principal; that's the whole point of the technique."""
    edges = []
    for role in account.roles:
        if role.arn == principal.arn:
            continue
        if _allowed(principal, "iam:UpdateAssumeRolePolicy", role.arn, account) and _allowed(
            principal, "sts:AssumeRole", role.arn, account
        ):
            edges.append(
                Edge(
                    source=principal.arn,
                    target=role.arn,
                    technique="rewrite_trust_policy",
                    permissions_used=["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
                )
            )
    return edges


def _pass_role_edges(
    principal: User | Group | Role, account: Account, technique: str, *service_actions: str
) -> list[Edge]:
    """Shared by #10/#12/#13: all three need iam:PassRole on a specific
    role plus one or two unrestricted service actions ("*") that use it to
    run code or infrastructure as that role."""
    edges = []
    for role in account.roles:
        if role.arn == principal.arn:
            continue
        if not _allowed(principal, "iam:PassRole", role.arn, account):
            continue
        if all(_allowed(principal, action, "*", account) for action in service_actions):
            edges.append(
                Edge(
                    source=principal.arn,
                    target=role.arn,
                    technique=technique,
                    permissions_used=["iam:PassRole", *service_actions],
                )
            )
    return edges


def check_lambda_pass_role(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#10: iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction ->
    create a Lambda function running as the passed role, then invoke it."""
    return _pass_role_edges(
        principal, account, "lambda_pass_role", "lambda:CreateFunction", "lambda:InvokeFunction"
    )


def check_update_lambda_code(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#11: lambda:UpdateFunctionCode on a function that already runs as a
    privileged role -> overwrite its code to run as that role next
    invocation. Depends on account.lambda_functions, which is never
    populated from the offline sample (see LambdaFunction's docstring) --
    this check only ever finds something once a live-mode loader or a test
    supplies that inventory."""
    edges = []
    for function in account.lambda_functions:
        role = next((r for r in account.roles if r.arn == function.execution_role_arn), None)
        if role is None:
            continue
        if _allowed(principal, "lambda:UpdateFunctionCode", function.arn, account):
            edges.append(
                Edge(
                    source=principal.arn,
                    target=role.arn,
                    technique="update_lambda_code",
                    permissions_used=["lambda:UpdateFunctionCode"],
                )
            )
    return edges


def check_ec2_pass_role(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#12: iam:PassRole + ec2:RunInstances -> launch an EC2 instance with
    the passed role's instance profile, then reach the role's credentials
    from inside it."""
    return _pass_role_edges(principal, account, "ec2_pass_role", "ec2:RunInstances")


def check_cloudformation_pass_role(principal: User | Group | Role, account: Account) -> list[Edge]:
    """#13: iam:PassRole + cloudformation:CreateStack -> create a stack
    that runs as the passed role."""
    return _pass_role_edges(
        principal, account, "cloudformation_pass_role", "cloudformation:CreateStack"
    )


CHECKS = [
    check_new_policy_version,
    check_attach_managed_policy,
    check_write_inline_policy,
    check_assume_role,
    check_create_access_key,
    check_add_user_to_group,
    check_console_password,
    check_rollback_policy_version,
    check_rewrite_trust_policy,
    check_lambda_pass_role,
    check_update_lambda_code,
    check_ec2_pass_role,
    check_cloudformation_pass_role,
]


def run_all_checks(principal: User | Group | Role, account: Account) -> list[Edge]:
    edges = []
    for check in CHECKS:
        edges.extend(check(principal, account))
    return edges
