"""Turn an attack path into a fix: the cheapest permission to remove, a
rewritten policy with it gone, a severity, and NIST 800-53 control tags.

"Cheapest to remove" = the hop that needs the fewest permissions to work.
A hop needing just one permission (e.g. carol's sts:AssumeRole) is broken
by deleting one line from one policy; a hop needing three (bob's PassRole +
CreateFunction + InvokeFunction) still only needs ONE of them gone to
break the chain, so the first-listed permission is used -- by convention
(see checks.py) it's always the technique's most central permission (e.g.
iam:PassRole, not the service action that merely uses it). Ties between
equally-cheap hops favor the earliest hop in the path: cutting the chain
as close to the attacker's own identity as possible is both the narrowest
fix and the easiest one to explain.

A hop with no permissions_used at all (technique "already_admin" -- the
target already had AdministratorAccess before this path even reached it)
can't be fixed by editing a policy statement, so it's never a remediation
candidate; removing *earlier* access is always the real fix for those.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from iam_paths.evaluator import action_matches
from iam_paths.models import ADMIN, Account, Group, PolicyDocument, Role, Statement, User

if TYPE_CHECKING:
    from iam_paths.graph import Hop


@dataclass(frozen=True)
class Grant:
    """Where a permission actually comes from: which principal's policy
    (owner), which policy (by name, and by ARN if it's a managed policy --
    None means inline), which document, and the specific statement."""

    owner: User | Group | Role
    policy_name: str
    policy_arn: str | None
    document: PolicyDocument
    statement: Statement


def _candidate_documents(principal: User | Group | Role, account: Account):
    """Yield (owner, policy_name, policy_arn, document) for every policy
    document that contributes to principal's effective permissions: its
    own inline and attached policies, plus -- for a User -- every group
    it's a member of. This mirrors models.py's _own_statements/
    effective_statements, but keeps each statement tagged with which
    policy and which owner it came from, which effective_statements()
    deliberately throws away."""
    for policy in principal.inline_policies:
        yield principal, policy.name, None, policy.document
    for ref in principal.attached_policies:
        policy = account.managed_policies.get(ref.arn)
        if policy is not None:
            yield principal, policy.name, policy.arn, policy.document
    if isinstance(principal, User):
        for group in account.groups:
            if group.name not in principal.group_names:
                continue
            for policy in group.inline_policies:
                yield group, policy.name, None, policy.document
            for ref in group.attached_policies:
                policy = account.managed_policies.get(ref.arn)
                if policy is not None:
                    yield group, policy.name, policy.arn, policy.document


def find_grant(principal: User | Group | Role, account: Account, permission: str) -> Grant | None:
    """The first Allow statement, anywhere in principal's effective
    policies, that grants `permission`. Resource is deliberately not
    checked here -- the caller already knows this permission was the one
    that made some check pass, so any Allow statement naming the action is
    the one to fix."""
    for owner, policy_name, policy_arn, document in _candidate_documents(principal, account):
        for statement in document.statements:
            if statement.effect == "Allow" and action_matches(statement, permission):
                return Grant(
                    owner=owner,
                    policy_name=policy_name,
                    policy_arn=policy_arn,
                    document=document,
                    statement=statement,
                )
    return None


def _document_without_permission(
    document: PolicyDocument, statement: Statement, permission: str
) -> PolicyDocument:
    new_statements = []
    for s in document.statements:
        if s is not statement:
            new_statements.append(s)
            continue
        remaining = [a for a in s.actions if a.lower() != permission.lower()]
        if remaining:
            new_statements.append(replace(s, actions=remaining))
        # else: this was the statement's only action -- drop it entirely,
        # since a statement granting nothing is not a meaningful fix to show.
    return PolicyDocument(statements=new_statements)


def _document_to_raw(document: PolicyDocument) -> dict[str, Any]:
    statements = []
    for s in document.statements:
        raw: dict[str, Any] = {"Effect": s.effect}
        if s.sid:
            raw["Sid"] = s.sid
        if s.actions:
            raw["Action"] = s.actions
        if s.not_action:
            raw["NotAction"] = s.not_action
        if s.resources:
            raw["Resource"] = s.resources
        if s.not_resource:
            raw["NotResource"] = s.not_resource
        if s.condition:
            raw["Condition"] = s.condition
        statements.append(raw)
    return {"Version": "2012-10-17", "Statement": statements}


@dataclass(frozen=True)
class Finding:
    principal_arn: str
    path: list[Hop]
    removed_permission: str
    grant: Grant
    fixed_document: PolicyDocument
    severity: str
    control_tags: list[str]

    @property
    def fixed_policy_json(self) -> dict[str, Any]:
        return _document_to_raw(self.fixed_document)


def _cheapest_hop(path: list[Hop]) -> Hop | None:
    candidates = [hop for hop in path if hop.permissions_used]
    if not candidates:
        return None
    return min(candidates, key=lambda hop: len(hop.permissions_used))


def remediate(account: Account, principal_arn: str, path: list[Hop] | None) -> Finding | None:
    if not path:
        return None

    hop = _cheapest_hop(path)
    if hop is None:
        return None

    source = account.principal_by_arn(hop.source)
    if source is None:
        return None

    removed_permission = hop.permissions_used[0]
    grant = find_grant(source, account, removed_permission)
    if grant is None:
        return None

    fixed_document = _document_without_permission(
        grant.document, grant.statement, removed_permission
    )

    severity = "Critical" if len(path) == 1 else "High"
    control_tags = ["AC-6"]
    if hop.target == ADMIN:
        control_tags.append("AC-6(5)")

    return Finding(
        principal_arn=principal_arn,
        path=path,
        removed_permission=removed_permission,
        grant=grant,
        fixed_document=fixed_document,
        severity=severity,
        control_tags=control_tags,
    )


def _replace_principal(account: Account, new_principal: User | Group | Role) -> Account:
    if isinstance(new_principal, User):
        users = [new_principal if u.arn == new_principal.arn else u for u in account.users]
        return replace(account, users=users)
    if isinstance(new_principal, Group):
        groups = [new_principal if g.arn == new_principal.arn else g for g in account.groups]
        return replace(account, groups=groups)
    roles = [new_principal if r.arn == new_principal.arn else r for r in account.roles]
    return replace(account, roles=roles)


def apply_fix(account: Account, finding: Finding) -> Account:
    """Return a NEW Account with the finding's fix applied -- the original
    is never mutated, so the caller can re-run the graph on both and
    compare. This is the test that actually proves a fix works: rebuild
    the graph from the returned account and confirm the path is gone."""
    grant = finding.grant

    if grant.policy_arn is None:
        new_inline = [
            replace(p, document=finding.fixed_document)
            if p.name == grant.policy_name and p.document is grant.document
            else p
            for p in grant.owner.inline_policies
        ]
        new_owner = replace(grant.owner, inline_policies=new_inline)
        return _replace_principal(account, new_owner)

    new_policy = replace(
        account.managed_policies[grant.policy_arn], document=finding.fixed_document
    )
    new_managed_policies = {**account.managed_policies, grant.policy_arn: new_policy}
    return replace(account, managed_policies=new_managed_policies)
