from pathlib import Path

from iam_paths.checks import (
    CHECKS,
    check_add_user_to_group,
    check_assume_role,
    check_attach_managed_policy,
    check_cloudformation_pass_role,
    check_console_password,
    check_create_access_key,
    check_ec2_pass_role,
    check_lambda_pass_role,
    check_new_policy_version,
    check_rewrite_trust_policy,
    check_rollback_policy_version,
    check_update_lambda_code,
    check_write_inline_policy,
    run_all_checks,
)
from iam_paths.loader import load_account
from iam_paths.models import (
    ADMIN,
    Account,
    LambdaFunction,
    ManagedPolicyRef,
    Policy,
    PolicyDocument,
    PolicyVersion,
    Role,
    Statement,
    User,
)

SAMPLE = Path(__file__).parent.parent / "samples" / "sample_account.json"


def _user(account: Account, name: str):
    return next(u for u in account.users if u.name == name)


def _role(account: Account, name: str):
    return next(r for r in account.roles if r.name == name)


def _group(account: Account, name: str):
    return next(g for g in account.groups if g.name == name)


def test_alice_can_create_policy_version_on_her_own_policy_edge_to_admin():
    account = load_account(SAMPLE)
    alice = _user(account, "alice")
    edges = check_new_policy_version(alice, account)
    assert len(edges) == 1
    assert edges[0].source == alice.arn
    assert edges[0].target == ADMIN
    assert edges[0].technique == "new_policy_version"


def test_deployrole_attach_user_policy_on_wildcard_resource_edge_to_admin():
    # DeployRole's own permission is iam:AttachUserPolicy on Resource "*" --
    # an unrestricted grant that can reach any user in the account, so it's
    # flagged as an edge straight to ADMIN (see checks.py's note on scope).
    account = load_account(SAMPLE)
    deploy_role = _role(account, "DeployRole")
    edges = check_attach_managed_policy(deploy_role, account)
    assert len(edges) == 1
    assert edges[0].source == deploy_role.arn
    assert edges[0].target == ADMIN
    assert edges[0].permissions_used == ["iam:AttachUserPolicy"]


def test_carol_can_assume_deployrole():
    account = load_account(SAMPLE)
    carol = _user(account, "carol")
    deploy_role = _role(account, "DeployRole")
    edges = check_assume_role(carol, account)
    assert len(edges) == 1
    assert edges[0].source == carol.arn
    assert edges[0].target == deploy_role.arn
    assert edges[0].technique == "assume_role"


def test_dave_can_create_access_key_for_ops_admin():
    account = load_account(SAMPLE)
    dave = _user(account, "dave")
    ops_admin = _user(account, "ops-admin")
    edges = check_create_access_key(dave, account)
    assert len(edges) == 1
    assert edges[0].source == dave.arn
    assert edges[0].target == ops_admin.arn
    assert edges[0].technique == "create_access_key"


def test_eve_can_add_herself_to_admins_group():
    account = load_account(SAMPLE)
    eve = _user(account, "eve")
    admins = _group(account, "Admins")
    edges = check_add_user_to_group(eve, account)
    assert len(edges) == 1
    assert edges[0].source == eve.arn
    assert edges[0].target == admins.arn
    assert edges[0].technique == "add_user_to_group"


def test_group_principal_cannot_add_user_to_group():
    # A Group can never be a member of another group -- only a User can --
    # so this check must return nothing for a Group principal, even if it
    # somehow had iam:AddUserToGroup granted.
    account = load_account(SAMPLE)
    intern = _group(account, "intern")
    assert check_add_user_to_group(intern, account) == []


def test_frank_has_no_escalation_edges_because_deny_beats_his_broad_allow():
    account = load_account(SAMPLE)
    frank = _user(account, "frank")
    assert run_all_checks(frank, account) == []


def test_grace_readonly_has_no_escalation_edges():
    account = load_account(SAMPLE)
    grace = _user(account, "grace")
    assert run_all_checks(grace, account) == []


def test_bob_can_pass_lambdaadminrole_to_a_lambda_function():
    account = load_account(SAMPLE)
    bob = _user(account, "bob")
    lambda_admin_role = _role(account, "LambdaAdminRole")
    edges = check_lambda_pass_role(bob, account)
    assert len(edges) == 1
    assert edges[0].source == bob.arn
    assert edges[0].target == lambda_admin_role.arn
    assert edges[0].technique == "lambda_pass_role"


def test_checks_list_matches_implemented_techniques():
    assert len(CHECKS) == 13


def test_write_inline_policy_returns_no_edge_when_not_allowed():
    account = load_account(SAMPLE)
    grace = _user(account, "grace")
    assert check_write_inline_policy(grace, account) == []


def test_console_password_creates_edge_to_target_user():
    attacker = User(
        name="attacker",
        arn="arn:aws:iam::123456789012:user/attacker",
        user_id="A1",
        inline_policies=[
            Policy(
                name="p",
                document=PolicyDocument(
                    statements=[
                        Statement(
                            effect="Allow", actions=["iam:CreateLoginProfile"], resources=["*"]
                        )
                    ]
                ),
            )
        ],
    )
    victim = User(name="victim", arn="arn:aws:iam::123456789012:user/victim", user_id="A2")
    account = Account(users=[attacker, victim])

    edges = check_console_password(attacker, account)
    assert len(edges) == 1
    assert edges[0].source == attacker.arn
    assert edges[0].target == victim.arn
    assert edges[0].technique == "console_password"


def test_rollback_policy_version_finds_a_broader_older_version():
    admin_version = PolicyVersion(
        version_id="v1",
        document=PolicyDocument(
            statements=[Statement(effect="Allow", actions=["*"], resources=["*"])]
        ),
    )
    scoped_version = PolicyVersion(
        version_id="v2",
        document=PolicyDocument(
            statements=[Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"])]
        ),
    )
    policy_arn = "arn:aws:iam::123456789012:policy/RolledBack"
    policy = Policy(
        name="RolledBack",
        arn=policy_arn,
        document=scoped_version.document,
        versions=[admin_version, scoped_version],
    )
    attacker = User(
        name="attacker",
        arn="arn:aws:iam::123456789012:user/attacker",
        user_id="A1",
        inline_policies=[
            Policy(
                name="p",
                document=PolicyDocument(
                    statements=[
                        Statement(
                            effect="Allow",
                            actions=["iam:SetDefaultPolicyVersion"],
                            resources=[policy_arn],
                        )
                    ]
                ),
            )
        ],
        attached_policies=[ManagedPolicyRef(name="RolledBack", arn=policy_arn)],
    )
    account = Account(users=[attacker], managed_policies={policy_arn: policy})

    edges = check_rollback_policy_version(attacker, account)
    assert len(edges) == 1
    assert edges[0].target == ADMIN
    assert edges[0].technique == "rollback_policy_version"


def test_rollback_policy_version_skips_when_no_broader_version_exists():
    only_version = PolicyVersion(
        version_id="v1",
        document=PolicyDocument(
            statements=[Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"])]
        ),
    )
    policy_arn = "arn:aws:iam::123456789012:policy/NeverAdmin"
    policy = Policy(
        name="NeverAdmin", arn=policy_arn, document=only_version.document, versions=[only_version]
    )
    attacker = User(
        name="attacker",
        arn="arn:aws:iam::123456789012:user/attacker",
        user_id="A1",
        inline_policies=[
            Policy(
                name="p",
                document=PolicyDocument(
                    statements=[
                        Statement(
                            effect="Allow",
                            actions=["iam:SetDefaultPolicyVersion"],
                            resources=[policy_arn],
                        )
                    ]
                ),
            )
        ],
        attached_policies=[ManagedPolicyRef(name="NeverAdmin", arn=policy_arn)],
    )
    account = Account(users=[attacker], managed_policies={policy_arn: policy})

    assert check_rollback_policy_version(attacker, account) == []


def test_rewrite_trust_policy_does_not_require_current_trust():
    # The whole point of this technique is that the role's CURRENT trust
    # policy does NOT need to allow the principal yet -- they rewrite it.
    role = Role(
        name="Untrusting",
        arn="arn:aws:iam::123456789012:role/Untrusting",
        role_id="R1",
        assume_role_policy=PolicyDocument(statements=[]),
    )
    attacker = User(
        name="attacker",
        arn="arn:aws:iam::123456789012:user/attacker",
        user_id="A1",
        inline_policies=[
            Policy(
                name="p",
                document=PolicyDocument(
                    statements=[
                        Statement(
                            effect="Allow",
                            actions=["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
                            resources=[role.arn],
                        )
                    ]
                ),
            )
        ],
    )
    account = Account(users=[attacker], roles=[role])

    edges = check_rewrite_trust_policy(attacker, account)
    assert len(edges) == 1
    assert edges[0].target == role.arn
    assert edges[0].technique == "rewrite_trust_policy"


def test_update_lambda_code_finds_nothing_without_lambda_function_inventory():
    # samples/sample_account.json never populates account.lambda_functions
    # (get-account-authorization-details doesn't include it), so this must
    # be a real no-op against the canonical sample.
    account = load_account(SAMPLE)
    bob = _user(account, "bob")
    assert check_update_lambda_code(bob, account) == []


def test_update_lambda_code_creates_edge_when_function_inventory_is_supplied():
    role = Role(
        name="FnRole",
        arn="arn:aws:iam::123456789012:role/FnRole",
        role_id="R1",
        assume_role_policy=PolicyDocument(statements=[]),
    )
    function_arn = "arn:aws:lambda:us-east-1:123456789012:function:privileged-fn"
    attacker = User(
        name="attacker",
        arn="arn:aws:iam::123456789012:user/attacker",
        user_id="A1",
        inline_policies=[
            Policy(
                name="p",
                document=PolicyDocument(
                    statements=[
                        Statement(
                            effect="Allow",
                            actions=["lambda:UpdateFunctionCode"],
                            resources=[function_arn],
                        )
                    ]
                ),
            )
        ],
    )
    account = Account(
        users=[attacker],
        roles=[role],
        lambda_functions=[LambdaFunction(arn=function_arn, execution_role_arn=role.arn)],
    )

    edges = check_update_lambda_code(attacker, account)
    assert len(edges) == 1
    assert edges[0].target == role.arn
    assert edges[0].technique == "update_lambda_code"


def test_ec2_and_cloudformation_pass_role_edges():
    role = Role(
        name="Infra",
        arn="arn:aws:iam::123456789012:role/Infra",
        role_id="R1",
        assume_role_policy=PolicyDocument(statements=[]),
    )
    attacker = User(
        name="attacker",
        arn="arn:aws:iam::123456789012:user/attacker",
        user_id="A1",
        inline_policies=[
            Policy(
                name="p",
                document=PolicyDocument(
                    statements=[
                        Statement(
                            effect="Allow",
                            actions=["iam:PassRole"],
                            resources=[role.arn],
                        ),
                        Statement(
                            effect="Allow",
                            actions=["ec2:RunInstances", "cloudformation:CreateStack"],
                            resources=["*"],
                        ),
                    ]
                ),
            )
        ],
    )
    account = Account(users=[attacker], roles=[role])

    ec2_edges = check_ec2_pass_role(attacker, account)
    cfn_edges = check_cloudformation_pass_role(attacker, account)
    assert len(ec2_edges) == 1
    assert ec2_edges[0].technique == "ec2_pass_role"
    assert len(cfn_edges) == 1
    assert cfn_edges[0].technique == "cloudformation_pass_role"
