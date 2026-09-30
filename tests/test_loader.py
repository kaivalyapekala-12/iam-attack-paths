import json
from pathlib import Path

from iam_paths.loader import load_account

SAMPLE = Path(__file__).parent.parent / "samples" / "sample_account.json"


def _actions_for(statements) -> set[str]:
    return {a for s in statements for a in s.actions}


def test_load_account_counts_everything():
    account = load_account(SAMPLE)
    assert {u.name for u in account.users} == {
        "alice", "bob", "carol", "dave", "eve", "frank", "grace", "ops-admin",
    }
    assert {g.name for g in account.groups} == {"intern", "Admins"}
    assert {r.name for r in account.roles} == {"LambdaAdminRole", "DeployRole"}
    assert "arn:aws:iam::123456789012:policy/AlicePolicy" in account.managed_policies


def test_alice_effective_statements_include_self_policy_rewrite():
    account = load_account(SAMPLE)
    alice = next(u for u in account.users if u.name == "alice")
    assert "iam:CreatePolicyVersion" in _actions_for(alice.effective_statements(account))


def test_bob_effective_statements_include_pass_role_and_lambda_actions():
    account = load_account(SAMPLE)
    bob = next(u for u in account.users if u.name == "bob")
    actions = _actions_for(bob.effective_statements(account))
    assert {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"} <= actions


def test_eve_inherits_add_user_to_group_from_intern_group():
    account = load_account(SAMPLE)
    eve = next(u for u in account.users if u.name == "eve")
    assert eve.inline_policies == []
    assert eve.attached_policies == []
    assert "iam:AddUserToGroup" in _actions_for(eve.effective_statements(account))


def test_grace_has_no_resolvable_statements_from_readonlyaccess():
    # Documents a real limitation: ReadOnlyAccess is AWS-managed, so its
    # document isn't in this dataset at all -- only the name/ARN pointer is.
    account = load_account(SAMPLE)
    grace = next(u for u in account.users if u.name == "grace")
    assert grace.effective_statements(account) == []


def test_deployrole_effective_statements_include_attach_user_policy():
    account = load_account(SAMPLE)
    deploy_role = next(r for r in account.roles if r.name == "DeployRole")
    assert "iam:AttachUserPolicy" in _actions_for(deploy_role.effective_statements(account))


def test_deployrole_trust_policy_allows_carol_to_assume_it():
    # Trust policies key the trusted principal under "Principal", not
    # "Resource" -- this is what technique 4 (assume role) will check
    # against sts:AssumeRole permission on carol's side.
    account = load_account(SAMPLE)
    deploy_role = next(r for r in account.roles if r.name == "DeployRole")
    trust_statement = deploy_role.assume_role_policy.statements[0]
    assert trust_statement.actions == ["sts:AssumeRole"]
    assert trust_statement.principal == {"AWS": "arn:aws:iam::123456789012:user/carol"}


def test_lambdaadminrole_trust_policy_trusts_the_lambda_service():
    account = load_account(SAMPLE)
    lambda_role = next(r for r in account.roles if r.name == "LambdaAdminRole")
    trust_statement = lambda_role.assume_role_policy.statements[0]
    assert trust_statement.principal == {"Service": "lambda.amazonaws.com"}


def test_loader_decodes_url_encoded_policy_document(tmp_path):
    # A URL-encoded PolicyDocument string is a real quirk of some raw IAM
    # API responses (as opposed to boto3, which usually decodes it for you).
    encoded_doc = (
        "%7B%22Version%22%3A%20%222012-10-17%22%2C%20%22Statement%22%3A%20"
        "%5B%7B%22Effect%22%3A%20%22Allow%22%2C%20%22Action%22%3A%20%22s3%3AGetObject%22%2C%20"
        "%22Resource%22%3A%20%22%2A%22%7D%5D%7D"
    )
    raw_account = {
        "UserDetailList": [
            {
                "UserName": "url-encoded-user",
                "Arn": "arn:aws:iam::123456789012:user/url-encoded-user",
                "UserId": "U1",
                "UserPolicyList": [
                    {"PolicyName": "EncodedInline", "PolicyDocument": encoded_doc}
                ],
                "AttachedManagedPolicies": [],
                "GroupList": [],
            }
        ],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    path = tmp_path / "url_encoded_account.json"
    path.write_text(json.dumps(raw_account))

    account = load_account(path)
    user = account.users[0]
    assert _actions_for(user.effective_statements(account)) == {"s3:GetObject"}
