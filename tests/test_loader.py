import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from iam_paths.loader import from_boto3, load_account

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


def _user_page(name: str) -> dict:
    return {
        "UserName": name,
        "Arn": f"arn:aws:iam::123456789012:user/{name}",
        "UserId": name.upper(),
        "UserPolicyList": [],
        "AttachedManagedPolicies": [],
        "GroupList": [],
    }


def _empty_page(user_name: str) -> dict:
    return {
        "UserDetailList": [_user_page(user_name)],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }


def test_from_boto3_uses_the_requested_profile_and_paginates():
    # boto3 is an optional "live" extra (see pyproject.toml) -- offline
    # dev/CI installs (`pip install -e ".[dev]"`) never have it, so this
    # test skips cleanly there instead of failing on an unrelated missing
    # dependency.
    pytest.importorskip("boto3")
    page_one = _empty_page("alice")
    page_two = _empty_page("bob")

    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [page_one, page_two]
    mock_client.get_paginator.return_value = mock_paginator

    mock_session = MagicMock()
    mock_session.client.return_value = mock_client

    with patch("boto3.Session", return_value=mock_session) as mock_session_cls:
        account = from_boto3("audit")

    mock_session_cls.assert_called_once_with(profile_name="audit")
    mock_session.client.assert_called_once_with("iam")
    mock_client.get_paginator.assert_called_once_with("get_account_authorization_details")
    assert {u.name for u in account.users} == {"alice", "bob"}
