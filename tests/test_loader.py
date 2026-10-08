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
    # from_boto3 now also fetches resource inventories (Lambda, EC2, ...)
    # via other service clients, so "iam" is called more than once, and
    # get_paginator() is called with several different operation names --
    # any_call, not called_once_with.
    mock_session.client.assert_any_call("iam")
    mock_client.get_paginator.assert_any_call("get_account_authorization_details")
    assert {u.name for u in account.users} == {"alice", "bob"}


def _mock_paginator(pages: list[dict]) -> MagicMock:
    paginator = MagicMock()
    paginator.paginate.return_value = pages
    return paginator


_ROLE_ARN = "arn:aws:iam::123456789012:role/InstanceRole"


def _mock_clients_for_inventory_test() -> dict[str, MagicMock]:
    iam_client = MagicMock()
    iam_client.get_paginator.return_value = _mock_paginator(
        [
            {
                "UserDetailList": [],
                "GroupDetailList": [],
                "RoleDetailList": [
                    {
                        "RoleName": "InstanceRole",
                        "Arn": _ROLE_ARN,
                        "RoleId": "R1",
                        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
                        "RolePolicyList": [],
                        "AttachedManagedPolicies": [],
                    }
                ],
                "Policies": [],
            }
        ]
    )
    iam_client.get_instance_profile.return_value = {
        "InstanceProfile": {"Roles": [{"Arn": _ROLE_ARN}]}
    }

    sts_client = MagicMock()
    sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

    lambda_client = MagicMock()
    lambda_client.get_paginator.return_value = _mock_paginator(
        [
            {
                "Functions": [
                    {
                        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fn",
                        "Role": _ROLE_ARN,
                    }
                ]
            }
        ]
    )

    ec2_client = MagicMock()
    ec2_client.meta.region_name = "us-east-1"
    ec2_client.get_paginator.return_value = _mock_paginator(
        [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-abc",
                                "IamInstanceProfile": {
                                    "Arn": "arn:aws:iam::123456789012:instance-profile/MyProfile"
                                },
                            }
                        ]
                    }
                ]
            }
        ]
    )

    sagemaker_client = MagicMock()
    sagemaker_client.get_paginator.return_value = _mock_paginator(
        [
            {
                "NotebookInstances": [
                    {
                        "NotebookInstanceName": "nb",
                        "NotebookInstanceArn": (
                            "arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/nb"
                        ),
                    }
                ]
            }
        ]
    )
    sagemaker_client.describe_notebook_instance.return_value = {"RoleArn": _ROLE_ARN}

    glue_client = MagicMock()
    glue_client.meta.region_name = "us-east-1"
    glue_client.get_paginator.return_value = _mock_paginator(
        [{"DevEndpoints": [{"EndpointName": "ep", "RoleArn": _ROLE_ARN}]}]
    )

    cfn_client = MagicMock()
    cfn_client.get_paginator.return_value = _mock_paginator(
        [
            {
                "Stacks": [
                    {
                        "StackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/s/abc",
                        "RoleARN": _ROLE_ARN,
                    }
                ]
            }
        ]
    )

    return {
        "iam": iam_client,
        "sts": sts_client,
        "lambda": lambda_client,
        "ec2": ec2_client,
        "sagemaker": sagemaker_client,
        "glue": glue_client,
        "cloudformation": cfn_client,
    }


def test_from_boto3_populates_all_resource_inventories():
    pytest.importorskip("boto3")
    clients = _mock_clients_for_inventory_test()
    mock_session = MagicMock()
    mock_session.client.side_effect = lambda service, *a, **kw: clients[service]

    with patch("boto3.Session", return_value=mock_session):
        account = from_boto3("audit")

    assert [f.arn for f in account.lambda_functions] == [
        "arn:aws:lambda:us-east-1:123456789012:function:fn"
    ]
    assert account.lambda_functions[0].execution_role_arn == _ROLE_ARN

    assert len(account.ec2_instances) == 1
    assert account.ec2_instances[0].instance_profile_role_arn == _ROLE_ARN

    assert len(account.sagemaker_notebooks) == 1
    assert account.sagemaker_notebooks[0].execution_role_arn == _ROLE_ARN

    assert len(account.glue_dev_endpoints) == 1
    assert account.glue_dev_endpoints[0].role_arn == _ROLE_ARN

    assert len(account.cloudformation_stacks) == 1
    assert account.cloudformation_stacks[0].role_arn == _ROLE_ARN


def test_from_boto3_degrades_gracefully_when_a_service_denies_access():
    # A real account might scope SecurityAudit down further for one
    # service (the same way our own test account's org SCP blocked IAM
    # group creation) -- one denied service must not crash the whole scan.
    pytest.importorskip("boto3")
    import botocore.exceptions

    clients = _mock_clients_for_inventory_test()
    clients["lambda"].get_paginator.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "ListFunctions"
    )
    mock_session = MagicMock()
    mock_session.client.side_effect = lambda service, *a, **kw: clients[service]

    with patch("boto3.Session", return_value=mock_session):
        account = from_boto3("audit")  # must not raise

    assert account.lambda_functions == []
    assert len(account.ec2_instances) == 1  # other inventories still populated


def test_from_boto3_degradation_warning_goes_to_stderr_not_stdout(capsys):
    # Real bug caught during live validation: the warning printed to
    # stdout, which corrupted `--format json` output when piped/parsed by
    # another program. It belongs on stderr.
    pytest.importorskip("boto3")
    import botocore.exceptions

    clients = _mock_clients_for_inventory_test()
    clients["lambda"].get_paginator.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "ListFunctions"
    )
    mock_session = MagicMock()
    mock_session.client.side_effect = lambda service, *a, **kw: clients[service]

    with patch("boto3.Session", return_value=mock_session):
        from_boto3("audit")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Lambda functions" in captured.err
