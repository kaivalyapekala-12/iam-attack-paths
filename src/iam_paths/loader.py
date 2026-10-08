"""Parse the raw AWS `get-account-authorization-details` JSON shape into
the typed models in models.py.

Two real AWS quirks get normalized here:
- A PolicyDocument sometimes arrives as a dict (boto3 usually decodes it
  for you) and sometimes as a URL-encoded JSON string (a raw API/CLI call
  can hand you either). We accept both.
- An attached managed policy's document is never inline where it's
  attached: AttachedManagedPolicies only gives a {PolicyName, PolicyArn}
  pointer. The actual document, if we have it at all, lives in the
  top-level Policies list, keyed by that ARN, and only its default version
  is currently in effect.
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from iam_paths.models import (
    Account,
    CloudFormationStack,
    EC2Instance,
    GlueDevEndpoint,
    Group,
    LambdaFunction,
    ManagedPolicyRef,
    Policy,
    PolicyDocument,
    PolicyVersion,
    Role,
    SageMakerNotebook,
    User,
)


def _parse_policy_document(raw: Any) -> PolicyDocument:
    if isinstance(raw, str):
        raw = json.loads(unquote(raw))
    return PolicyDocument.from_raw(raw)


def _parse_inline_policies(raw_list: list[dict[str, Any]]) -> list[Policy]:
    return [
        Policy(name=raw["PolicyName"], document=_parse_policy_document(raw["PolicyDocument"]))
        for raw in raw_list
    ]


def _parse_attached_policies(raw_list: list[dict[str, Any]]) -> list[ManagedPolicyRef]:
    return [ManagedPolicyRef(name=raw["PolicyName"], arn=raw["PolicyArn"]) for raw in raw_list]


def _parse_managed_policies(raw_list: list[dict[str, Any]]) -> dict[str, Policy]:
    policies: dict[str, Policy] = {}
    for raw in raw_list:
        versions = [
            PolicyVersion(version_id=v["VersionId"], document=_parse_policy_document(v["Document"]))
            for v in raw["PolicyVersionList"]
        ]
        default_version = next(v for v in versions if v.version_id == raw["DefaultVersionId"])
        policies[raw["Arn"]] = Policy(
            name=raw["PolicyName"],
            arn=raw["Arn"],
            document=default_version.document,
            versions=versions,
        )
    return policies


def _parse_user(raw: dict[str, Any]) -> User:
    return User(
        name=raw["UserName"],
        arn=raw["Arn"],
        user_id=raw["UserId"],
        inline_policies=_parse_inline_policies(raw.get("UserPolicyList", [])),
        attached_policies=_parse_attached_policies(raw.get("AttachedManagedPolicies", [])),
        group_names=list(raw.get("GroupList", [])),
    )


def _parse_group(raw: dict[str, Any]) -> Group:
    return Group(
        name=raw["GroupName"],
        arn=raw["Arn"],
        group_id=raw["GroupId"],
        inline_policies=_parse_inline_policies(raw.get("GroupPolicyList", [])),
        attached_policies=_parse_attached_policies(raw.get("AttachedManagedPolicies", [])),
    )


def _parse_role(raw: dict[str, Any]) -> Role:
    return Role(
        name=raw["RoleName"],
        arn=raw["Arn"],
        role_id=raw["RoleId"],
        assume_role_policy=_parse_policy_document(raw["AssumeRolePolicyDocument"]),
        inline_policies=_parse_inline_policies(raw.get("RolePolicyList", [])),
        attached_policies=_parse_attached_policies(raw.get("AttachedManagedPolicies", [])),
    )


def _account_from_raw(raw: dict[str, Any]) -> Account:
    return Account(
        users=[_parse_user(u) for u in raw.get("UserDetailList", [])],
        groups=[_parse_group(g) for g in raw.get("GroupDetailList", [])],
        roles=[_parse_role(r) for r in raw.get("RoleDetailList", [])],
        managed_policies=_parse_managed_policies(raw.get("Policies", [])),
    )


def load_account(path: str | Path) -> Account:
    raw = json.loads(Path(path).read_text())
    return _account_from_raw(raw)


def _safe_fetch(label: str, fetch: Any) -> list[Any]:
    """Every inventory fetch below calls a service SecurityAudit is
    supposed to grant read access to, but a real account might scope that
    down further (the same way our own test account's org SCP blocked IAM
    group creation). Rather than let one missing permission crash the
    whole scan, this degrades to "found nothing in this account" and
    prints a one-line note -- an honest gap, not a silent one."""
    import botocore.exceptions

    try:
        return fetch()
    except botocore.exceptions.ClientError as exc:
        print(
            f"Warning: couldn't read {label} ({exc.response['Error']['Code']}); skipping.",
            file=sys.stderr,
        )
        return []


def _fetch_lambda_functions(session: Any) -> list[LambdaFunction]:
    client = session.client("lambda")
    functions = []
    for page in client.get_paginator("list_functions").paginate():
        for fn in page.get("Functions", []):
            functions.append(LambdaFunction(arn=fn["FunctionArn"], execution_role_arn=fn["Role"]))
    return functions


def _fetch_ec2_instances(session: Any, account_id: str) -> list[EC2Instance]:
    ec2 = session.client("ec2")
    iam = session.client("iam")
    region = ec2.meta.region_name
    role_arn_by_profile: dict[str, str | None] = {}
    instances = []
    for page in ec2.get_paginator("describe_instances").paginate():
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                profile = inst.get("IamInstanceProfile")
                if not profile:
                    continue
                profile_name = profile["Arn"].rsplit("/", 1)[-1]
                if profile_name not in role_arn_by_profile:
                    roles = iam.get_instance_profile(InstanceProfileName=profile_name)[
                        "InstanceProfile"
                    ]["Roles"]
                    role_arn_by_profile[profile_name] = roles[0]["Arn"] if roles else None
                role_arn = role_arn_by_profile[profile_name]
                if role_arn is None:
                    continue
                instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{inst['InstanceId']}"
                instances.append(EC2Instance(arn=instance_arn, instance_profile_role_arn=role_arn))
    return instances


def _fetch_sagemaker_notebooks(session: Any) -> list[SageMakerNotebook]:
    client = session.client("sagemaker")
    notebooks = []
    for page in client.get_paginator("list_notebook_instances").paginate():
        for summary in page.get("NotebookInstances", []):
            detail = client.describe_notebook_instance(
                NotebookInstanceName=summary["NotebookInstanceName"]
            )
            role_arn = detail.get("RoleArn")
            if role_arn is None:
                continue
            notebooks.append(
                SageMakerNotebook(arn=summary["NotebookInstanceArn"], execution_role_arn=role_arn)
            )
    return notebooks


def _fetch_glue_dev_endpoints(session: Any, account_id: str) -> list[GlueDevEndpoint]:
    client = session.client("glue")
    region = client.meta.region_name
    endpoints = []
    for page in client.get_paginator("get_dev_endpoints").paginate():
        for ep in page.get("DevEndpoints", []):
            role_arn = ep.get("RoleArn")
            if role_arn is None:
                continue
            arn = f"arn:aws:glue:{region}:{account_id}:devEndpoint/{ep['EndpointName']}"
            endpoints.append(GlueDevEndpoint(arn=arn, role_arn=role_arn))
    return endpoints


def _fetch_cloudformation_stacks(session: Any) -> list[CloudFormationStack]:
    client = session.client("cloudformation")
    stacks = []
    for page in client.get_paginator("describe_stacks").paginate():
        for stack in page.get("Stacks", []):
            stacks.append(CloudFormationStack(arn=stack["StackId"], role_arn=stack.get("RoleARN")))
    return stacks


def from_boto3(profile_name: str) -> Account:
    """Live mode: the read-only equivalent of `aws iam get-account-
    authorization-details --profile <profile_name>`, paginated, plus the
    resource inventories (Lambda functions, EC2 instances, SageMaker
    notebooks, Glue dev endpoints, CloudFormation stacks) that techniques
    #11 and #20-#25 need but get-account-authorization-details doesn't
    provide. Requires the profile to exist in the caller's AWS
    config/credentials files (~/.aws) with at least the SecurityAudit
    managed policy -- see the README for how the scanner IAM user should
    be set up. Every call here is read-only (List/Describe/Get); nothing
    in this function can modify the account."""
    import boto3

    session = boto3.Session(profile_name=profile_name)
    iam_client = session.client("iam")
    paginator = iam_client.get_paginator("get_account_authorization_details")

    users: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    roles: list[dict[str, Any]] = []
    policies: list[dict[str, Any]] = []
    for page in paginator.paginate():
        users.extend(page.get("UserDetailList", []))
        groups.extend(page.get("GroupDetailList", []))
        roles.extend(page.get("RoleDetailList", []))
        policies.extend(page.get("Policies", []))

    account = _account_from_raw(
        {
            "UserDetailList": users,
            "GroupDetailList": groups,
            "RoleDetailList": roles,
            "Policies": policies,
        }
    )

    account_id = session.client("sts").get_caller_identity()["Account"]
    return replace(
        account,
        lambda_functions=_safe_fetch("Lambda functions", lambda: _fetch_lambda_functions(session)),
        ec2_instances=_safe_fetch(
            "EC2 instances", lambda: _fetch_ec2_instances(session, account_id)
        ),
        sagemaker_notebooks=_safe_fetch(
            "SageMaker notebooks", lambda: _fetch_sagemaker_notebooks(session)
        ),
        glue_dev_endpoints=_safe_fetch(
            "Glue dev endpoints", lambda: _fetch_glue_dev_endpoints(session, account_id)
        ),
        cloudformation_stacks=_safe_fetch(
            "CloudFormation stacks", lambda: _fetch_cloudformation_stacks(session)
        ),
    )
