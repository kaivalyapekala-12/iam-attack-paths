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
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from iam_paths.models import (
    Account,
    Group,
    ManagedPolicyRef,
    Policy,
    PolicyDocument,
    PolicyVersion,
    Role,
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


def from_boto3(profile_name: str) -> Account:
    """Live mode: the read-only equivalent of `aws iam get-account-
    authorization-details --profile <profile_name>`, paginated. Requires
    the profile to exist in the caller's AWS config/credentials files
    (~/.aws) with at least the SecurityAudit managed policy -- see the
    README for how the scanner IAM user should be set up. Never makes a
    write call; get_account_authorization_details is inherently read-only."""
    import boto3

    client = boto3.Session(profile_name=profile_name).client("iam")
    paginator = client.get_paginator("get_account_authorization_details")

    users: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    roles: list[dict[str, Any]] = []
    policies: list[dict[str, Any]] = []
    for page in paginator.paginate():
        users.extend(page.get("UserDetailList", []))
        groups.extend(page.get("GroupDetailList", []))
        roles.extend(page.get("RoleDetailList", []))
        policies.extend(page.get("Policies", []))

    return _account_from_raw(
        {
            "UserDetailList": users,
            "GroupDetailList": groups,
            "RoleDetailList": roles,
            "Policies": policies,
        }
    )
