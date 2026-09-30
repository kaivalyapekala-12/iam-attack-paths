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
        default_version = next(
            v for v in raw["PolicyVersionList"] if v["VersionId"] == raw["DefaultVersionId"]
        )
        policies[raw["Arn"]] = Policy(
            name=raw["PolicyName"],
            arn=raw["Arn"],
            document=_parse_policy_document(default_version["Document"]),
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


def load_account(path: str | Path) -> Account:
    raw = json.loads(Path(path).read_text())
    return Account(
        users=[_parse_user(u) for u in raw.get("UserDetailList", [])],
        groups=[_parse_group(g) for g in raw.get("GroupDetailList", [])],
        roles=[_parse_role(r) for r in raw.get("RoleDetailList", [])],
        managed_policies=_parse_managed_policies(raw.get("Policies", [])),
    )
