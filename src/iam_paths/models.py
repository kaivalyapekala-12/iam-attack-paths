"""Typed, normalized IAM entities.

This is NOT the raw AWS JSON shape (see loader.py for parsing that). It's the
internal representation everything else in the package works with, so
evaluator.py and graph.py never have to re-check whether "Action" was a
string or a list, or chase down whether a policy was inline or attached.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Effect = Literal["Allow", "Deny"]

_VALID_EFFECTS = {"Allow", "Deny"}


def as_list(value: Any) -> list[Any]:
    """IAM lets several fields (Action, Resource, Statement, ...) be either
    a single bare value or a list of values. Normalize to a list once, here,
    so nothing downstream has to branch on it."""
    if isinstance(value, list):
        return value
    return [value]


@dataclass(frozen=True)
class Statement:
    effect: Effect
    actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    # NotAction/NotResource mean "everything except" -- mutually exclusive
    # with actions/resources in real IAM. Empty means "not used".
    not_action: list[str] = field(default_factory=list)
    not_resource: list[str] = field(default_factory=list)
    # Kept as the raw dict rather than parsed: the evaluator never needs to
    # understand a Condition's operators, only to notice one is present and
    # flag it instead of guessing (see evaluator.can).
    condition: dict[str, Any] | None = None
    sid: str | None = None
    # Only meaningful on trust policies (Role.assume_role_policy) and other
    # resource-based policies -- identity policies (inline/managed, attached
    # to a user/group/role) never have this. Kept as the raw dict, e.g.
    # {"AWS": "arn:...:user/carol"} or {"Service": "lambda.amazonaws.com"},
    # since which shape it takes depends on who's being trusted.
    principal: dict[str, Any] | str | None = None

    def __post_init__(self) -> None:
        if self.effect not in _VALID_EFFECTS:
            raise ValueError(f"Invalid Effect: {self.effect!r} (must be Allow or Deny)")

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> Statement:
        return cls(
            effect=raw["Effect"],
            actions=as_list(raw["Action"]) if "Action" in raw else [],
            resources=as_list(raw["Resource"]) if "Resource" in raw else [],
            not_action=as_list(raw["NotAction"]) if "NotAction" in raw else [],
            not_resource=as_list(raw["NotResource"]) if "NotResource" in raw else [],
            condition=raw.get("Condition"),
            sid=raw.get("Sid"),
            principal=raw.get("Principal"),
        )


@dataclass(frozen=True)
class PolicyDocument:
    statements: list[Statement]

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> PolicyDocument:
        return cls(statements=[Statement.from_raw(s) for s in as_list(raw.get("Statement", []))])


@dataclass(frozen=True)
class PolicyVersion:
    version_id: str
    document: PolicyDocument


@dataclass(frozen=True)
class Policy:
    """A named policy with a resolved document: either inline (owned by one
    principal, no ARN, no version history) or customer-managed (reusable,
    has an ARN and lives in Account.managed_policies). `document` is always
    the currently-effective (default) version; `versions` additionally
    holds every version for a customer-managed policy, since technique #8
    (roll back to a broader old version) needs to see versions that
    *aren't* in effect right now."""

    name: str
    document: PolicyDocument
    arn: str | None = None
    versions: list[PolicyVersion] = field(default_factory=list)


@dataclass(frozen=True)
class ManagedPolicyRef:
    """A pointer to an attached managed policy whose document lives
    elsewhere: in Account.managed_policies for a customer-managed policy,
    or nowhere in this dataset at all for an AWS-managed one."""

    name: str
    arn: str


def _resolve_attached_statements(
    attached_policies: list[ManagedPolicyRef], managed_policies: dict[str, Policy]
) -> list[Statement]:
    """Look up each attached policy's document by ARN. AWS-managed policies
    (e.g. ReadOnlyAccess, AdministratorAccess) only ever appear as a pointer
    here -- their document is never in our dataset -- so a ref that doesn't
    resolve is silently skipped rather than treated as an error. Anything
    that needs to detect "has AdministratorAccess" must check the pointer's
    name/ARN directly instead of relying on resolved statements."""
    statements: list[Statement] = []
    for ref in attached_policies:
        policy = managed_policies.get(ref.arn)
        if policy is not None:
            statements.extend(policy.document.statements)
    return statements


def _own_statements(
    inline_policies: list[Policy],
    attached_policies: list[ManagedPolicyRef],
    account: Account,
) -> list[Statement]:
    statements: list[Statement] = []
    for policy in inline_policies:
        statements.extend(policy.document.statements)
    statements.extend(_resolve_attached_statements(attached_policies, account.managed_policies))
    return statements


@dataclass(frozen=True)
class User:
    name: str
    arn: str
    user_id: str
    inline_policies: list[Policy] = field(default_factory=list)
    attached_policies: list[ManagedPolicyRef] = field(default_factory=list)
    group_names: list[str] = field(default_factory=list)

    def effective_statements(self, account: Account) -> list[Statement]:
        """Every statement that actually applies to this user: her own
        inline and attached policies, PLUS every group she's in. Group
        membership matters because AWS evaluates it exactly like a directly
        attached policy -- a user with no policies of her own can still
        escalate purely through what her group grants (see eve/intern in
        the sample account)."""
        statements = _own_statements(self.inline_policies, self.attached_policies, account)
        for group in account.groups:
            if group.name in self.group_names:
                statements.extend(group.effective_statements(account))
        return statements


@dataclass(frozen=True)
class Group:
    name: str
    arn: str
    group_id: str
    inline_policies: list[Policy] = field(default_factory=list)
    attached_policies: list[ManagedPolicyRef] = field(default_factory=list)

    def effective_statements(self, account: Account) -> list[Statement]:
        return _own_statements(self.inline_policies, self.attached_policies, account)


@dataclass(frozen=True)
class Role:
    name: str
    arn: str
    role_id: str
    assume_role_policy: PolicyDocument
    inline_policies: list[Policy] = field(default_factory=list)
    attached_policies: list[ManagedPolicyRef] = field(default_factory=list)

    def effective_statements(self, account: Account) -> list[Statement]:
        return _own_statements(self.inline_policies, self.attached_policies, account)


@dataclass(frozen=True)
class LambdaFunction:
    """Which execution role a Lambda function runs as. Not part of
    get-account-authorization-details at all -- it comes from a separate
    lambda:ListFunctions call -- so loader.load_account() never populates
    this from the offline JSON; it's empty unless something else (a future
    live-mode loader, or a test) supplies it. Technique #11 (editing an
    existing function's code) is a real no-op against the sample account as
    a result -- a documented v1 limitation, not a bug."""

    arn: str
    execution_role_arn: str


@dataclass(frozen=True)
class Account:
    users: list[User] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    roles: list[Role] = field(default_factory=list)
    managed_policies: dict[str, Policy] = field(default_factory=dict)
    lambda_functions: list[LambdaFunction] = field(default_factory=list)

    def all_principals(self) -> list[User | Group | Role]:
        """Every principal a check function might need to run against.
        Roles and groups matter here, not just users: a role's own
        permissions can create an escalation (see DeployRole in the sample),
        and it's only found by checking the role itself, not the user who
        can assume it."""
        return [*self.users, *self.groups, *self.roles]


# Sentinel target for an Edge that leads straight to admin, rather than to
# another principal's ARN (e.g. "alice can rewrite her own policy to grant
# herself AdministratorAccess" has no intermediate hop to name).
ADMIN = "ADMIN"


@dataclass(frozen=True)
class Edge:
    """One step in an attack path: `source` can become `target` via
    `technique`, using `permissions_used`. `target` is either another
    principal's ARN or the ADMIN sentinel."""

    source: str
    target: str
    technique: str
    permissions_used: list[str]
