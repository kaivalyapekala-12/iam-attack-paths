"""A simplified AWS IAM policy evaluator.

Answers one question -- can(principal, action, resource) -- that every
escalation check in checks.py will ask, over and over, with different
actions and resources. Getting this one function right means every check
built on top of it is just "which permissions does technique N need".

Simplified vs. real AWS evaluation (documented as limitations in the
README): no permission boundaries, no Service Control Policies (SCPs), and
no resource-based policies other than role trust policies. A Condition is
never evaluated -- its truth depends on runtime request context (MFA
status, source IP, tags, ...) we don't have -- so a matching statement
with one is flagged as ALLOWED_WITH_CONDITION instead of guessed at.
"""

from __future__ import annotations

import fnmatch
import re
from enum import StrEnum
from typing import TYPE_CHECKING

from iam_paths.models import Statement

if TYPE_CHECKING:
    from iam_paths.models import Account, Group, Role, User


class Decision(StrEnum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    ALLOWED_WITH_CONDITION = "ALLOWED_WITH_CONDITION"


def _wildcard_match(pattern: str, value: str, *, case_insensitive: bool) -> bool:
    """IAM action patterns (iam:Create*) are case-insensitive; ARNs are not.
    fnmatch.translate() turns * -> ".*" and ? -> "." and anchors the end
    with \\Z, so re.match against it behaves as a full-string match."""
    regex = fnmatch.translate(pattern)
    flags = re.IGNORECASE if case_insensitive else 0
    return re.match(regex, value, flags) is not None


def _action_matches(statement: Statement, action: str) -> bool:
    if statement.not_action:
        return not any(
            _wildcard_match(p, action, case_insensitive=True) for p in statement.not_action
        )
    return any(_wildcard_match(p, action, case_insensitive=True) for p in statement.actions)


def _resource_matches(statement: Statement, resource: str) -> bool:
    if statement.not_resource:
        return not any(
            _wildcard_match(p, resource, case_insensitive=False) for p in statement.not_resource
        )
    return any(_wildcard_match(p, resource, case_insensitive=False) for p in statement.resources)


def _matches(statement: Statement, action: str, resource: str) -> bool:
    return _action_matches(statement, action) and _resource_matches(statement, resource)


def can(principal: User | Group | Role, action: str, resource: str, account: Account) -> Decision:
    """Evaluate a single (principal, action, resource) request against every
    statement that applies to the principal.

    Rules, in order:
    1. Default is deny.
    2. An explicit Deny in any matching statement always wins.
    3. Otherwise, any matching Allow grants the action.
    4/6. Actions and resources match case-insensitively (actions only) with
         * and ? wildcards.
    5. NotAction/NotResource mean "everything except".
    7. A matching Allow with a Condition can't be resolved without runtime
       request context, so it's flagged rather than guessed at.
    """
    matching = [s for s in principal.effective_statements(account) if _matches(s, action, resource)]

    if any(s.effect == "Deny" for s in matching):
        return Decision.DENIED

    allows = [s for s in matching if s.effect == "Allow"]
    if not allows:
        return Decision.DENIED

    if any(s.condition is not None for s in allows):
        return Decision.ALLOWED_WITH_CONDITION

    return Decision.ALLOWED
