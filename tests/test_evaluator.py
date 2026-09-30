from pathlib import Path

from iam_paths.evaluator import Decision, can
from iam_paths.loader import load_account
from iam_paths.models import Account, Policy, PolicyDocument, Statement, User

SAMPLE = Path(__file__).parent.parent / "samples" / "sample_account.json"


def _account_with(statements: list[Statement]) -> tuple[Account, User]:
    policy = Policy(name="p", document=PolicyDocument(statements=statements))
    user = User(
        name="u",
        arn="arn:aws:iam::123456789012:user/u",
        user_id="U1",
        inline_policies=[policy],
    )
    return Account(users=[user]), user


def test_default_deny_with_no_matching_statement():
    account, user = _account_with([])
    assert can(user, "s3:GetObject", "*", account) == Decision.DENIED


def test_explicit_allow_grants_action():
    account, user = _account_with(
        [Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"])]
    )
    assert can(user, "s3:GetObject", "*", account) == Decision.ALLOWED


def test_explicit_deny_beats_allow_even_when_deny_comes_first():
    account, user = _account_with(
        [
            Statement(effect="Deny", actions=["s3:*"], resources=["*"]),
            Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"]),
        ]
    )
    assert can(user, "s3:GetObject", "*", account) == Decision.DENIED


def test_wildcard_action_matches_case_insensitively():
    account, user = _account_with(
        [Statement(effect="Allow", actions=["IAM:Create*"], resources=["*"])]
    )
    assert can(user, "iam:createpolicyversion", "*", account) == Decision.ALLOWED


def test_not_action_means_everything_except():
    account, user = _account_with(
        [Statement(effect="Allow", not_action=["iam:*"], resources=["*"])]
    )
    assert can(user, "s3:GetObject", "*", account) == Decision.ALLOWED
    assert can(user, "iam:CreateUser", "*", account) == Decision.DENIED


def test_not_resource_means_everything_except():
    account, user = _account_with(
        [
            Statement(
                effect="Allow",
                actions=["s3:GetObject"],
                not_resource=["arn:aws:s3:::secret-bucket/*"],
            )
        ]
    )
    assert can(user, "s3:GetObject", "arn:aws:s3:::public-bucket/x", account) == Decision.ALLOWED
    assert can(user, "s3:GetObject", "arn:aws:s3:::secret-bucket/x", account) == Decision.DENIED


def test_resource_wildcard_matches_arn_with_question_mark():
    account, user = _account_with(
        [Statement(effect="Allow", actions=["s3:GetObject"], resources=["arn:aws:s3:::bucket-?/*"])]
    )
    assert can(user, "s3:GetObject", "arn:aws:s3:::bucket-1/x", account) == Decision.ALLOWED
    assert can(user, "s3:GetObject", "arn:aws:s3:::bucket-12/x", account) == Decision.DENIED


def test_matching_allow_with_condition_returns_allowed_with_condition():
    account, user = _account_with(
        [
            Statement(
                effect="Allow",
                actions=["s3:GetObject"],
                resources=["*"],
                condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            )
        ]
    )
    assert can(user, "s3:GetObject", "*", account) == Decision.ALLOWED_WITH_CONDITION


def test_non_matching_action_is_denied_by_default():
    account, user = _account_with(
        [Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"])]
    )
    assert can(user, "s3:PutObject", "*", account) == Decision.DENIED


def test_alice_can_edit_her_own_policy():
    account = load_account(SAMPLE)
    alice = next(u for u in account.users if u.name == "alice")
    alice_policy_arn = "arn:aws:iam::123456789012:policy/AlicePolicy"
    assert can(alice, "iam:CreatePolicyVersion", alice_policy_arn, account) == Decision.ALLOWED


def test_frank_full_iam_but_escalation_actions_explicitly_denied():
    account = load_account(SAMPLE)
    frank = next(u for u in account.users if u.name == "frank")
    # Broad Allow on iam:* is still beaten by the explicit Deny on this action.
    assert can(frank, "iam:CreatePolicyVersion", "*", account) == Decision.DENIED
    # An iam action that isn't in the Deny list stays allowed by iam:*.
    assert can(frank, "iam:ListUsers", "*", account) == Decision.ALLOWED


def test_grace_readonly_has_no_resolvable_statements_so_denied():
    account = load_account(SAMPLE)
    grace = next(u for u in account.users if u.name == "grace")
    assert can(grace, "s3:GetObject", "*", account) == Decision.DENIED
