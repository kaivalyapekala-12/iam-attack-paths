import pytest

from iam_paths.models import (
    Account,
    Group,
    ManagedPolicyRef,
    Policy,
    PolicyDocument,
    Statement,
    User,
    as_list,
)


def test_as_list_wraps_a_bare_string():
    # IAM lets Action/Resource be a single string instead of a list of one.
    assert as_list("iam:PassRole") == ["iam:PassRole"]


def test_as_list_leaves_a_list_alone():
    assert as_list(["a", "b"]) == ["a", "b"]


def test_statement_from_raw_normalizes_action_and_resource():
    raw = {
        "Sid": "Example",
        "Effect": "Allow",
        "Action": "iam:CreatePolicyVersion",
        "Resource": "arn:aws:iam::123456789012:policy/AlicePolicy",
    }
    stmt = Statement.from_raw(raw)
    assert stmt.sid == "Example"
    assert stmt.effect == "Allow"
    assert stmt.actions == ["iam:CreatePolicyVersion"]
    assert stmt.resources == ["arn:aws:iam::123456789012:policy/AlicePolicy"]


def test_statement_from_raw_accepts_already_listed_action_and_resource():
    raw = {
        "Effect": "Allow",
        "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"],
        "Resource": "*",
    }
    stmt = Statement.from_raw(raw)
    assert stmt.actions == ["lambda:CreateFunction", "lambda:InvokeFunction"]


def test_statement_rejects_invalid_effect():
    with pytest.raises(ValueError, match="Invalid Effect"):
        Statement(effect="Permit", actions=["s3:GetObject"], resources=["*"])


def test_statement_sid_defaults_to_none():
    stmt = Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"])
    assert stmt.sid is None


def test_policy_document_from_raw_builds_all_statements():
    raw = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
        ],
    }
    doc = PolicyDocument.from_raw(raw)
    assert len(doc.statements) == 2
    assert doc.statements[0].effect == "Allow"
    assert doc.statements[1].effect == "Deny"


def test_policy_document_from_raw_handles_a_single_statement_dict():
    # IAM also allows "Statement" to be one dict instead of a list of one.
    raw = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
    }
    doc = PolicyDocument.from_raw(raw)
    assert len(doc.statements) == 1


def test_user_defaults_are_empty_not_shared_between_instances():
    # Guards against the classic Python bug: mutable default args/fields
    # accidentally shared across every instance.
    alice = User(name="alice", arn="arn:aws:iam::123456789012:user/alice", user_id="A1")
    bob = User(name="bob", arn="arn:aws:iam::123456789012:user/bob", user_id="A2")
    alice.inline_policies.append(
        Policy(name="p", document=PolicyDocument(statements=[]))
    )
    assert bob.inline_policies == []


def test_account_managed_policies_keyed_by_arn():
    policy = Policy(
        name="AlicePolicy",
        arn="arn:aws:iam::123456789012:policy/AlicePolicy",
        document=PolicyDocument(statements=[]),
    )
    account = Account(managed_policies={policy.arn: policy})
    assert account.managed_policies["arn:aws:iam::123456789012:policy/AlicePolicy"] is policy


def test_managed_policy_ref_has_no_document():
    ref = ManagedPolicyRef(name="ReadOnlyAccess", arn="arn:aws:iam::aws:policy/ReadOnlyAccess")
    assert ref.name == "ReadOnlyAccess"
    assert not hasattr(ref, "document")


def _allow_statement(action: str) -> Statement:
    return Statement(effect="Allow", actions=[action], resources=["*"])


def test_user_effective_statements_includes_own_inline_and_attached():
    managed = Policy(
        name="ManagedGrant",
        arn="arn:aws:iam::123456789012:policy/ManagedGrant",
        document=PolicyDocument(statements=[_allow_statement("s3:GetObject")]),
    )
    user = User(
        name="alice",
        arn="arn:aws:iam::123456789012:user/alice",
        user_id="A1",
        inline_policies=[
            Policy(
                name="Inline",
                document=PolicyDocument(statements=[_allow_statement("iam:CreatePolicyVersion")]),
            )
        ],
        attached_policies=[ManagedPolicyRef(name="ManagedGrant", arn=managed.arn)],
    )
    account = Account(users=[user], managed_policies={managed.arn: managed})

    actions = {a for s in user.effective_statements(account) for a in s.actions}
    assert actions == {"iam:CreatePolicyVersion", "s3:GetObject"}


def test_user_effective_statements_includes_statements_inherited_from_groups():
    # This is the case that matters for escalation detection: eve has no
    # policy of her own at all, but inherits AddUserToGroup purely through
    # group membership. A loader that only looked at the user's own inline
    # and attached policies would completely miss this escalation path.
    group = Group(
        name="intern",
        arn="arn:aws:iam::123456789012:group/intern",
        group_id="G1",
        inline_policies=[
            Policy(
                name="InternGrant",
                document=PolicyDocument(statements=[_allow_statement("iam:AddUserToGroup")]),
            )
        ],
    )
    eve = User(
        name="eve",
        arn="arn:aws:iam::123456789012:user/eve",
        user_id="A2",
        group_names=["intern"],
    )
    account = Account(users=[eve], groups=[group])

    actions = {a for s in eve.effective_statements(account) for a in s.actions}
    assert actions == {"iam:AddUserToGroup"}


def test_effective_statements_skips_unresolvable_attached_policy():
    # AWS-managed policies (e.g. ReadOnlyAccess) only ever show up as a
    # name+ARN pointer in AttachedManagedPolicies -- their document is never
    # in this dataset. We can't invent statements we don't have, so the
    # loader/model must silently skip them rather than crash. Any
    # "is this an admin" check has to look at the pointer's name/ARN
    # directly instead of relying on resolved statements.
    grace = User(
        name="grace",
        arn="arn:aws:iam::123456789012:user/grace",
        user_id="A3",
        attached_policies=[
            ManagedPolicyRef(name="ReadOnlyAccess", arn="arn:aws:iam::aws:policy/ReadOnlyAccess")
        ],
    )
    account = Account(users=[grace])
    assert grace.effective_statements(account) == []
