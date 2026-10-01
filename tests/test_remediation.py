from pathlib import Path

from iam_paths.graph import build_graph, shortest_attack_path
from iam_paths.loader import load_account
from iam_paths.models import Account
from iam_paths.remediation import apply_fix, find_grant, remediate

SAMPLE = Path(__file__).parent.parent / "samples" / "sample_account.json"


def _user(account: Account, name: str):
    return next(u for u in account.users if u.name == name)


def test_alice_critical_severity_one_hop():
    account = load_account(SAMPLE)
    graph = build_graph(account)
    alice = _user(account, "alice")
    path = shortest_attack_path(graph, alice.arn)

    finding = remediate(account, alice.arn, path)

    assert finding is not None
    assert finding.severity == "Critical"
    assert finding.removed_permission == "iam:CreatePolicyVersion"
    assert "AC-6" in finding.control_tags
    assert "AC-6(5)" in finding.control_tags


def test_carol_high_severity_two_hops_fixes_the_earlier_cheaper_hop():
    account = load_account(SAMPLE)
    graph = build_graph(account)
    carol = _user(account, "carol")
    path = shortest_attack_path(graph, carol.arn)

    finding = remediate(account, carol.arn, path)

    assert finding is not None
    assert finding.severity == "High"
    # Both hops need exactly one permission -- the earlier hop (carol's own
    # sts:AssumeRole) is the tie-break, since cutting the chain at her own
    # identity is the narrowest fix.
    assert finding.removed_permission == "sts:AssumeRole"
    assert finding.grant.owner.arn == carol.arn
    # This hop's target is DeployRole, not ADMIN itself, so AC-6(5) doesn't apply.
    assert finding.control_tags == ["AC-6"]


def test_dave_fix_targets_the_create_access_key_hop_not_already_admin():
    account = load_account(SAMPLE)
    graph = build_graph(account)
    dave = _user(account, "dave")
    path = shortest_attack_path(graph, dave.arn)

    finding = remediate(account, dave.arn, path)

    assert finding is not None
    assert finding.removed_permission == "iam:CreateAccessKey"
    assert finding.grant.owner.arn == dave.arn


def test_eve_fix_targets_the_intern_groups_policy_not_eve_herself():
    # Eve has no policy of her own -- iam:AddUserToGroup comes entirely
    # from the intern group's inline policy -- so the fix must edit the
    # group's policy, not fabricate one on eve.
    account = load_account(SAMPLE)
    graph = build_graph(account)
    eve = _user(account, "eve")
    path = shortest_attack_path(graph, eve.arn)

    finding = remediate(account, eve.arn, path)

    assert finding is not None
    assert finding.grant.owner.name == "intern"
    assert finding.grant.policy_arn is None  # inline, not managed


def test_fixed_policy_json_no_longer_grants_the_removed_action():
    account = load_account(SAMPLE)
    graph = build_graph(account)
    alice = _user(account, "alice")
    path = shortest_attack_path(graph, alice.arn)
    finding = remediate(account, alice.arn, path)

    raw = finding.fixed_policy_json
    actions = [a for s in raw["Statement"] for a in s.get("Action", [])]
    assert "iam:CreatePolicyVersion" not in actions


def test_find_grant_returns_none_for_a_permission_nobody_has():
    account = load_account(SAMPLE)
    grace = _user(account, "grace")
    assert find_grant(grace, account, "iam:CreatePolicyVersion") is None


def test_remediate_returns_none_for_no_path():
    account = load_account(SAMPLE)
    grace = _user(account, "grace")
    assert remediate(account, grace.arn, None) is None


# --- The strongest claim: applying the fix and re-running actually closes
# the path, for every user who has one. ---


def test_applying_the_fix_closes_the_path_for_every_escalating_user():
    account = load_account(SAMPLE)
    graph = build_graph(account)

    for name in ("alice", "bob", "carol", "dave", "eve"):
        user = _user(account, name)
        path = shortest_attack_path(graph, user.arn)
        assert path is not None, f"{name} should have a path before the fix"

        finding = remediate(account, user.arn, path)
        assert finding is not None, f"{name} should have a remediation finding"

        fixed_account = apply_fix(account, finding)
        fixed_graph = build_graph(fixed_account)
        fixed_path = shortest_attack_path(fixed_graph, user.arn)

        assert fixed_path is None, f"{name} should have no path after the fix"
        # The original account is untouched -- apply_fix never mutates it.
        assert shortest_attack_path(graph, user.arn) is not None
