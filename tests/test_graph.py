from pathlib import Path

from iam_paths.graph import build_graph, is_admin, shortest_attack_path
from iam_paths.loader import load_account
from iam_paths.models import ADMIN, Account

SAMPLE = Path(__file__).parent.parent / "samples" / "sample_account.json"


def _user(account: Account, name: str):
    return next(u for u in account.users if u.name == name)


def _role(account: Account, name: str):
    return next(r for r in account.roles if r.name == name)


def _group(account: Account, name: str):
    return next(g for g in account.groups if g.name == name)


def test_ops_admin_is_admin_via_administratoraccess_pointer():
    # AdministratorAccess is AWS-managed -- its document never resolves via
    # can() -- so is_admin() has to recognize the attached-policy pointer
    # by name/ARN directly, not by evaluating statements.
    account = load_account(SAMPLE)
    ops_admin = _user(account, "ops-admin")
    assert is_admin(ops_admin, account)


def test_admins_group_is_admin():
    account = load_account(SAMPLE)
    admins = _group(account, "Admins")
    assert is_admin(admins, account)


def test_lambdaadminrole_is_admin():
    account = load_account(SAMPLE)
    role = _role(account, "LambdaAdminRole")
    assert is_admin(role, account)


def test_alice_is_not_already_admin():
    account = load_account(SAMPLE)
    alice = _user(account, "alice")
    assert not is_admin(alice, account)


def test_alice_shortest_path_is_one_hop_self_to_admin():
    account = load_account(SAMPLE)
    graph = build_graph(account)
    alice = _user(account, "alice")
    path = shortest_attack_path(graph, alice.arn)
    assert path is not None
    assert len(path) == 1
    assert path[0].source == alice.arn
    assert path[0].target == ADMIN
    assert path[0].technique == "new_policy_version"


def test_carol_shortest_path_is_carol_deployrole_admin():
    account = load_account(SAMPLE)
    graph = build_graph(account)
    carol = _user(account, "carol")
    deploy_role = _role(account, "DeployRole")

    path = shortest_attack_path(graph, carol.arn)

    assert path is not None
    assert [hop.source for hop in path] == [carol.arn, deploy_role.arn]
    assert [hop.target for hop in path] == [deploy_role.arn, ADMIN]
    assert path[0].technique == "assume_role"
    assert path[1].technique == "attach_managed_policy"


def test_dave_shortest_path_goes_through_ops_admin():
    account = load_account(SAMPLE)
    graph = build_graph(account)
    dave = _user(account, "dave")
    ops_admin = _user(account, "ops-admin")

    path = shortest_attack_path(graph, dave.arn)

    assert path is not None
    assert [hop.source for hop in path] == [dave.arn, ops_admin.arn]
    assert path[0].technique == "create_access_key"
    assert path[1].technique == "already_admin"


def test_eve_shortest_path_goes_through_admins_group():
    account = load_account(SAMPLE)
    graph = build_graph(account)
    eve = _user(account, "eve")
    admins = _group(account, "Admins")

    path = shortest_attack_path(graph, eve.arn)

    assert path is not None
    assert [hop.target for hop in path] == [admins.arn, ADMIN]
    assert path[0].technique == "add_user_to_group"


def test_bob_shortest_path_goes_through_lambdaadminrole():
    account = load_account(SAMPLE)
    graph = build_graph(account)
    bob = _user(account, "bob")
    lambda_admin_role = _role(account, "LambdaAdminRole")

    path = shortest_attack_path(graph, bob.arn)

    assert path is not None
    assert [hop.target for hop in path] == [lambda_admin_role.arn, ADMIN]
    assert path[0].technique == "lambda_pass_role"


def test_frank_has_no_attack_path():
    account = load_account(SAMPLE)
    graph = build_graph(account)
    frank = _user(account, "frank")
    assert shortest_attack_path(graph, frank.arn) is None


def test_grace_has_no_attack_path():
    account = load_account(SAMPLE)
    graph = build_graph(account)
    grace = _user(account, "grace")
    assert shortest_attack_path(graph, grace.arn) is None
