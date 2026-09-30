"""Build the attack graph and read off each user's shortest path to admin.

Every principal (user, group, AND role -- see Account.all_principals) is a
node. Every escalation edge from checks.py is an edge, labeled with its
technique. A principal that's already admin gets a direct edge to the
ADMIN sentinel node. From there, "can this user reach admin, and how" is
just a shortest-path query.

BFS vs. Dijkstra: every edge here is unweighted -- a technique either
works or it doesn't, there's no "cost" that makes a 3-hop path cheaper
than a 2-hop one. networkx.shortest_path() on an unweighted graph runs
plain BFS, not Dijkstra (which only matters once edges carry weights).
Shortest paths matter to an attacker for the same reason they matter here:
the fewest-hop path is the one with the fewest permissions that need to
line up and the fewest places remediation has to touch -- it's both the
easiest path to exploit and the cheapest one to fix.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import networkx as nx

from iam_paths.checks import run_all_checks
from iam_paths.evaluator import Decision, can
from iam_paths.models import ADMIN, User

if TYPE_CHECKING:
    from iam_paths.models import Account, Group, Role

_ADMINISTRATOR_ACCESS_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _has_administrator_access_attached(principal: User | Group | Role, account: Account) -> bool:
    """AdministratorAccess is AWS-managed, so its document is never in our
    dataset (see ManagedPolicyRef) -- can() has nothing to evaluate for it.
    Whether it's attached has to be checked by name/ARN directly, including
    through a user's group memberships."""
    if any(ref.arn == _ADMINISTRATOR_ACCESS_ARN for ref in principal.attached_policies):
        return True
    if isinstance(principal, User):
        for group in account.groups:
            if group.name in principal.group_names and any(
                ref.arn == _ADMINISTRATOR_ACCESS_ARN for ref in group.attached_policies
            ):
                return True
    return False


def is_admin(principal: User | Group | Role, account: Account) -> bool:
    """A principal counts as admin if it has AdministratorAccess attached
    (directly or via a group), or if its own statements literally grant
    "*" on "*"."""
    if _has_administrator_access_attached(principal, account):
        return True
    return can(principal, "*", "*", account) == Decision.ALLOWED


def build_graph(account: Account) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node(ADMIN)

    for principal in account.all_principals():
        graph.add_node(principal.arn)

    for principal in account.all_principals():
        if is_admin(principal, account):
            graph.add_edge(
                principal.arn, ADMIN, technique="already_admin", permissions_used=[]
            )
        for edge in run_all_checks(principal, account):
            graph.add_edge(
                edge.source,
                edge.target,
                technique=edge.technique,
                permissions_used=edge.permissions_used,
            )

    return graph


@dataclass(frozen=True)
class Hop:
    source: str
    target: str
    technique: str
    permissions_used: list[str]


def shortest_attack_path(graph: nx.DiGraph, principal_arn: str) -> list[Hop] | None:
    """The fewest-hop route from this principal to ADMIN, with the
    technique used at each step. None if there's no path at all -- either
    the principal isn't in the graph, or nothing connects it to ADMIN."""
    try:
        nodes = nx.shortest_path(graph, principal_arn, ADMIN)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None

    hops = []
    for source, target in zip(nodes, nodes[1:], strict=False):
        data = graph.get_edge_data(source, target)
        hops.append(
            Hop(
                source=source,
                target=target,
                technique=data["technique"],
                permissions_used=data["permissions_used"],
            )
        )
    return hops


def all_user_attack_paths(account: Account, graph: nx.DiGraph) -> dict[str, list[Hop] | None]:
    return {user.arn: shortest_attack_path(graph, user.arn) for user in account.users}
