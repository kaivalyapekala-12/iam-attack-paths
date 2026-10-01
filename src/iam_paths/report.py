"""Shape the attack graph + remediation findings into one row per user,
independent of how that row ends up being displayed. cli.py picks a
render_* function based on --format; both read from the same ReportRow
list, so table/json/html can never silently disagree about what was
found.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from iam_paths.graph import build_graph, shortest_attack_path
from iam_paths.models import ADMIN
from iam_paths.remediation import remediate

if TYPE_CHECKING:
    from rich.table import Table

    from iam_paths.graph import Hop
    from iam_paths.models import Account


def _short_name(arn: str) -> str:
    """ADMIN stays ADMIN; an ARN like .../user/carol or .../role/DeployRole
    becomes just "carol" / "DeployRole" -- the part a person actually reads
    in a table, not the full ARN."""
    if arn == ADMIN:
        return ADMIN
    return arn.rsplit("/", 1)[-1]


def _path_summary(path: list[Hop]) -> str:
    names = [_short_name(path[0].source), *(_short_name(hop.target) for hop in path)]
    return " -> ".join(names)


def _technique_chain(path: list[Hop]) -> str:
    return " -> ".join(hop.technique for hop in path)


@dataclass(frozen=True)
class ReportRow:
    principal: str
    reaches_admin: bool
    severity: str | None
    path: str
    technique: str
    fix: str | None
    control_tags: list[str]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_report(account: Account) -> list[ReportRow]:
    graph = build_graph(account)
    rows = []
    for user in account.users:
        path = shortest_attack_path(graph, user.arn)
        if path is None:
            rows.append(
                ReportRow(
                    principal=user.name,
                    reaches_admin=False,
                    severity=None,
                    path="(no path to admin)",
                    technique="",
                    fix=None,
                    control_tags=[],
                )
            )
            continue

        finding = remediate(account, user.arn, path)
        fix = None
        control_tags: list[str] = []
        if finding is not None:
            owner_name = finding.grant.owner.name
            policy_name = finding.grant.policy_name
            fix = f"Remove {finding.removed_permission} from {owner_name}'s {policy_name} policy"
            control_tags = finding.control_tags

        rows.append(
            ReportRow(
                principal=user.name,
                reaches_admin=True,
                severity=finding.severity if finding is not None else None,
                path=_path_summary(path),
                technique=_technique_chain(path),
                fix=fix,
                control_tags=control_tags,
            )
        )
    return rows


def render_json(rows: list[ReportRow]) -> str:
    return json.dumps([row.as_dict() for row in rows], indent=2)


def render_table(rows: list[ReportRow]) -> Table:
    from rich.table import Table

    table = Table(title="IAM Attack Paths")
    table.add_column("User")
    table.add_column("Reaches Admin")
    table.add_column("Severity")
    table.add_column("Path")
    table.add_column("Technique")
    table.add_column("Fix")

    severity_style = {"Critical": "bold red", "High": "yellow"}
    for row in rows:
        style = severity_style.get(row.severity)
        table.add_row(
            row.principal,
            "yes" if row.reaches_admin else "no",
            row.severity or "-",
            row.path,
            row.technique or "-",
            row.fix or "-",
            style=style,
        )
    return table


_HTML_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>IAM Attack Paths</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
  body {{
    font-family: -apple-system, sans-serif; margin: 2rem;
    background: #0b0f14; color: #e6edf3;
  }}
  h1 {{ font-size: 1.4rem; }}
  .finding {{
    border: 1px solid #30363d; border-radius: 8px;
    padding: 1rem; margin-bottom: 1.5rem;
  }}
  .critical {{ border-left: 4px solid #f85149; }}
  .high {{ border-left: 4px solid #d29922; }}
  .none {{ border-left: 4px solid #3fb950; }}
  .meta {{ color: #8b949e; font-size: 0.9rem; }}
  code {{ background: #161b22; padding: 0.1rem 0.3rem; border-radius: 4px; }}
</style>
</head>
<body>
<h1>IAM Attack Paths</h1>
{findings}
<script>mermaid.initialize({{ startOnLoad: true, theme: "dark" }});</script>
</body>
</html>
"""

_FINDING_TEMPLATE = """<div class="finding {css_class}">
  <h2>{principal}</h2>
  <p class="meta">Severity: {severity} | Controls: {controls}</p>
  <pre class="mermaid">
graph LR
{mermaid_edges}
  </pre>
  <p>Fix: {fix}</p>
</div>
"""


def _mermaid_edges(path: list[Hop]) -> str:
    lines = []
    for hop in path:
        src = _short_name(hop.source).replace(" ", "_")
        dst = _short_name(hop.target).replace(" ", "_")
        lines.append(f'    {src} -->|{hop.technique}| {dst}')
    return "\n".join(lines)


def render_html(rows: list[ReportRow], account: Account) -> str:
    graph = build_graph(account)
    findings = []
    for user, row in zip(account.users, rows, strict=False):
        if not row.reaches_admin:
            findings.append(
                _FINDING_TEMPLATE.format(
                    css_class="none",
                    principal=row.principal,
                    severity="none",
                    controls="-",
                    mermaid_edges=f"    {_short_name(user.arn)}[no path to admin]",
                    fix="-",
                )
            )
            continue
        path = shortest_attack_path(graph, user.arn)
        findings.append(
            _FINDING_TEMPLATE.format(
                css_class=row.severity.lower() if row.severity else "none",
                principal=row.principal,
                severity=row.severity or "-",
                controls=", ".join(row.control_tags) or "-",
                mermaid_edges=_mermaid_edges(path) if path else "",
                fix=row.fix or "-",
            )
        )
    return _HTML_TEMPLATE.format(findings="\n".join(findings))
