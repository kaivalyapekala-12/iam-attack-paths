import json
from pathlib import Path

import pytest

from iam_paths.cli import main

SAMPLE = Path(__file__).parent.parent / "samples" / "sample_account.json"


def test_scan_table_exits_zero_without_fail_on(capsys):
    exit_code = main(["scan", "--file", str(SAMPLE), "--format", "table"])
    assert exit_code == 0
    assert "alice" in capsys.readouterr().out


def test_scan_json_to_stdout_is_valid_and_includes_every_user(capsys):
    exit_code = main(["scan", "--file", str(SAMPLE), "--format", "json"])
    assert exit_code == 0
    rows = json.loads(capsys.readouterr().out)
    names = {row["principal"] for row in rows}
    assert names == {"alice", "bob", "carol", "dave", "eve", "frank", "grace", "ops-admin"}


def test_scan_json_to_file(tmp_path, capsys):
    out_path = tmp_path / "report.json"
    exit_code = main(["scan", "--file", str(SAMPLE), "--format", "json", "--out", str(out_path)])
    assert exit_code == 0
    rows = json.loads(out_path.read_text())
    assert len(rows) == 8
    assert capsys.readouterr().out == ""


def test_scan_html_writes_a_file(tmp_path):
    out_path = tmp_path / "report.html"
    exit_code = main(["scan", "--file", str(SAMPLE), "--format", "html", "--out", str(out_path)])
    assert exit_code == 0
    html = out_path.read_text()
    assert "<html>" in html
    assert "alice" in html


def test_fail_on_critical_exits_nonzero_when_a_critical_finding_exists(capsys):
    # Alice is a 1-hop (Critical) finding in the sample.
    exit_code = main(["scan", "--file", str(SAMPLE), "--format", "json", "--fail-on", "critical"])
    capsys.readouterr()
    assert exit_code == 1


def test_no_fail_on_exits_zero_even_with_critical_findings(capsys):
    exit_code = main(["scan", "--file", str(SAMPLE), "--format", "json"])
    capsys.readouterr()
    assert exit_code == 0


def test_profile_flag_is_not_implemented_yet(capsys):
    exit_code = main(["scan", "--profile", "audit"])
    assert exit_code == 2
    assert "Step 8" in capsys.readouterr().err


def test_file_and_profile_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        main(["scan", "--file", str(SAMPLE), "--profile", "audit"])
