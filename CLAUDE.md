# IAM Attack-Path Analyzer

## Goal
A Python CLI that reads AWS IAM data (users, groups, roles, policies),
finds privilege-escalation paths to admin, and recommends least-privilege fixes.

## Stack
Python 3.12, networkx, boto3 (live mode only), pytest, ruff, rich (CLI tables).

## Layout
src/iam_paths/  loader.py, models.py, evaluator.py, checks.py, graph.py,
                remediation.py, report.py, cli.py
tests/          one test file per module
samples/        fake account JSON only

## Rules
- I am learning: explain every design decision and each new file in plain words.
- Work on ONE step at a time. Write the tests first, then the code.
- Keep functions small and typed. Run pytest and ruff before saying a step is done.
- NEVER commit AWS keys, real account data, or anything from ~/.aws.
- Live AWS calls must be read-only.
