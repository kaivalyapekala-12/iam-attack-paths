# IAM Attack-Path Analyzer

A Python CLI that reads an AWS account's IAM setup (users, groups, roles, policies),
finds every way a low-privilege principal can escalate to admin, and recommends the
one permission to remove for each path.

<!-- TODO: demo GIF here -->

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

iam-paths scan --file samples/sample_account.json --format table
```

> If `iam-paths` raises `ModuleNotFoundError: No module named 'iam_paths'` right after
> an editable install, that's a known Python 3.14 bug in its frozen `site` module
> silently failing to process the editable-install `.pth` file. Work around it with
> a regular install instead: `pip install .` (re-run after each code change).



## Commands

```bash
iam-paths scan --file samples/sample_account.json              # offline, table output
iam-paths scan --file samples/sample_account.json --format json
iam-paths scan --file samples/sample_account.json --format html --out out/report.html
iam-paths scan --file samples/sample_account.json --fail-on critical  # exits 1 if any Critical finding
```

Live scanning against a real AWS account (`--profile`) is reserved for Step 8 and not
implemented yet.

## Techniques detected

Based on [Rhino Security Labs' AWS privilege-escalation research](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/):

1. New policy version on a policy attached to self
2. Attach a managed policy to self
3. Write an inline policy on self
4. Assume a role whose trust policy allows you
5. Create an access key for another user
6. Add yourself to a group
7. Set/reset another user's console password
8. Roll back a policy to a broader old version
9. Rewrite a role's trust policy, then assume it
10. Pass a privileged role to a Lambda function
11. Edit an existing Lambda function's code
12. Pass a privileged role to an EC2 instance
13. Pass a privileged role to a CloudFormation stack

## Results on a real AWS account

Pending Step 8 (testing against [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable)).

## Limitations (v1)

- No permission boundaries, no Service Control Policies (SCPs), no resource-based
  policies other than role trust policies.
- A matching statement with a `Condition` is flagged as `ALLOWED_WITH_CONDITION`
  rather than evaluated, since its truth depends on runtime request context (MFA,
  source IP, tags, ...) this tool doesn't have. Conditional grants don't appear as
  graph edges for the same reason.
- Technique #11 (editing existing Lambda code) needs a function → execution-role
  mapping that `get-account-authorization-details` doesn't provide; it's always a
  no-op against an offline scan today.

## Credits

- Privilege-escalation techniques: [Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- Real-account validation: [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable) (Bishop Fox)
