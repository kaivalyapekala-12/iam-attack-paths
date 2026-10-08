# IAM Attack-Path Analyzer

A Python CLI that reads an AWS account's IAM setup (users, groups, roles, policies),
finds every way a low-privilege principal can escalate to admin, and recommends the
one permission to remove for each path.

![demo](demo.gif)

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

iam-paths scan --profile audit                                 # live, read-only (needs: pip install -e ".[live]")
```

Live scanning (`--profile`) calls the read-only `get-account-authorization-details`
API against whatever AWS CLI profile you name, paginated. It needs `boto3`
(`pip install -e ".[live]"`) and a profile already configured in `~/.aws` — see
below for setting one up with least-privilege (`SecurityAudit`) access.

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
10. Pass a privileged role to a Lambda function (direct invoke, or an event-source trigger like a DynamoDB stream)
11. Edit an existing Lambda function's code
12. Pass a privileged role to an EC2 instance
13. Pass a privileged role to a CloudFormation stack
14. Pass a privileged role to a CodeBuild project
15. Pass a privileged role to a Glue development endpoint
16. Pass a privileged role to a Data Pipeline
17. Pass a privileged role to a SageMaker notebook instance
18. Pass a privileged role to a SageMaker training job
19. Pass a privileged role to a SageMaker processing job

## Results on a real AWS account

Scanned a throwaway AWS account deployed with [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable)
(default, free config only — IAM resources, no Lambda/EC2/Glue/SageMaker/CloudFormation
modules). The account's Organization enforces a Service Control Policy denying
`iam:CreateGroup`, so 3 of 265 planned resources (all IAM Groups) never deployed —
noted below where it affects a specific scenario.

**Detected 14 of 32 escalation scenarios** in IAM Vulnerable's `privesc-paths` module:

`privesc1` `3` `4` `5` `6` `7` `8` `9` `10` `11` `12` `14` `15` `20`

The other 18, broken down by why:

| Why not detected | Count | Scenarios |
|---|---|---|
| Account's org SCP blocked `iam:CreateGroup`, so the target group was never created | 2 | `privesc13` (AddUserToGroup), `privesc-sre` (admin access flows through a group that doesn't exist) |
| IAM Vulnerable's own maintainers note it isn't exploitable via Terraform alone (confirmed in their source comment: needs a manually-created 2nd policy version) | 1 | `privesc2` (SetExistingDefaultPolicyVersion) |
| Needs the optional (paid) Lambda module, which wasn't deployed — no function exists to edit | 1 | `privesc17` (EditExistingLambdaFunctionWithRole) |
| Out of this tool's 13 techniques by design (CodeBuild, EC2 Instance Connect, SageMaker, SSM, Glue, CloudFormation `UpdateStack`, Data Pipeline) | 12 | `privesc-codeBuildCreateProjectPassRole`, `privesc-ec2InstanceConnect`, `privesc-sageMaker*` (×4), `privesc-ssm*` (×2), `privesc18`, `privesc19`, `privesc-CloudFormationUpdateStack`, `privesc21` |
| Real technique-coverage gap: needs a Lambda `CreateEventSourceMapping` (DynamoDB-trigger) variant of pass-role-to-Lambda; this tool's check only covers the direct-invoke variant | 1 | `privesc16` |
| Chain genuinely traversable (confirmed: the edge exists in the graph) — just never the *shortest* path for an already-admin deployer, since the scenario is designed around a separate low-privilege identity | 1 | `privesc-AssumeRole` chain |

**Correctness validation** (IAM Vulnerable's separate `tool-testing` module, built specifically
to catch scanners with wrong Allow/Deny/NotAction/Condition logic):
- **5 of 5** "false positive" traps correctly produced *no* path — confirms explicit-Deny-wins,
  `NotAction`, resource-scoping, and condition-scoping are all handled correctly and the tool
  doesn't over-report.
- **3 of 4** "false negative" traps correctly detected. The one miss
  (`fn3-exploitableConditionConstraint`) is intentional: this tool only resolves conditions we
  can't verify at scan time (see Limitations) by refusing to claim the path exists, rather than
  guessing — the deliberate trade-off that makes the 5/5 false-positive result above possible.

False positives found: **0**.

PMapper comparison: not done.

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
