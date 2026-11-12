## terraform-secure-baseline

[![terraform-security](https://github.com/A1T888/terraform-secure-baseline/actions/workflows/security.yml/badge.svg)](https://github.com/A1T888/terraform-secure-baseline/actions/workflows/security.yml)

A zero-cost Terraform security demo. The same small AWS stack is written twice: `insecure/` (deliberately flawed) and `secure/` (hardened). Free scanners and policy-as-code show the difference, and a CI pipeline enforces it. Each fix is mapped to an ISO/IEC 27001:2022 Annex A control.

**Nothing is deployed and no cloud account is needed.** Everything runs as static analysis on the `.tf` files.

## Why this exists

Infrastructure as code moves security decisions into the code review stage. One misconfigured line, such as a public bucket, SSH open to the internet or a wildcard IAM policy, can expose a whole environment. Catching these before `terraform apply` is cheaper than finding them in production.

## Results

| Check | `insecure/` | `secure/` |
|---|---|---|
| Checkov (3.4.3) | 13 passed, **44 failed** | 145 passed, **0 failed**, 9 documented skips |
| Trivy IaC (HIGH/CRITICAL) | 15 findings | **0 findings** |
| Conftest custom policy (2 rules) | 2 violations | 2 of 2 pass |
| Gitleaks | no leaks (keys in `insecure/` are AWS documentation examples) | no leaks |
| `terraform validate` | valid | valid |

CI runs on every push: the hardened stack must pass, and the insecure stack is expected to fail.

![Scan results](docs/scan-results/ci-run.png)

## What is in the repo

```
terraform-secure-baseline/
├── insecure/main.tf            # intentionally flawed stack. Never deploy.
├── secure/main.tf              # hardened version of the same stack
├── policies/ssh_open.rego      # custom OPA/Conftest rules
├── docs/control-mapping.md     # fixes mapped to ISO 27001:2022 Annex A
├── docs/scan-results/          # screenshots
└── .github/workflows/security.yml
```

**What `insecure/` gets wrong:** public S3 ACL, no encryption or versioning, SSH and all TCP ports open to `0.0.0.0/0`, a wildcard (`*`) IAM policy, a public unencrypted database with a hardcoded password, no flow logs, no KMS key rotation, a single-region CloudTrail without log validation, and an unpinned provider with hardcoded (fake) credentials.

**What `secure/` does instead:** KMS encryption for storage and logs, private subnets, a restricted security group, a least-privilege IAM policy, CloudTrail with log validation, VPC flow logs, S3 access logging and versioning, RDS backups, deletion protection and Multi-AZ, a database password passed in as a sensitive variable, and a pinned provider version.

## Tools

| Purpose | Tool |
|---|---|
| Misconfiguration scanning | Checkov, Trivy |
| Secrets scanning | Gitleaks |
| Policy-as-code | OPA / Conftest (Rego) |
| Syntax and formatting | `terraform validate`, `terraform fmt` |
| CI | GitHub Actions |

## Run it yourself

No AWS credentials are needed.

```bash
# scanners
pip install checkov
checkov -d insecure --framework terraform
checkov -d secure   --framework terraform
trivy config secure/ --severity HIGH,CRITICAL
conftest test secure/main.tf --parser hcl2 -p policies/
gitleaks detect --source .

# validation (per folder)
terraform init -backend=false
terraform validate
```

## The CI pipeline

- **`hardened-must-pass`:** format check, Gitleaks, Checkov and Trivy against `secure/`. This job must be green.
- **`insecure-must-fail`:** Checkov against `insecure/`. This job is **expected to fail**. It proves the scanners catch the deliberate flaws, and `continue-on-error` stops it from blocking the build.

## Control mapping

Each fix is linked to the Checkov check and the closest ISO 27001:2022 Annex A control, for example encryption to A.8.24, logging to A.8.15, and access restriction to A.8.3. See [docs/control-mapping.md](docs/control-mapping.md). The mapping is my own judgement of the closest control. It is not an official crosswalk.

## Skipped checks

The hardened stack has 9 inline `#checkov:skip` comments, each with a written reason:

- **Cost or scope:** cross-region replication, S3 event notifications, CloudTrail SNS notifications and CloudWatch Logs integration, which need extra infrastructure that this baseline does not have.
- **False positives:** three checks on the KMS key policy, where `Resource = "*"` means "this key" by AWS design.

## Limitations

- Static analysis only. The code has never been applied to a real AWS account, so runtime behaviour, such as bucket-policy ordering for CloudTrail, is untested.
- Scanners find known misconfiguration patterns. They do not judge architecture or business risk.
- The state backend is local. A production setup would use an encrypted, versioned remote backend with locking.

## Lessons learned

> Replace this section with your own words before publishing. Keep only points you could explain in an interview.

- **One scanner is not enough.** Checkov passed the hardened stack, but Trivy flagged a high-severity rule on a security group allowing egress to `0.0.0.0/0`. Two scanners with different rule sets caught what one missed.
- **Not every finding should be "fixed".** Some checks needed extra cost or infrastructure, and some were false positives. Documenting each skip with a reason lets a reviewer challenge a decision instead of finding a silent suppression.
- **A failing job can be the correct result.** The insecure stack is meant to fail CI. That is the evidence the gate works.
- **Passing scans is not the same as secure.** These tools check known patterns. They do not prove the design is sound.
- **Control mapping is judgement.** There is no official crosswalk from Checkov rules to Annex A, so each link is a choice.

## Next steps

- Run against a real account with an encrypted remote state backend.
- Add `terraform plan` checks in CI with Conftest on the plan JSON.
- Pin every GitHub Action to a full commit SHA.
- Add more custom Rego rules, such as mandatory encryption on all buckets.

## Disclaimer

The credentials in `insecure/main.tf` are the public example keys from AWS documentation, not real secrets. The `insecure/` stack is for demonstration only and must never be deployed.
