# terraform-secure-baseline

[![terraform-security](https://github.com/A1T888/terraform-secure-baseline/actions/workflows/security.yml/badge.svg)](https://github.com/A1T888/terraform-secure-baseline/actions/workflows/security.yml)

Terraform security demo. The same small AWS stack is written twice: `insecure/` (deliberately flawed) and `secure/` (hardened). Free scanners and policy-as-code show the difference, and a CI pipeline enforces it. Each fix is mapped to an ISO/IEC 27001:2022 Annex A control.

**Nothing is deployed and no cloud account is needed.** Everything runs as static analysis on the `.tf` files.

> [!WARNING]
> `insecure/` is deliberately vulnerable and is for demonstration only. Do not deploy it. The access keys in that folder are the public example keys from AWS documentation, not real credentials.

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

## What is in the repo

```
terraform-secure-baseline/
├── insecure/main.tf            # intentionally flawed stack. Never deploy.
├── secure/main.tf              # hardened version of the same stack
├── policies/ssh_open.rego      # custom OPA/Conftest rules
├── docs/control-mapping.md     # fixes mapped to ISO 27001:2022 Annex A
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

- **A second scanner found something the first missed.** Checkov passed the hardened stack, but Trivy flagged a security group allowing egress to `0.0.0.0/0` (AWS-0104). That is one finding, not proof that two scanners always beat one, but it showed that their rule sets differ.
- **A scan-clean fix is not a tested fix.** I restricted egress to the VPC range to satisfy Trivy. In a real deployment that could block access to AWS services unless VPC endpoints are added, and I have not applied the stack to verify.
- **Skips need reasons.** Of the 9 skips, six were cost or scope items and three were false positives on KMS key policies. Writing the reason next to each one lets a reviewer challenge the decision instead of finding a silent suppression.
- **The insecure stack is a negative test.** CI is meant to fail on it, and that proves the gate catches real flaws. A red cross inside a passing run is confusing, so the pipeline section explains it.
- **Scanners are evidence, not compliance.** They check technical configuration. ISO 27001 Annex A also covers policy, process and review, so a passing check supports a control without proving it. The mapping is my own judgement of the closest control.

## Next steps

- Run against a real account with an encrypted remote state backend.
- Add `terraform plan` checks in CI with Conftest on the plan JSON.
- Pin every GitHub Action to a full commit SHA.
- Add more custom Rego rules, such as mandatory encryption on all buckets.
