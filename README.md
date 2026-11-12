# terraform-secure-baseline

[![terraform-security](https://github.com/A1T888/terraform-secure-baseline/actions/workflows/security.yml/badge.svg)](https://github.com/A1T888/terraform-secure-baseline/actions/workflows/security.yml)

Static-analysis security showcase for Terraform. The same AWS stack is written twice:
`insecure/` (deliberately flawed) and `secure/` (hardened). Free scanners and policy-as-code
prove the difference. **Nothing is deployed and no cloud account is needed.**

## Results

| Stack | Checkov passed | Checkov failed | Skipped (justified) | Conftest policy |
|---|---|---|---|---|
| `insecure/` | 13 | **44** | 0 | 2 violations |
| `secure/` | 145 | **0** | 9 | 2 of 2 pass |

Checkov 3.4.3, Conftest 0.56.0. Skips are inline `#checkov:skip` comments with a reason
(cross-region replication, SNS and event notifications, CloudWatch integration: cost or scope;
KMS key-policy `Resource = "*"` checks: false positives by AWS design).

## Run it

```bash
pip install checkov
checkov -d insecure --framework terraform
checkov -d secure   --framework terraform
conftest test secure/main.tf --parser hcl2 -p policies/
gitleaks detect --source .
```

## What it covers

- Misconfiguration scanning (Checkov, Trivy)
- Secrets scanning (Gitleaks)
- Custom policy-as-code (OPA/Conftest): no SSH from the internet, provider must set default tags
- CI gate on GitHub Actions: hardened stack must pass, insecure stack is expected to fail
- Mapping to ISO 27001:2022 Annex A: see [docs/control-mapping.md](docs/control-mapping.md)

## Limitations

Static analysis only. The code has not been applied to a real account, so runtime behaviour
(for example CloudTrail bucket-policy ordering) is untested. Scanners find known misconfiguration
patterns, not design flaws.

## Lessons learned

(Write 3 to 4 honest points here: what surprised you, what you chose to skip and why.)
