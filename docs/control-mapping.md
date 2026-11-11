# Control mapping: Terraform checks to ISO/IEC 27001:2022 Annex A

| Risk in `insecure/` | Fix in `secure/` | Checkov IDs | Annex A control |
|---|---|---|---|
| Public S3 ACL, no public access block | `aws_s3_bucket_public_access_block` | CKV_AWS_20, CKV2_AWS_6 | A.8.3 Information access restriction |
| Unencrypted S3 / RDS / trail | SSE-KMS, `storage_encrypted`, trail `kms_key_id` | CKV_AWS_145, CKV_AWS_16, CKV_AWS_35 | A.8.24 Use of cryptography |
| KMS key rotation off, no key policy | `enable_key_rotation`, explicit key policy | CKV_AWS_7, CKV2_AWS_64 | A.8.24 Use of cryptography |
| SSH open to 0.0.0.0/0 | Restricted to `var.admin_cidr` | CKV_AWS_24 | A.8.20 Networks security, A.8.22 Segregation of networks |
| Wildcard IAM policy | Scoped read-only policy | CKV_AWS_62, CKV_AWS_63, CKV_AWS_355 | A.5.15 Access control, A.8.2 Privileged access rights |
| Hardcoded credentials / DB password | Env or role credentials, sensitive variable | CKV_AWS_41 | A.5.17 Authentication information |
| No CloudTrail validation, single region | Multi-region, log validation | CKV_AWS_36, CKV_AWS_67 | A.8.15 Logging |
| No VPC flow logs, no S3 access logs | `aws_flow_log`, `aws_s3_bucket_logging` | CKV2_AWS_11, CKV_AWS_18 | A.8.15 Logging, A.8.16 Monitoring activities |
| No versioning, backups, deletion protection | Versioning, 7-day backups, protection on | CKV_AWS_21, CKV_AWS_133, CKV_AWS_293 | A.8.13 Information backup |
| Public RDS, no Multi-AZ | Private subnets, Multi-AZ | CKV_AWS_17, CKV_AWS_157 | A.8.14 Redundancy of information processing facilities |
| Unpinned provider | `~> 5.60` plus `required_version` | n/a | A.8.30 Outsourced development, A.5.21 ICT supply chain |
| Unreviewed changes | PR + CI gate (branch protection) | n/a | A.8.32 Change management |

Mapping is my own judgement of the closest control, not an official crosswalk. State that in your README.
