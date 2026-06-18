# Acme Health Capstone — Design Document

A 30-day GRC engineering exercise: take a deliberately non-compliant Patient Intake API (`cgep-app-starter`) and wrap it in the engineering controls that would let an auditor verify SOC 2 Trust Services Criteria coverage without ever speaking to the engineering team.

## Framework choice

**Primary framework: SOC 2 Type II (Trust Services Criteria).**

Acme is a 50-person telehealth company. Three frameworks are in play:
- **HIPAA Security Rule**: applicable (PHI is at stake; the workload tags every resource `DataClass=phi`). Required for the business to operate but rarely the "show me the report" framework in enterprise procurement.
- **SOC 2 Type II**: an enterprise customer is asking. This is the artifact a procurement team will request.
- **CMMC Level 2**: federal pilot is "on the table" but speculative.

For a 30-day engineering deliverable, SOC 2 is the highest-leverage choice:
- Most enterprise customers won't sign without a SOC 2 report
- The Trust Services Criteria map cleanly to engineering controls (encryption, access enforcement, monitoring, change management)
- AICPA doesn't publish an official OSCAL catalog for SOC 2, so we cite **NIST 800-53 Rev 5** in the OSCAL `source` field and tag each implemented-requirement with the SOC 2 CC ID as a `prop`. This is standard practice and matches how SOC 2 audits actually map to control libraries in production.

HIPAA-relevant hardening (encryption at rest, transit, access logging) is incidentally satisfied by the SOC 2 work. CMMC L2 is acknowledged as future work in the WRITEUP but not pursued in this iteration.

## System inventory

### What the starter ships

The starter deploys 21 resources for a Patient Intake API:
- VPC + 2 public subnets + 2 private subnets + IGW + route table (network)
- API Gateway v2 (HTTP API): one route `POST /intake`
- Lambda function (Python 3.12, in-line zip from `terraform/lambda/handler.py`)
- IAM role + inline policy for Lambda (overprivileged by design)
- DynamoDB table (PAY_PER_REQUEST)
- S3 uploads bucket (force_destroy off, SSE-S3 only)
- Random ID suffix for uniqueness

Deploy gate proven on Day 1: API returned `{"submission_id": "67a5e2a4-...", "status": "received"}` (see `docs/deploy-gate-receipt.md`).

### What this capstone adds

| Layer | Adds | Purpose |
|-------|------|---------|
| Terraform baseline | KMS CMK, S3 evidence vault with Object Lock, CloudTrail multi-region, IAM policy tightening, Lambda VPC config, DynamoDB encryption override, TLS-only bucket policy | Closes the 8 gaps; produces governance posture |
| OPA policy suite | 5 Rego policies + tests, run via Conftest in CI | Detective enforcement keyed to SOC 2 CC IDs |
| GitHub Actions pipeline | One workflow: plan → policy gate → apply → Cosign sign → upload to vault | The chain of custody from PR to immutable evidence |
| OSCAL component | `compliant-intake-api` component-definition + minimal profile | Machine-readable assurance document |

## Gap-by-gap closure plan

The starter's `GAPS.md` lists 8 named, intentional non-compliance gaps. Each is closed by Terraform overrides (preventative) and 5 of them are additionally policed by Rego (detective). Closing in both layers demonstrates defense-in-depth; running on existing infrastructure means even a manual misconfiguration would be caught at the next pipeline run.

| ID | Description | SOC 2 | Terraform | Rego |
|----|-------------|-------|-----------|------|
| GAP-01 | S3 uploads bucket: SSE-S3 instead of CMK | CC6.1 | `kms.tf` (new CMK) + `hardening.tf` (point bucket at CMK) | `sc28_s3_cmk.rego` |
| GAP-02 | DynamoDB: AWS-owned key, not CMK | CC6.1 | `hardening.tf` (DDB `server_side_encryption` block with CMK) | `sc28_ddb_cmk.rego` |
| GAP-03 | No TLS-only bucket policy (`aws:SecureTransport`) | CC6.7 | `hardening.tf` (bucket policy with Deny on non-TLS) | `sc7_tls_only.rego` |
| GAP-04 | No versioning on uploads bucket | A1.2 | `hardening.tf` (versioning block) | (Terraform only) |
| GAP-05 | Lambda not in VPC | CC6.6 | `hardening.tf` (Lambda `vpc_config` block, sg + private subnets from starter outputs) | `cc66_lambda_vpc.rego` |
| GAP-06 | No DLQ, no X-Ray, no reserved concurrency | CC7.2 | `hardening.tf` (DLQ SQS, `tracing_config`, `reserved_concurrent_executions`) | (Terraform only) |
| GAP-07 | Lambda IAM has `dynamodb:*` and `s3:*` | CC6.3 | `hardening.tf` (override `aws_iam_role_policy.lambda_inline` with scoped actions) | `cc63_iam_least_priv.rego` |
| GAP-08 | API Gateway: no logging, throttling, WAF | CC7.2 | `hardening.tf` (stage logging + throttle settings; WAF deferred) | (Terraform only) |

**5 Rego policies, mapped to 4 different SOC 2 CCs (CC6.1, CC6.7, CC6.6, CC6.3).** Range matters more than count.

**3 Terraform-only gaps (GAP-04, 06, 08)** are still closed; they're not gated by Rego because the patterns are repetitive enough that one example of each pattern in the Rego suite makes the point. The OSCAL component captures all 8 gaps in `implemented-requirements`; the Rego layer is a subset.

## Architectural decisions

| Decision | Choice | Why |
|----------|--------|-----|
| AWS region | us-east-1 | Cheapest; matches starter default; consistent with all prior lab work |
| Object Lock mode on evidence vault | **GOVERNANCE** (1-day retention for capstone, scaled to 365-day in production) | Allows account admin to override in emergency; matches Lab 2.5 pattern; sufficient for SOC 2 (Type II auditors accept GOVERNANCE with documented override controls) |
| Apply trigger in pipeline | Apply on merge to `main`, no manual gate | Demonstrates the full automation story; the policy gate on the PR is the human checkpoint |
| Account topology | Single account | Acceptable per the brief for 30-day delivery. WRITEUP documents that a separate evidence-vault account would be the production pattern. |
| Authentication | AWS IAM Identity Center (SSO), MFA required, no static IAM keys | Established Day 2 after a credential-leak incident. Documented as the "right" pattern for human access; CI uses GitHub OIDC short-lived tokens. |
| Lambda runtime | Python 3.12 (starter default) | Not changing the workload. Capstone is governance, not rewriting the app. |
| Versioning + Object Lock | Both enabled on uploads bucket AND evidence vault | Versioning enables Object Lock; Object Lock requires versioning. They go together. |
| KMS key rotation | Enabled (annual, AWS default) | SC-12 requirement; one of the cheapest defenses to add |
| Cost guardrails | AWS Billing & Cost Management | Account-wide $20/month budget with default email alerts. Expected capstone spend: $10-20 across KMS key, CloudTrail bucket storage, evidence vault storage, and CI runs

## Repository structure
cgep-app-starter/
├── terraform/                  (starter)
│   ├── main.tf                 (starter, untouched)
│   ├── outputs.tf              (starter, untouched)
│   ├── variables.tf            (starter, untouched)
│   ├── lambda/                 (starter)
│   ├── kms.tf                  (NEW: CMK for S3+DDB)
│   ├── evidence-vault.tf       (NEW: S3 Object Lock vault)
│   ├── cloudtrail.tf           (NEW: management-events trail)
│   └── hardening.tf            (NEW: all GAP-closing overrides)
├── policies/                   (NEW)
│   ├── sc28_s3_cmk.rego
│   ├── sc28_ddb_cmk.rego
│   ├── sc7_tls_only.rego
│   ├── cc66_lambda_vpc.rego
│   ├── cc63_iam_least_priv.rego
│   └── tests/
│       └── *_test.rego
├── component-definitions/      (NEW, trestle-native layout)
│   └── compliant-intake-api/component-definition.json
├── profiles/                   (NEW, trestle-native layout)
│   └── soc2-cc-minimum/profile.json
├── scripts/                    (NEW)
│   ├── capture-evidence.sh     (ported from Lab 2.5)
│   ├── verify-evidence.sh      (ported from Lab 4.4)
│   └── policy-gate.sh          (ported from Lab 3.4)
├── oidc/                       (NEW, isolated state)
│   └── main.tf                 (GitHub OIDC provider + role for CI)
├── .github/workflows/          (NEW)
│   └── grc-gate.yml            (plan → policy → apply → sign → upload)
├── docs/                       (NEW)
│   ├── design.md               (this file)
│   └── deploy-gate-receipt.md  (Day 1 proof)
├── evidence/                   (NEW)
│   └── (per-control captures)
├── WRITEUP.md                  (NEW, final reflection)
├── README.md                   (REPLACED)
├── Makefile                    (starter, possibly modified for python3 portability)
└── (starter's other files: GAPS.md, FRAMEWORKS.md, WORKLOAD.md, test/)
### Why this structure

Two non-obvious choices:

1. **Evidence vault Terraform is in `terraform/` next to the starter, not in its own folder.** The vault deploys with the workload; their lifecycles are coupled (the pipeline writes to a vault that has to exist when the pipeline runs). Sharing state simplifies CI.

2. **OIDC is in its own folder with its own state.** The IAM role created for GitHub Actions is high-trust infrastructure that should rarely change. Isolating its state prevents CI changes to the workload from accidentally modifying the OIDC trust relationship.

## What's not in scope (explicit non-goals)

- **WAF on API Gateway**: GAP-08's full closure includes WAF. Deferred; documented in WRITEUP. WAF is a $5/month addition that the budget supports but adds limited value for the demonstration.
- **Cross-account evidence isolation**: out of scope for 30-day delivery; acknowledged as the production pattern.
- **HIPAA-specific safeguards beyond SOC 2 overlap**: HIPAA Security Rule has Administrative + Physical safeguards that this capstone doesn't address (training, BAAs, facility access). The Technical Safeguards (encryption, access logs, audit controls) are incidentally satisfied by the SOC 2 work.
- **Lambda code review or rewrite**: the brief explicitly says don't rewrite the app. The handler.py stays as-is.
- **CMMC L2 mapping**: noted as available but not pursued.

## Risk acknowledgments

- **Single AWS account.** A determined insider with admin in the account could in theory tamper with the evidence vault. The chain of custody we engineer (Cosign signing via GitHub OIDC, Rekor transparency log) detects this even when the account is fully compromised, because the Rekor entry lives outside the account.
- **Object Lock in GOVERNANCE mode allows override.** Documented as a deliberate choice for an emergency-recovery scenario; mitigated by Cosign signatures that don't depend on Object Lock to be verifiable.
- **Apply-on-merge with no second human gate.** The policy gate on the PR is the human checkpoint; merging is the approval. Acceptable for a 30-day exercise; in production a 4-eyes approval on apply would be added.

## Status as of Day 2

- ✅ Deploy gate cleared (Day 1)
- ✅ SSO authentication established (Day 2, replacing leaked static keys)
- ✅ Folder structure created
- ✅ Design doc written (this file)
- ⏳ OIDC Terraform ported (Day 2, in progress)
- ⏳ Evidence vault Terraform ported (Day 2, in progress)
- ☐ Hardening Terraform written (Week 2)
- ☐ Rego policies written (Week 3)
- ☐ Pipeline wired (Week 3)
- ☐ OSCAL authored (Week 4)
- ☐ WRITEUP written (Week 4)

28 days remaining.