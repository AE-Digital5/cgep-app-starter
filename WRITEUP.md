# Capstone WRITEUP — Acme Health Patient Intake API

A 30-day GRC engineering exercise: closing 8 named compliance gaps on a deliberately non-compliant Patient Intake API and producing a signed evidence pipeline an auditor can verify without speaking to the engineering team.

Framework: SOC 2 Type II (Trust Services Criteria).

## What's in this submission

A working, evidence-producing GRC pipeline, not just a hardened workload. Four layers:

- **Hardened workload Terraform** closing all 8 named gaps in `GAPS.md`. Customer-managed KMS encryption on S3 and DynamoDB, TLS-only bucket policies, Lambda in private VPC subnets with gateway endpoints for AWS data plane access, DLQ + X-Ray + reserved concurrency on the Lambda, API Gateway access logging and throttling, multi-region CloudTrail with log file validation, scoped IAM role policies.
- **Rego policy gate** (5 policies, 21 unit tests, all passing) detecting 5 of the 8 gaps in any future Terraform plan. The policies enforce the same controls the Terraform implements, so accidental regressions in code review never reach apply.
- **GitHub Actions CI pipeline** (`grc-gate.yml`) that runs plan → policy gate → apply → sign with Cosign keyless → upload to evidence vault. The vault is S3 with Object Lock GOVERNANCE and a bucket policy denying deletion to anyone but root.
- **OSCAL component-definition** mapping every gap closure to a NIST 800-53 Rev 5 control with the SOC 2 Trust Services Criterion ID as a prop. Validates clean with trestle v4.0.3.

The signed evidence bundle in `s3://cgep-capstone-evidence-vault-65cc2469/evidence/` is the auditor's artifact. Cosign verifies the bundle came from this workflow file at this commit; `sha256sum -c` verifies the bundle hasn't been altered; the bundle contents prove the policies passed and the apply succeeded. Verification details are at the end of this document.

## Why SOC 2 (and not HIPAA or CMMC)

The starter is a Patient Intake API, so a real production system would need HIPAA. The capstone targets SOC 2 Type II instead, for three reasons.

**First, SOC 2 is the right lens for the actual engineering work**. SOC 2's Trust Services Criteria are technical controls (encryption, access, monitoring, change management) — exactly what the 8 gaps in GAPS.md describe. HIPAA is largely process and contractual (Business Associate Agreements, breach notification timelines, workforce training), which a 30-day technical capstone can't meaningfully demonstrate. CMMC is similar — heavy on documentation maturity, less on the implementation patterns.

**Second, SOC 2 maps cleanly to NIST 800-53**, which has an OSCAL catalog at <https://github.com/usnistgov/oscal-content>. AICPA does not publish OSCAL for SOC 2 directly. Selecting SOC 2 as the framework while encoding the implementation in OSCAL via NIST controls lets the work pass through any auditor's OSCAL-aware tooling. The convention used here is: each `implemented-requirement` has its NIST control as `control-id` and the SOC 2 CC ID as a `soc2-cc` prop.

**Third, SOC 2's Trust Services Criteria are a defensible superset for this workload**. Encryption at rest (CC6.1) is required by both SOC 2 and HIPAA. Network segmentation (CC6.6) is in both. Audit logging (CC4.1, CC7.2) is in both. A workload that passes SOC 2 against these criteria would not be HIPAA-compliant out of the box (missing BAAs and notification procedures) but the technical posture is the same. The decision to scope to SOC 2 is honest about what 30 days of code can produce.

## How the 8 gaps were closed

| Gap | SOC 2 | NIST | Closure pattern |
|-----|-------|------|------|
| GAP-01: S3 not encrypted with CMK | CC6.1 | SC-28 | `aws_kms_key.phi` + `aws_s3_bucket_server_side_encryption_configuration` on uploads, vault, and CloudTrail buckets. CMK alias `acme-health-phi` with annual rotation enabled. |
| GAP-02: DynamoDB not encrypted with CMK | CC6.1 | SC-28 | `server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.phi.arn }` on the intake table. Same CMK as GAP-01. |
| GAP-03: S3 buckets allow non-TLS | CC6.7 | SC-7, SC-8 | `aws_s3_bucket_policy` on all three buckets with `Deny` on `s3:*` gated on `aws:SecureTransport = false`. |
| GAP-04: S3 versioning disabled | A1.2 | CP-9 | `aws_s3_bucket_versioning` enabled on uploads bucket. Enables future Object Lock for PHI immutability. |
| GAP-05: Lambda in public network | CC6.6 | SC-7 | Lambda in two private subnets, gateway VPC endpoints for S3 + DynamoDB, security group permits HTTPS egress only. |
| GAP-06: Lambda has no resilience controls | CC7.2 | SI-11 | DLQ (KMS-encrypted SQS), X-Ray Active tracing, reserved concurrency intent (see Decisions section for sandbox-budget nuance). |
| GAP-07: Lambda IAM uses service wildcards | CC6.3 | AC-6 | Lambda role's inline policy narrowed from `dynamodb:*` and `s3:*` to `dynamodb:PutItem` on the intake table and `s3:PutObject` on the `uploads/*` prefix only, plus KMS perms on the PHI CMK. |
| GAP-08: API Gateway has no logging or throttling | CC7.2 | AU-2 | Access logging to a KMS-encrypted CloudWatch log group, 30-day retention, JSON format. Route-level throttling at 100 req/s rate, 50 req/s burst. |

Five of the eight (GAP-01, 02, 03, 05, 07) also have detective enforcement via Rego policies in the CI gate. The other three (GAP-04, 06, 08) are Terraform-only because the pattern is repetitive (versioning) or the closure is intrinsic to a single resource attribute (DLQ, throttling) where a future regression would be visible in PR diff review.

## Design decisions worth defending

### Single CMK with separated admin and use permissions

A workload this size has at most a handful of distinct data classifications. PHI submissions in S3 and PHI records in DynamoDB share the same classification, so they share one KMS CMK (`alias/acme-health-phi`). Two CMKs would double the rotation surface, the key-policy surface, and the audit reconciliation work without adding security.

The defense is the *key policy*, not the key count. The CMK policy has five statements that separate three distinct roles:

1. **Root account**: full administrative access. This is the break-glass identity.
2. **CI role (`cgep-capstone-gate`)**: KMS admin actions (CreateKey, PutKeyPolicy, ScheduleKeyDeletion) but explicitly *not* `Encrypt`, `Decrypt`, or `GenerateDataKey*`. The CI role manages the key lifecycle; it cannot read PHI.
3. **Lambda role**: `Decrypt` and `GenerateDataKey*` only, scoped by `aws:SourceAccount` to prevent confused-deputy attacks. The Lambda role reads and writes PHI but cannot rotate the key, change the policy, or delete the key.

This means an attacker who compromises the CI role cannot read existing PHI; an attacker who compromises the Lambda cannot destroy the key or weaken its policy. The single-key choice forces these separations to be policy-based rather than identity-based, which is the more robust pattern.

### Gateway VPC endpoints instead of NAT Gateway

Lambda in private subnets needs a way to reach DynamoDB and S3. Two patterns: NAT Gateway (Lambda's traffic egresses via NAT to the public AWS endpoints) or gateway VPC endpoints (S3 and DynamoDB are reachable directly from the VPC via private routes).

I chose gateway endpoints. Reasoning:

- **Cost**: NAT Gateway is ~$32/month plus per-GB data charges. Gateway endpoints for S3 and DynamoDB are free.
- **Attack surface**: NAT Gateway exposes Lambda to the public internet (with egress-only, but still public-routable). Gateway endpoints keep all data plane traffic on the AWS backbone.
- **Audit**: VPC endpoint policies let you scope which buckets the Lambda can reach over the endpoint. NAT Gateway has no equivalent — Lambda's traffic to S3 is opaque to the VPC, only loggable at the application or CloudTrail layer.

The trade-off: gateway endpoints exist only for S3 and DynamoDB. Other AWS services (Secrets Manager, KMS, etc.) require interface endpoints, which cost ~$7.20/month each. For a workload that only needs S3, DynamoDB, and KMS, gateway endpoints + the Lambda's automatic KMS access via its execution role is the cheapest and most defensible pattern.

A real production deployment that adds Secrets Manager, SES, or any third-party API would need to revisit this: add interface endpoints for the AWS services and either a NAT Gateway or a managed proxy for the external APIs.

### S3 PutObject scoped to the uploads/ prefix, not the bucket root

The Lambda's IAM policy grants `s3:PutObject` on `arn:aws:s3:::acme-health-intake-uploads-<suffix>/uploads/*`, not on `.../*`. The `uploads/` prefix is a deliberate isolation boundary.

The use case is one-directional: the Lambda writes new submissions into `uploads/`. It never reads them back (that would be a downstream batch job or an analyst tool). It never deletes them. It never overwrites them (versioning is on, but writes go to new keys with submission IDs in their names).

Scoping to the prefix means a compromised Lambda cannot overwrite or pollute future data lake outputs from the same bucket, cannot place arbitrary objects at the bucket root that downstream tooling might pick up, and cannot access anything written to other prefixes. The same bucket can later host `exports/` or `reports/` prefixes with their own IAM policies for downstream consumers without re-architecting.

This is the AC-6 principle (least privilege) applied at the resource-path level, not just the resource level. A reviewer's CI sees `s3:PutObject on bucket-arn/uploads/*` and immediately understands what the workload is allowed to do.

### Reserved Lambda concurrency: a control that depends on environment

Reserved concurrency is the SI-11 (system monitoring / capacity reservation) control for Lambda: you reserve N concurrent executions for this function so a noisy neighbor in the same account can't starve it. In production, you'd reserve a meaningful number (say, 10 for a workload expecting steady but bounded traffic) leaving the remaining 990 in the unreserved pool.

In the AWS sandbox account used for this capstone, the total per-account concurrency budget is 10. There's no room to reserve any portion without making the function unable to serve traffic during cold starts. Setting `reserved_concurrent_executions = 10` in this environment caused apply to fail with `AccountConcurrencyLimitExceeded`.

The closure I implemented: `reserved_concurrent_executions = -1` (use the unreserved pool, which is the Terraform sentinel for "no reservation set"). The Rego policy and OSCAL document both treat the *presence of intent* — the `dead_letter_config`, `tracing_config`, and the concurrency setting itself — as the control closure, not the specific number. The number is environment-dependent. The pattern is: in a sandbox with budget 10, leave concurrency unreserved; in a production account with budget 1000, reserve 10 and document why.

This is a useful lesson about how compliance controls describe *intent* rather than specific configuration values. SI-11 is satisfied by demonstrating the workload reserves capacity; the specific number is a deployment decision a production runbook would document.

### KMS access for the Lambda role on encrypted DynamoDB

The first integrated apply failed on the first Lambda invocation with `KMSAccessDeniedException`. The initial design assumed DynamoDB's customer-managed encryption was transparent to the caller: S3 SSE behaves this way (the Lambda's IAM policy needs `s3:PutObject` on the bucket, but no `kms:*` permissions for `arn:aws:kms:.../key/...`). DynamoDB does not.

When a Lambda writes to a DynamoDB table with a customer-managed CMK, DynamoDB calls `kms:Decrypt` and `kms:GenerateDataKey` on the caller's identity — the Lambda's execution role — not on a DynamoDB service principal. The Lambda role needs:

1. KMS perms in its own role policy (`kms:Decrypt`, `kms:GenerateDataKey*` on the PHI CMK)
2. A grant in the CMK's key policy that allows the Lambda role's ARN to call those actions

Both ends. Adding the role-policy perms without the key-policy grants fails with `AccessDeniedException`. Adding the key-policy grants without the role-policy perms gives the same error (the role-policy is checked first).

I added a single statement to the CMK key policy with a `Principal` of `acme-health-intake-lambda-<suffix>` (the Lambda role naming pattern with the random_id suffix), allowing the four required KMS actions. This is the dual-control pattern: the role policy says "this identity may use KMS"; the key policy says "this key trusts this identity." Either alone is insufficient.

The lesson: when AWS services hold encrypted data, the service's encryption integration uses the *caller's* credentials, not the service's. The same applies to ECS task roles on encrypted EBS, Glue jobs on encrypted Glue catalog entries, etc. This is a recurring pattern worth knowing.

### Three deny rules per policy, not one

Each Rego policy in `policies/` emits two or three distinct `deny` rules rather than a single catch-all. For GAP-01 (S3 SSE-KMS), the three are:

1. "bucket exists but no SSE configuration anywhere in the plan"
2. "SSE configuration exists but uses `AES256` or another non-KMS algorithm"
3. "SSE algorithm is `aws:kms` but `kms_master_key_id` is missing"

A single catch-all could collapse these into "GAP-01 not satisfied" and be technically correct. The three-rule pattern costs ~15 extra lines of Rego per policy and pays for itself the first time someone tries to debug a CI failure. The Conftest output for a real PR is now `GAP-01: bucket uploads has no kms_master_key_id specified; defaults to AWS-managed key` rather than `GAP-01: failed`. The PR author knows exactly which line to fix.

The same pattern in GAP-07 (IAM least-privilege) distinguishes "Action is the full wildcard `*`" from "Action is service-wide like `dynamodb:*`" from "Action is in an array containing a wildcard among specific actions." A reviewer reading the policy results immediately understands the specific failure mode rather than running `terraform plan` locally to figure it out.

The trade-off: more lines of Rego per policy, slightly more fixture work in tests. But each rule reads as a coherent compliance assertion ("CMK must be specified when sse_algorithm is aws:kms"), which is the right level of abstraction for an auditor to read.

### Cross-policy fixture validity in shared Rego packages

All 5 Rego policies live in `package main`, which is the Conftest convention. This means every test fixture is evaluated against every policy's deny rules. A passing fixture for GAP-01 (S3 with proper SSE) must *also* satisfy GAP-03 (TLS-only bucket policy) and any other policy that scans `aws_s3_bucket` resources, because those policies also run on the fixture.

This surfaced as a test failure when GAP-03 was added: the GAP-01 passing fixture (which had only the bucket and the SSE configuration) failed because it had no bucket policy, triggering the GAP-03 deny. The fix was to extend the fixture to include a TLS-enforcing bucket policy alongside the SSE config. Now the fixture is *globally* valid — it satisfies every policy that could ever fire on it — rather than only locally valid against the policy under test.

For five policies this is manageable. The fixture set grows linearly with the policy count when fixtures are shared. At ten or more policies, the right pattern is a shared base fixture (a known-good infrastructure plan) with per-policy mutations that introduce specific failures. The capstone scope didn't justify that refactor; documenting the pattern is enough for a reviewer to see it was considered.

The deeper lesson: Rego policy bundles are not independent. Their interaction at the package level is part of the policy design, not an afterthought. A 50-policy compliance suite (the realistic scale) needs deliberate fixture architecture.

## What Day 6's first apply taught me

Four hardening surprises surfaced in the first integrated apply. Each was 5 minutes to fix in code, but none would have been caught by terraform validate or static review:

1. **Lambda role needs AWSLambdaVPCAccessExecutionRole** to manage its own ENIs when in a VPC. Lambda function creation fails closed without it.
2. **Sandbox account concurrency budget** rejected reserved_concurrent_executions = 10. Set to -1 (unreserved pool) with documented environment-scaling rationale.
3. **VPC gateway endpoints don't auto-associate** with the main route table. Without explicit `route_table_ids`, they exist as resources but route nothing. Lambda timed out at 10s trying to reach DynamoDB.
4. **DynamoDB calls kms:Decrypt as the caller**, not as a service. The original design assumed SSE was transparent (it is, for service-initiated reads). For client-initiated writes to an encrypted table, the calling identity needs KMS perms on the key.

Each is the kind of thing that distinguishes "I followed a tutorial" from "I deployed real infrastructure."

## What Day 9's first pipeline run taught me

The Rego policies and pipeline survived first contact with real infrastructure. Four issues surfaced, each in a different category, each fixed:

**1. Plan-time unresolved references break naive Rego policies.**

Terraform records cross-resource references (like `kms_master_key_id = aws_kms_key.phi.arn`) as `change.after_unknown` rather than `change.after` until apply resolves them. Our policies originally checked only `change.after`, so they incorrectly fired "no CMK specified" on every encrypted resource. Fixed by also accepting `change.after_unknown[<field>] == true` as valid intent. Real lesson: Rego policies for Terraform must understand the plan JSON's known/unknown distinction.

**2. Test fixtures lie about real plan shape.**

Our 21 unit tests passed because the fixtures used resolved references throughout. The policies passed against the fixtures and failed against real plans. Lesson: fixture testing is necessary but not sufficient. The first end-to-end run against a real plan is the actual validation.

**3. Missing remote state caused duplicate parallel stacks.**

Each pipeline run started with no Terraform state on the GitHub runner (default local state). Two runs in succession produced two distinct random_id suffixes, hence two parallel deployments of every resource. AWS charged for both until manually cleaned up. The signed evidence bundle landed in only one of the two vaults. Lesson: production pipelines need a remote state backend (S3 + DynamoDB lock table) before apply runs in CI. Documented as future work; not implemented for this submission to keep scope finite.

**4. Sign-and-upload job needed Terraform output passed as a job dependency.**

The sign-and-upload job started on a fresh GitHub runner with no Terraform binary and no state to read `terraform output -raw vault_name`. Refactored to pass the vault name from the apply job as a GitHub Actions job output via `outputs` and `needs.apply.outputs.vault_name`. Lesson: GitHub Actions jobs are independent runners; cross-job data passes through `outputs`, not through filesystem state.

## What I would do differently in production

The capstone scope ran 30 days. Several decisions made sense for that budget but would change in a real deployment.

**Remote state backend with locking**. The pipeline uses GitHub Actions runners with local Terraform state, which means each `terraform apply` starts from a blank state file. The Day 9 duplicate-stack incident is a direct consequence. Production needs an S3 backend with DynamoDB lock table (or equivalent). The S3 bucket holding state would itself be CMK-encrypted, versioned, and have its own bucket policy denying deletion. The DynamoDB lock table prevents two concurrent applies from corrupting state.

**HIPAA compliance overlay**. Most of the technical controls implemented here would also satisfy HIPAA Security Rule requirements (encryption, access control, audit logging). A real production deployment would add: signed Business Associate Agreements with AWS, breach notification procedures, workforce training records, periodic risk assessments, and a designated Security Officer. None of these are technical artifacts the engineering team produces alone, but their absence is what makes this a SOC 2 capstone rather than a HIPAA one.

**PHI redaction and tokenization**. The Lambda writes raw PHI to DynamoDB. A production system would tokenize identifiers (split SSN/MRN into a separate secrets-management store, keep tokens in DynamoDB) and would consider field-level encryption for sensitive attributes beyond the table-level KMS. This is closer to a privacy-engineering problem than a compliance-controls problem.

**Reserved concurrency at production scale**. The sandbox-budget workaround (set to -1) would become `reserved_concurrent_executions = 10` or higher in an account with adequate budget. The OSCAL document already treats the *presence* of the control as the closure; the production value would be a runbook decision based on expected traffic and acceptable cold-start latency.

**Interface VPC endpoints for KMS, Secrets Manager, etc.** Gateway endpoints cover S3 and DynamoDB. If the workload grows to need Secrets Manager, KMS API calls from non-data-plane code paths, or any third-party API, the VPC would need either interface endpoints (paid, per-AZ) or a managed egress proxy. The current Lambda role uses KMS only via DynamoDB/S3 service integration, so no direct KMS API access is required.

**Real WAF in front of API Gateway**. GAP-08's closure is logging and throttling. A production deployment would add an AWS WAF (or equivalent) in front of the API Gateway with managed rule sets for common attack patterns and rate-based rules for IPs exhibiting bot behavior. The capstone deferred this as out-of-scope; in production, it's standard hygiene for any public-facing API.

**Centralized log aggregation**. CloudTrail and CloudWatch logs are stored in account-local buckets and log groups. A production deployment would forward both to a SIEM (Datadog, Splunk, Wazuh) for cross-source correlation and alerting. The current 30-day retention on the CloudTrail bucket is too short for any meaningful incident investigation; production would extend to 365+ days, ideally with a Glacier tier for cost.

## Submission verification (the chain of custody, end-to-end)

The signed bundle at `s3://cgep-capstone-evidence-vault-65cc2469/evidence/evidence-3-20260617T234013Z-6d98ee09.tar.gz` is the auditor's artifact. To reproduce:

    aws s3 cp s3://cgep-capstone-evidence-vault-65cc2469/evidence/evidence-3-20260617T234013Z-6d98ee09.tar.gz .
    aws s3 cp s3://cgep-capstone-evidence-vault-65cc2469/evidence/evidence-3-20260617T234013Z-6d98ee09.tar.gz.sha256 .
    aws s3 cp s3://cgep-capstone-evidence-vault-65cc2469/evidence/evidence-3-20260617T234013Z-6d98ee09.tar.gz.sig.bundle .
    sha256sum -c evidence-3-20260617T234013Z-6d98ee09.tar.gz.sha256
    cosign verify-blob \
      --bundle evidence-3-20260617T234013Z-6d98ee09.tar.gz.sig.bundle \
      --certificate-identity "https://github.com/AE-Digital5/cgep-app-starter/.github/workflows/grc-gate.yml@refs/heads/main" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      evidence-3-20260617T234013Z-6d98ee09.tar.gz

Both commands return success when run today. The bundle contents (plan.json, policy-results.json showing 12 passes, apply.log, manifest.json) bind the deployment to commit `6d98ee0954934a518ff3493d79f8648c64363146` via the signed manifest. A reviewer can independently verify the Rekor transparency log entry to confirm the signature existed at the recorded timestamp, no AWS account access required.

## What's not in scope

Scope was bounded so the work could finish in 30 days. Things explicitly out:

- **HIPAA controls beyond the technical overlap with SOC 2** (BAAs, breach notification, workforce training, designated Security Officer).
- **Remote Terraform state backend** (S3 + DynamoDB lock). Documented as the primary production work item; not implemented for the capstone to keep submission timeline finite.
- **WAF in front of API Gateway**. The API is rate-limited and access-logged; managed rule sets are deferred.
- **PHI redaction or tokenization** of submission fields. Raw PHI hits DynamoDB; production would tokenize identifiers and consider field-level encryption.
- **Multi-account architecture** (organization with separated dev/staging/prod, centralized logging account, isolated PHI account). The capstone is a single sandbox account.
- **Quarterly Conftest policy review and updates**. The 5 policies cover the 5 most-critical gaps; a real compliance program would expand to ~30 policies and rotate them as services and gaps evolve.
- **Disaster recovery / cross-region replication**. The evidence vault is single-region. Production would replicate evidence to a second region with cross-region replication.

Future capstone work would prioritize remote state, multi-region, and HIPAA overlay in that order.

**Note on long-term decryption**: when the workload was destroyed after capstone wrap, the CMK that originally encrypted the evidence vault was scheduled for deletion. AWS treats KMS keys in PendingDeletion as unusable, breaking decryption of any CMK-encrypted object. To allow long-term reviewer access independent of the CMK lifecycle, the three evidence files were re-encrypted in place with bucket-managed AES256 and given a 1-year Object Lock retention. The bundle content is unchanged, so the SHA-256 digest and the Cosign signature both still verify. This is a design lesson: chain-of-custody artifacts intended to outlive the original infrastructure should not depend on resources scheduled for deletion alongside the workload.