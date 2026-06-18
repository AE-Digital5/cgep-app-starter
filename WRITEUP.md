# Capstone WRITEUP — Acme Health Patient Intake API

A 30-day GRC engineering exercise: closing 8 named compliance gaps on a deliberately non-compliant Patient Intake API and producing a signed evidence pipeline an auditor can verify without speaking to the engineering team.

Framework: SOC 2 Type II (Trust Services Criteria).

## What's in this submission

- Hardened Terraform closing all 8 gaps from GAPS.md
- Signed evidence pipeline (GitHub Actions + Cosign + Object Lock vault)
- 5 Rego policies enforcing the most critical 5 gaps in PR review
- OSCAL component-definition.json mapping controls to NIST 800-53 Rev 5 with SOC 2 CC IDs as props

## Why SOC 2 (and not HIPAA or CMMC)

[fill in later]

## How the 8 gaps were closed

[a table with all 8, the SOC 2 CC, the closure pattern, and a sentence each]

## Design decisions worth defending

### Single CMK with separated admin and use permissions

[fill in]

### Gateway VPC endpoints instead of NAT Gateway

[fill in]

### S3 PutObject scoped to the uploads/ prefix, not the bucket root

[fill in]

### Reserved Lambda concurrency: a control that depends on environment

[fill in — Day 6 lesson about sandbox account budget]

### KMS access for the Lambda role on encrypted DynamoDB

[fill in — Day 6 lesson about which calls KMS happens on whose credentials]

### Three deny rules per policy, not one

[fill in — Day 7 lesson: better CI output, fewer ambiguous failures. Each Rego policy emits 2-3 separate denies (missing config, wrong value, missing CMK) rather than a single catch-all. Trade-off: more lines of policy, but the CI report tells you exactly what's wrong, not just that something is.]

### Cross-policy fixture validity in shared Rego packages

[fill in — Day 7 lesson: when N policies share `package main`, each passing fixture must satisfy ALL N policies. Discovered when GAP-03 was added and GAP-01/03 cross-failed. Patched fixtures to be globally valid. At 10+ policies this would warrant a shared fixture base pattern.]

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

## What I would do differently in production

[fill in]

## What's not in scope

[from design.md non-goals section]

## How to verify this submission

[steps for the grader to run]