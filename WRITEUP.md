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

## What Day 6's first apply taught me

Four hardening surprises surfaced in the first integrated apply. Each was 5 minutes to fix in code, but none would have been caught by terraform validate or static review:

1. **Lambda role needs AWSLambdaVPCAccessExecutionRole** to manage its own ENIs when in a VPC. Lambda function creation fails closed without it.
2. **Sandbox account concurrency budget** rejected reserved_concurrent_executions = 10. Set to -1 (unreserved pool) with documented environment-scaling rationale.
3. **VPC gateway endpoints don't auto-associate** with the main route table. Without explicit `route_table_ids`, they exist as resources but route nothing. Lambda timed out at 10s trying to reach DynamoDB.
4. **DynamoDB calls kms:Decrypt as the caller**, not as a service. The original design assumed SSE was transparent (it is, for service-initiated reads). For client-initiated writes to an encrypted table, the calling identity needs KMS perms on the key.

Each is the kind of thing that distinguishes "I followed a tutorial" from "I deployed real infrastructure."

## What I would do differently in production

[fill in]

## What's not in scope

[from design.md non-goals section]

## How to verify this submission

[steps for the grader to run]