# Acme Health Patient Intake API — CGE-P GRC Capstone

> A 30-day GRC engineering capstone targeting **SOC 2 Type II**. This fork takes the deliberately non-compliant `cgep-app-starter` and closes all 8 named compliance gaps with hardened Terraform, detective Rego policy gates, a signed-evidence CI pipeline, and an OSCAL component-definition mapping every closure to a NIST 800-53 Rev 5 control.

**Submission artifact**: the signed evidence bundle at `s3://cgep-capstone-evidence-vault-65cc2469/evidence/evidence-3-20260617T234013Z-6d98ee09.tar.gz`. Reproducible verification is the last section below.

---

## What this is

The upstream `cgep-app-starter` ships a minimal AWS workload (VPC, Lambda, API Gateway, DynamoDB, S3) for handling patient intake submissions. It is **non-compliant by design** — the starter's `GAPS.md` enumerates 8 specific holes a real auditor would call out.

This fork closes all 8 gaps and adds the GRC infrastructure around the workload: detective enforcement, automated evidence collection, and machine-readable assurance.

---

## The four layers

### 1. Hardened workload Terraform (`terraform/`)

Closes all 8 named gaps from `GAPS.md`:

- KMS CMK (`alias/acme-health-phi`) with separated admin (CI role) and use (Lambda role) permissions
- SSE-KMS on uploads, evidence vault, and CloudTrail buckets
- DynamoDB SSE-KMS using the same CMK
- TLS-only bucket policies on all three buckets
- Lambda in private VPC subnets with S3 + DynamoDB gateway VPC endpoints
- Lambda DLQ (KMS-encrypted SQS) + X-Ray Active tracing + reserved concurrency intent
- Lambda IAM scoped to `dynamodb:PutItem` and `s3:PutObject` on the `uploads/*` prefix only
- API Gateway access logging (KMS-encrypted CloudWatch) + throttling (100/50 rps)
- Multi-region CloudTrail with log file validation

Detail: see `docs/design.md` for the architectural rationale.

### 2. Rego policy gate (`policies/`)

Five OPA Rego policies enforcing the most critical 5 gaps detectively:

| Policy | Gap | SOC 2 | NIST |
|--------|-----|-------|------|
| `sc28_s3_cmk.rego` | GAP-01 | CC6.1 | SC-28 |
| `sc28_ddb_cmk.rego` | GAP-02 | CC6.1 | SC-28 |
| `sc7_tls_only.rego` | GAP-03 | CC6.7 | SC-7, SC-8 |
| `cc66_lambda_vpc.rego` | GAP-05 | CC6.6 | SC-7 |
| `cc63_iam_least_priv.rego` | GAP-07 | CC6.3 | AC-6 |

Unit tests in `policies/tests/`. All 21 tests pass. Conftest runs the policies against `plan.json` in the CI gate.

```bash
opa test policies/ -v
# PASS: 21/21
```

### 3. GitHub Actions CI pipeline (`.github/workflows/grc-gate.yml`)

Plan → policy gate → apply → sign-with-Cosign-keyless → upload-to-evidence-vault.

- Trigger: PRs touching `terraform/`, `policies/`, `oidc/`, or the workflow itself; plus pushes to `main`
- OIDC auth to AWS via the `cgep-capstone-gate` role (defined in `oidc/`)
- Conftest fails the PR if any of the 5 Rego policies deny against the real plan
- Cosign keyless signs the bundle; signature published to Sigstore Rekor for transparency
- Vault is S3 with Object Lock GOVERNANCE retention + a `DenyBucketDeletion` policy

### 4. OSCAL component-definition (`component-definitions/compliant-intake-api/`)

Machine-readable assurance document mapping every gap closure to a NIST 800-53 Rev 5 control with the SOC 2 Trust Services Criterion ID as a `soc2-cc` prop. Validates clean with trestle v4.0.3.

```bash
trestle validate -f component-definitions/compliant-intake-api/component-definition.json
trestle validate -f profiles/soc2-cc-minimum/profile.json
```

---

## Repository layout
├── terraform/                    workload IaC (closes all 8 gaps)

│   ├── main.tf                   VPC, Lambda, API Gateway, DDB

│   ├── kms.tf                    PHI CMK + key policy

│   ├── hardening.tf              SSE, TLS, versioning, IAM

│   ├── cloudtrail.tf             multi-region trail

│   ├── evidence-vault.tf         Object Lock S3 vault

│   └── lambda/handler.py         intake handler

├── policies/                     5 Rego policies + 21 unit tests

├── oidc/                         GitHub OIDC role for CI (separate state)

├── .github/workflows/grc-gate.yml the full CI pipeline

├── component-definitions/         OSCAL component-definition.json

│   └── compliant-intake-api/component-definition.json

├── profiles/                      OSCAL profile selecting the 8 controls

│   └── soc2-cc-minimum/profile.json

├── docs/

│   ├── design.md                 decisions, rationale, architecture

│   └── deploy-gate-receipt.md    Day 1 deploy-gate proof

├── GAPS.md                       the 8 named gaps (from starter, kept verbatim)

├── WRITEUP.md                    the engineering reflection (read this)

└── README.md                     this file

## Read order for graders

1. **`WRITEUP.md`** — the substantive document. Framework choice, gap closures, design decisions, lessons from Day 6 and Day 9, future production work, verification recipe.
2. **`docs/design.md`** — earlier architectural decision record.
3. **`GAPS.md`** — the original 8 gaps the starter ships with.
4. **`component-definitions/compliant-intake-api/component-definition.json`** — OSCAL implementation document.

## Verifying the signed evidence bundle

The bundle is the auditor's artifact. Verify it locally:

```bash
# Download the bundle and its sidecars
aws s3 cp s3://cgep-capstone-evidence-vault-65cc2469/evidence/evidence-3-20260617T234013Z-6d98ee09.tar.gz .
aws s3 cp s3://cgep-capstone-evidence-vault-65cc2469/evidence/evidence-3-20260617T234013Z-6d98ee09.tar.gz.sha256 .
aws s3 cp s3://cgep-capstone-evidence-vault-65cc2469/evidence/evidence-3-20260617T234013Z-6d98ee09.tar.gz.sig.bundle .

# Verify the bundle hasn't been altered
sha256sum -c evidence-3-20260617T234013Z-6d98ee09.tar.gz.sha256
# Expected: OK

# Verify the Cosign signature came from this workflow at this commit
cosign verify-blob \
  --bundle evidence-3-20260617T234013Z-6d98ee09.tar.gz.sig.bundle \
  --certificate-identity "https://github.com/AE-Digital5/cgep-app-starter/.github/workflows/grc-gate.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  evidence-3-20260617T234013Z-6d98ee09.tar.gz
# Expected: Verified OK
```

Bundle contents: `plan.json`, `policy-results.json` (12 successes), `apply.log`, `manifest.json`. The manifest binds the deployment to commit `6d98ee0954934a518ff3493d79f8648c64363146`, run #3, and the CI role ARN.

## Running the pipeline in your own account

The pipeline is built to be portable. To run it in a fresh AWS account, you'd:

1. Fork this repo
2. Apply `oidc/` once locally to create the GitHub OIDC role
3. Set `vars.AWS_ROLE_ARN` in your fork's GitHub Settings → Variables to the new role's ARN
4. Push any change to `terraform/`

**Cost note**: a full pipeline run creates ~45 AWS resources including a KMS CMK (~$1/mo), multi-region CloudTrail, a Lambda + ENIs, a VPC with gateway endpoints, an API Gateway HTTP API, a DynamoDB on-demand table, S3 buckets, an SQS queue, and CloudWatch log groups. Idle cost is approximately $0.50-1.00/day. Destroying via `terraform destroy` returns cost to near zero except the KMS key which goes into 7-day pending deletion.

## Status

The deliverable is the signed evidence bundle in the vault, produced by CI run #3 from commit `6d98ee0` on Tue Jun 17 2026. The workload was destroyed after capstone wrap to control sandbox cost; the vault and bundle remain.

Capstone window: Jun 8 → Jun 30 2026.

---

Forked from [GRCEngClub/cgep-app-starter](https://github.com/GRCEngClub/cgep-app-starter). Capstone work by AE-Digital5.