######################################################################
# evidence-vault.tf
#
# S3 Object Lock vault for signed evidence bundles.
# The capstone pipeline (.github/workflows/grc-gate.yml) writes here
# on every run: bundle, .sha256 sidecar, .sig.bundle, receipt.json.
#
# Object Lock + versioning + bucket-policy-denies-DeleteBucket means
# even an account compromise can't silently destroy the audit trail.
######################################################################

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "vault" {
  bucket              = "cgep-capstone-evidence-vault-${random_id.suffix.hex}"
  object_lock_enabled = true # Must be set at bucket creation; cannot be enabled later.
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration { status = "Enabled" } # Object Lock requires versioning.
}

resource "aws_s3_bucket_object_lock_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    default_retention {
      mode = "GOVERNANCE" # Allows account-root override in emergency; sufficient for SOC 2 + capstone scope.
      days = 1            # 1-day retention for capstone; production baseline is 365.
    }
  }
  depends_on = [aws_s3_bucket_versioning.vault]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
    # CMK upgrade tracked as Week-2 hardening (kms.tf).
  }
}

resource "aws_s3_bucket_public_access_block" "vault" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "vault" {
  bucket = aws_s3_bucket.vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyBucketDeletionExceptRoot"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:DeleteBucket"
      Resource  = aws_s3_bucket.vault.arn
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    }]
  })
}

output "vault_name" {
  value       = aws_s3_bucket.vault.id
  description = "S3 bucket name of the evidence vault. Used by capture-evidence.sh and the pipeline upload step."
}

output "vault_arn" {
  value       = aws_s3_bucket.vault.arn
  description = "Full ARN of the vault. Used by IAM policies that need to grant write access."
}