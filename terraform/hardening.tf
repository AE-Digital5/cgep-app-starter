######################################################################
# hardening.tf
#
# GAP-closing overrides on starter resources. Each block has:
#   - The gap ID from GAPS.md
#   - The SOC 2 Trust Services Criterion it closes
#   - A pointer to the starter resource being hardened
#
# Resources here ADD compliance behavior to starter resources without
# modifying the starter's resource definitions, except where the
# starter's resource type requires inline attributes (GAP-02 in main.tf,
# GAP-05 future). Each modification is surgical and documented.
######################################################################

######################################################################
# GAP-01: S3 uploads bucket encryption with customer-managed KMS key.
# SOC 2 CC6.1 (Logical access controls / Encryption).
#
# Starter resource: aws_s3_bucket.uploads (in main.tf, no encryption set;
# AWS default is SSE-S3 with AWS-managed key).
#
# Hardening: explicit SSE-KMS configuration pointing at our PHI CMK.
# Bucket-key enabled to reduce per-request KMS API costs (~99% reduction
# for S3 traffic; recommended for any high-volume bucket).
######################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

######################################################################
# GAP-03: TLS-only access to the S3 uploads bucket.
# SOC 2 CC6.7 (System communications / Encryption in transit).
#
# Starter resource: aws_s3_bucket.uploads has no bucket policy. The
# default access pattern accepts both HTTP and HTTPS. PHI uploaded over
# plain HTTP is a real exposure in a development VPC.
#
# Hardening: bucket policy denying any request where aws:SecureTransport
# is false. This is the canonical AWS pattern for HIPAA/SOC 2 TLS-only.
######################################################################

data "aws_iam_policy_document" "uploads_tls_only" {
  statement {
    sid    = "DenyUnencryptedTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.uploads.arn,
      "${aws_s3_bucket.uploads.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = aws_s3_bucket.uploads.id
  policy = data.aws_iam_policy_document.uploads_tls_only.json
}

######################################################################
# GAP-04: Versioning on the S3 uploads bucket.
# SOC 2 A1.2 (Availability / Recovery capability).
#
# Starter resource: aws_s3_bucket.uploads (no versioning, so accidental
# or malicious overwrites are unrecoverable).
#
# Hardening: enable versioning. Combined with the TLS-only policy
# (GAP-03), SSE-KMS (GAP-01), and tight IAM (GAP-07, pending), the
# uploads bucket becomes recoverable-by-default for PHI ingestion.
#
# Note: this also enables future Object Lock if the team decides PHI
# uploads themselves should be immutable; Object Lock requires versioning.
######################################################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}