######################################################################
# cloudtrail.tf
#
# Multi-region CloudTrail with log-file validation, writing to a
# dedicated S3 bucket encrypted with the PHI CMK.
#
# Closes the SOC 2 audit-trail story:
#   - CC7.1 (Monitoring): every account-level API call is recorded
#   - CC4.1 (Monitoring controls): log-file validation lets an auditor
#     detect tampering with the trail itself
#   - A1.2 (Availability / Recovery): 30-day retention with lifecycle
#     deletion, gives ops time to investigate before logs age out
#
# Production scale: 365-day retention, optionally a second trail
# writing to a separate evidence-archive account for separation of
# duties. Out of scope for the 30-day capstone.
######################################################################

# Dedicated S3 bucket for CloudTrail logs. Encrypted with our PHI CMK
# even though CloudTrail itself doesn't write PHI; the trail captures
# API calls that could include PHI in request parameters, and a
# uniform encryption story is easier to defend.
resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "${local.name_prefix}-cloudtrail-${local.suffix}"
  force_destroy = true # Lifecycle-aged logs only; safe to force destroy at lab scope.
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle: delete logs after 30 days. Capstone scope; production
# would retain longer (365+) and tier to S3 Glacier Deep Archive.
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "expire-after-30-days"
    status = "Enabled"

    filter {} # Apply to all objects.

    expiration {
      days = 30
    }
  }
}

# Bucket policy granting the CloudTrail service permission to write.
# Scoped via aws:SourceArn to ONLY our trail; without this condition,
# any CloudTrail in any AWS account could in theory write here.
data "aws_iam_policy_document" "cloudtrail_bucket" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-trail-${local.suffix}"]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-trail-${local.suffix}"]
    }
  }
  
  statement {
    sid    = "DenyUnencryptedTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.cloudtrail.arn,
      "${aws_s3_bucket.cloudtrail.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket.json
}

resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-trail-${local.suffix}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true # SOC 2 CC4.1: lets auditor detect log tampering.

  # depends_on ensures the bucket policy attaches BEFORE the trail tries
  # to write its first event. Without this, AWS often returns
  # InsufficientS3BucketPolicy on the first apply.
  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

output "cloudtrail_name" {
  value       = aws_cloudtrail.main.name
  description = "Name of the multi-region CloudTrail. Verify with aws cloudtrail get-trail-status."
}

output "cloudtrail_bucket" {
  value       = aws_s3_bucket.cloudtrail.id
  description = "S3 bucket holding CloudTrail logs."
}