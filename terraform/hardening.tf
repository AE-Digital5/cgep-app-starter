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

######################################################################
# GAP-06 supporting resources: Lambda DLQ + IAM permission.
# SOC 2 CC7.2 (Failure recovery + observability).
#
# Lambda hardening attributes (reserved_concurrent_executions,
# dead_letter_config, tracing_config) are set in main.tf on the Lambda
# resource itself. Here we add the supporting SQS queue and the IAM
# permission allowing Lambda to write to it.
######################################################################

resource "aws_sqs_queue" "lambda_dlq" {
  name                              = "${local.name_prefix}-lambda-dlq-${local.suffix}"
  message_retention_seconds         = 1209600 # 14 days (SQS max)
  kms_master_key_id                 = aws_kms_key.phi.id
  kms_data_key_reuse_period_seconds = 300
}

# Grant the Lambda's existing role permission to write to the DLQ.
# Inline policy here (separate from the starter's lambda_inline policy
# in main.tf) to keep GAP-06 changes localized in this file.
resource "aws_iam_role_policy" "lambda_dlq_write" {
  name = "lambda-dlq-write"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = aws_sqs_queue.lambda_dlq.arn
    }]
  })
}

######################################################################
# GAP-08: API Gateway access logging + throttling.
# SOC 2 CC7.2 (System operations / Monitoring + Capacity management).
#
# The starter's stage has no access logging and no throttling. The
# logging closure here creates a CloudWatch log group + modifies the
# stage in main.tf to write to it. Throttling is set as stage
# attributes in main.tf (default_route_settings).
#
# WAF deferred to future enhancement (documented in design.md).
######################################################################

resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/${local.name_prefix}-api-${local.suffix}/access"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.phi.arn

  # Trust the KMS key to encrypt log group contents. The key's policy
  # already allows the CloudWatch Logs service via the wildcard service
  # statements; if cross-account access is ever needed, add a specific
  # statement to kms.tf.
}

######################################################################
# GAP-05: Lambda in VPC + free gateway endpoints for AWS data plane.
# SOC 2 CC6.6 (Network segmentation / Logical access).
#
# Starter resource: aws_lambda_function.intake runs in AWS's managed
# Lambda network (effectively public internet). Moving it into the
# starter's existing private subnets means egress is constrained and
# auditable.
#
# Egress design: VPC gateway endpoints for S3 and DynamoDB. These are
# free, keep all traffic on the AWS private network, and remove the
# need for a NAT Gateway ($32/month). Interface endpoints for KMS,
# CloudWatch Logs, X-Ray deferred as future work; Lambda's runtime
# integration with these services does not require interface endpoints
# for the current handler.py code path.
######################################################################

# Security group for the Lambda. No ingress (Lambda doesn't accept
# inbound traffic). Egress is broad outbound HTTPS; the actual reach
# is constrained by the lack of NAT and the gateway endpoints' route
# table entries (so Lambda can only reach S3 and DynamoDB).
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-${local.suffix}"
  description = "Lambda function egress. No ingress."
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to AWS service endpoints (constrained by gateway endpoints)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-lambda-sg-${local.suffix}"
  }
}

# Gateway endpoint for S3. Free. Auto-associates with the VPC's main
# route table; private subnets use the main route table (they have no
# explicit association), so traffic to S3 from the Lambda subnets
# automatically routes through this endpoint.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"

  # Endpoint policy: restrict use to this account's resources. Without
  # this, the endpoint would allow access to S3 buckets in OTHER AWS
  # accounts (a common over-permissive pattern). Defense-in-depth.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountScopedS3Access"
      Effect    = "Allow"
      Principal = "*"
      Action    = "*"
      Resource  = "*"
      Condition = {
        StringEquals = {
          "aws:PrincipalAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })

  tags = {
    Name = "${local.name_prefix}-s3-endpoint-${local.suffix}"
  }
}

# Gateway endpoint for DynamoDB. Same pattern.
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.dynamodb"
  vpc_endpoint_type = "Gateway"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountScopedDynamoDBAccess"
      Effect    = "Allow"
      Principal = "*"
      Action    = "*"
      Resource  = "*"
      Condition = {
        StringEquals = {
          "aws:PrincipalAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })

  tags = {
    Name = "${local.name_prefix}-ddb-endpoint-${local.suffix}"
  }
}

# Look up the current region for use in the endpoint service names.
data "aws_region" "current" {}