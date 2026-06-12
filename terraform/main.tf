######################################################################
# Acme Health — Patient Intake API (CGE-P Capstone Starter)
#
# This is the workload your capstone repo wraps with GRC controls.
# It is INTENTIONALLY non-compliant. See GAPS.md for the named flaws
# your Rego policies + Terraform overrides are expected to remediate.
######################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "acme-health-intake"
      ManagedBy = "terraform"
      Workload  = "patient-intake-api"
      DataClass = "phi"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "acme-health-intake"
  suffix      = random_id.suffix.hex
}

######################################################################
# Networking — VPC the learner is expected to put the Lambda inside.
# Two public + two private subnets across two AZs.
######################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.${count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${local.name_prefix}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.42.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "${local.name_prefix}-private-${count.index}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

######################################################################
# DynamoDB — submissions table.
# GAP-02: encryption uses AWS-owned default, not a CMK you control.
######################################################################

resource "aws_dynamodb_table" "intake" {
  name         = "${local.name_prefix}-submissions-${local.suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  # GAP-02 closure: customer-managed KMS key for SOC 2 CC6.1 (Encryption at rest).
  # Reference to aws_kms_key.phi defined in kms.tf.
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.phi.arn
  }
}

######################################################################
# S3 — uploads bucket.
# GAP-01: relies on AWS-managed SSE-S3 (default since 2023) instead of
#         SSE-KMS with a customer CMK. PHI keys are not under customer
#         custody.
# GAP-03: no bucket policy denying non-TLS requests
#         (aws:SecureTransport).
# GAP-04: no versioning. PHI overwrites are unrecoverable.
#
# Note: AWS now defaults new buckets to SSE-S3 + full public access block.
# The "gaps" here are real residual gaps once those defaults are in place.
######################################################################

resource "aws_s3_bucket" "uploads" {
  bucket = "${local.name_prefix}-uploads-${local.suffix}"
}

# (Intentionally omitted: SSE-KMS encryption with a customer CMK,
#  bucket policy enforcing aws:SecureTransport, versioning, lifecycle.
#  These are the gaps the learner closes.)

######################################################################
# Lambda — the intake handler.
# GAP-05: not deployed inside the VPC.
# GAP-06: no reserved concurrency, no DLQ, no X-Ray.
# GAP-07: IAM role has dynamodb:* and s3:* on the resources (over-broad).
######################################################################

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda/handler.zip"
}

resource "aws_iam_role" "lambda" {
  name = "${local.name_prefix}-lambda-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# GAP-07: deliberately broad permissions on the workload data stores.
resource "aws_iam_role_policy" "lambda_inline" {
  name = "intake-data-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "dynamodb:*"
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = ["${aws_s3_bucket.uploads.arn}", "${aws_s3_bucket.uploads.arn}/*"]
      }
    ]
  })
}

resource "aws_lambda_function" "intake" {
  function_name    = "${local.name_prefix}-handler-${local.suffix}"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  timeout          = 10

  environment {
    variables = {
      INTAKE_TABLE  = aws_dynamodb_table.intake.name
      UPLOAD_BUCKET = aws_s3_bucket.uploads.id
    }
  }

  # GAP-06 closure: reserved concurrency caps blast radius. SOC 2 CC7.2
  # (Capacity / System operations). Pre-GAP this was unlimited, meaning
  # a runaway invocation could exhaust the account-level Lambda budget.
  # 10 is generous for a single intake API and leaves >900 for other
  # workloads.
  reserved_concurrent_executions = 10

  # GAP-06 closure: dead-letter queue captures failed invocations.
  # SOC 2 CC7.2 (Failure recovery). Without this, after Lambda's
  # built-in retries (2x for async, 0 for sync) the failed event is
  # silently dropped. DLQ only catches async invocations; this API is
  # sync (API Gateway), so DLQ here is defense-in-depth for future async
  # use (e.g., S3 event trigger).
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  # GAP-06 closure: X-Ray Active tracing. SOC 2 CC7.2 (Observability).
  # Active traces every invocation; PassThrough only traces when the
  # X-Ray header is set upstream. For audit completeness on a PHI
  # workload, Active is the right choice.
  tracing_config {
    mode = "Active"
  }

  # GAP-05 closure: Lambda in VPC. SOC 2 CC6.6 (Network segmentation).
  # References starter's private subnets and the hardened SG in
  # hardening.tf. Egress to S3 + DynamoDB via free gateway endpoints
  # (also in hardening.tf); no NAT, no internet.
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }
}

######################################################################
# API Gateway — HTTP API in front of the Lambda.
# GAP-08: no access logging, no throttling, no WAF.
######################################################################

resource "aws_apigatewayv2_api" "intake" {
  name          = "${local.name_prefix}-api-${local.suffix}"
  protocol_type = "HTTP"
  description   = "HTTP API for intake service"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.intake.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.intake.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "intake" {
  api_id    = aws_apigatewayv2_api.intake.id
  route_key = "POST /intake"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.intake.id
  name        = "$default"
  auto_deploy = true

  # GAP-08 closure: access logging. SOC 2 CC7.2 (Monitoring).
  # Logs every request (method, path, status, latency, source IP, etc.)
  # to a KMS-encrypted CloudWatch log group. Format is JSON for parser
  # compatibility with Athena / log aggregators.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format = jsonencode({
      requestId               = "$context.requestId"
      requestTime             = "$context.requestTime"
      sourceIp                = "$context.identity.sourceIp"
      userAgent               = "$context.identity.userAgent"
      httpMethod              = "$context.httpMethod"
      routeKey                = "$context.routeKey"
      status                  = "$context.status"
      protocol                = "$context.protocol"
      responseLength          = "$context.responseLength"
      integrationErrorMessage = "$context.integrationErrorMessage"
    })
  }

  # GAP-08 closure: throttling. SOC 2 CC7.2 (Capacity).
  # 100 req/s rate, 50 req/s burst. Reasonable for a single-tenant
  # intake API; would scale up for production traffic patterns.
  default_route_settings {
    throttling_rate_limit  = 100
    throttling_burst_limit = 50
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.intake.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.intake.execution_arn}/*/*"
}
