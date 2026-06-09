# oidc/main.tf
# GitHub Actions OIDC trust for the capstone repo.
# Reuses the existing OIDC provider in the account (created by Lab 4.3).
# Role permissions: PowerUserAccess (everything except IAM mutations)
# + narrow inline policy for the IAM actions the workload genuinely needs.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" { region = "us-east-1" }

variable "github_org" {
  type        = string
  description = "GitHub org or user that owns the capstone repo."
}

variable "github_repo" {
  type        = string
  description = "GitHub repository name. Trust is scoped to repo:<org>/<repo>:*"
}

data "aws_caller_identity" "current" {}

# Reference the existing OIDC provider (created by Lab 4.3). Don't try to create another.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_role" "capstone_gate" {
  name        = "cgep-capstone-gate"
  description = "Role assumed by GitHub Actions to plan and apply the capstone workload."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
        }
      }
    }]
  })

  tags = {
    Project   = "cgep-capstone"
    ManagedBy = "terraform"
  }
}

# PowerUserAccess: everything in AWS except IAM and Organizations.
# We add narrow IAM perms inline below.
resource "aws_iam_role_policy_attachment" "power_user" {
  role       = aws_iam_role.capstone_gate.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# Narrow IAM permissions: just the actions Terraform needs to manage the workload's
# Lambda execution role. Note PassRole is scoped to roles whose names start with
# "acme-health-intake-" — this prevents the CI from being used to pass arbitrary
# roles to arbitrary services (the classic IAM privilege-escalation vector).
data "aws_iam_policy_document" "iam_write" {
  statement {
    sid    = "ManageWorkloadIamRoles"
    effect = "Allow"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:UpdateRole",
      "iam:UpdateRoleDescription",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:PutRolePolicy",
      "iam:GetRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:ListRolePolicies",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:ListRoleTags",
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/acme-health-intake-*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/cgep-capstone-*",
    ]
  }

  statement {
    sid    = "PassWorkloadRolesToServices"
    effect = "Allow"
    actions = ["iam:PassRole"]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/acme-health-intake-*",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = [
        "lambda.amazonaws.com",
        "apigateway.amazonaws.com",
        "cloudtrail.amazonaws.com",
      ]
    }
  }

  # Allow reading the OIDC provider we reference via data source.
  statement {
    sid    = "ReadOIDCProvider"
    effect = "Allow"
    actions = [
      "iam:GetOpenIDConnectProvider",
      "iam:ListOpenIDConnectProviders",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "iam_write" {
  name   = "iam-write-narrow"
  role   = aws_iam_role.capstone_gate.name
  policy = data.aws_iam_policy_document.iam_write.json
}

output "role_arn" {
  value       = aws_iam_role.capstone_gate.arn
  description = "ARN of the GitHub Actions role. Paste into the AWS_ROLE_ARN repo variable."
}

output "role_name" {
  value       = aws_iam_role.capstone_gate.name
  description = "Name of the role, useful for inline-policy modifications."
}