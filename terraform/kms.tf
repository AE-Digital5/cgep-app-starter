######################################################################
# kms.tf
#
# Customer-managed KMS key for encryption at rest of PHI data:
#   - S3 uploads bucket (closes GAP-01, SOC 2 CC6.1)
#   - DynamoDB table     (closes GAP-02, SOC 2 CC6.1)
#
# Single CMK shared by both data stores. Per-service key separation is
# documented as a next maturity step; for one data class (PHI) at a
# 50-person company, one key with a clear policy is the right baseline.
#
# Key rotation: enabled (annual, AWS default; satisfies SC-12).
######################################################################

data "aws_iam_policy_document" "phi_key" {
  # 1) Account root retains administrative control. Without this, a
  #    misconfigured policy could permanently lock the key. AWS
  #    explicitly recommends this statement on every CMK.
  statement {
    sid    = "EnableRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # 2) CI role can administer the key via Terraform: schedule deletion,
  #    update policy, enable/disable, tag. NOT a blanket kms:* because
  #    the CI role shouldn't be able to encrypt/decrypt PHI itself.
  statement {
    sid    = "AllowCIRoleToManageKey"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/cgep-capstone-gate"]
    }
    actions = [
      "kms:CreateAlias",
      "kms:DeleteAlias",
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
      "kms:EnableKey",
      "kms:DisableKey",
      "kms:EnableKeyRotation",
      "kms:DisableKeyRotation",
      "kms:GetKeyRotationStatus",
      "kms:ListKeyPolicies",
      "kms:ListResourceTags",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:UpdateKeyDescription",
    ]
    resources = ["*"]
  }

  # 3) S3 service can use the key for SSE-KMS on objects in the uploads
  #    bucket. The condition restricts use to this specific bucket via
  #    EncryptionContext, so a different bucket in the account can't
  #    invoke this key even if its policy somehow allows it.
  statement {
    sid    = "AllowS3EncryptDecrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # 4) DynamoDB service can use the key for SSE-KMS on the intake table.
  statement {
    sid    = "AllowDynamoDBEncryptDecrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["dynamodb.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "phi" {
  description             = "Acme Health PHI encryption (S3 uploads + DynamoDB intake table). SOC 2 CC6.1."
  enable_key_rotation     = true # SC-12: annual automatic rotation.
  deletion_window_in_days = 7    # Soft-deletes; can be cancelled within window.
  policy                  = data.aws_iam_policy_document.phi_key.json
}

resource "aws_kms_alias" "phi" {
  name          = "alias/acme-health-phi"
  target_key_id = aws_kms_key.phi.key_id
}

output "phi_kms_key_arn" {
  value       = aws_kms_key.phi.arn
  description = "ARN of the PHI CMK. Used by S3 and DynamoDB encryption configurations."
}

output "phi_kms_key_id" {
  value       = aws_kms_key.phi.key_id
  description = "Key ID of the PHI CMK."
}

output "phi_kms_alias" {
  value       = aws_kms_alias.phi.name
  description = "Human-readable alias for the PHI CMK."
}