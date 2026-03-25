# =============================================================================
# Serverless Databricks Workspace IAM Module
# Extracts and modularizes all IAM-related policies required for a
# Databricks Serverless workspace deployment.
#
# Note: Serverless deployments do NOT require cross-account IAM roles for
# compute management. Databricks manages the compute infrastructure.
# IAM concerns are limited to:
#   - S3 bucket policies (granting Databricks access to workspace root storage)
#   - KMS key policies (for DBFS, managed services, and optional EBS encryption)
# =============================================================================

# =============================================================================
# DATA SOURCES
# =============================================================================

data "aws_caller_identity" "current" {}

# =============================================================================
# S3 BUCKET POLICY - Workspace Root Storage
# Grants Databricks access to the workspace root S3 bucket with
# PrincipalTag-based condition for account scoping.
# Includes a Deny statement to prevent DBFS from accessing Unity Catalog paths.
# =============================================================================

data "aws_iam_policy_document" "workspace_root_databricks_access" {
  statement {
    sid    = "GrantDatabricksAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [
      "${var.workspace_root_bucket_arn}/*",
      var.workspace_root_bucket_arn
    ]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.databricks_aws_account_id}:root"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/DatabricksAccountId"
      values   = [var.databricks_account_id]
    }
  }

  statement {
    sid    = "PreventDBFSFromAccessingUnityCatalogMetastore"
    effect = "Deny"
    actions = [
      "s3:*"
    ]
    resources = ["${var.workspace_root_bucket_arn}/unity-catalog/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.databricks_aws_account_id}:root"]
    }
  }
}

# =============================================================================
# KMS KEY POLICY - Workspace Encryption
# Combined policy for DBFS, managed services, and optional EBS encryption.
# Follows the same pattern as complete-workspace-serverless module.
# =============================================================================

data "aws_iam_policy_document" "workspace_kms" {
  statement {
    sid    = "EnableRootPermissions"
    effect = "Allow"
    actions = [
      "kms:*"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowDatabricksUseForDBFS"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.databricks_aws_account_id}:root"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/DatabricksAccountId"
      values   = [var.databricks_account_id]
    }
  }

  statement {
    sid    = "AllowDatabricksUseForDBFSGrants"
    effect = "Allow"
    actions = [
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.databricks_aws_account_id}:root"]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/DatabricksAccountId"
      values   = [var.databricks_account_id]
    }
  }

  statement {
    sid    = "AllowDatabricksUseForManagedServices"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.databricks_aws_account_id}:root"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/DatabricksAccountId"
      values   = [var.databricks_account_id]
    }
  }

  dynamic "statement" {
    for_each = var.databricks_cross_account_role_arn == null ? [] : [var.databricks_cross_account_role_arn]
    content {
      sid    = "AllowDatabricksUseForEBS"
      effect = "Allow"
      actions = [
        "kms:Decrypt",
        "kms:GenerateDataKey*",
        "kms:CreateGrant",
        "kms:DescribeKey"
      ]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [statement.value]
      }

      condition {
        test     = "ForAnyValue:StringLike"
        variable = "kms:ViaService"
        values   = ["ec2.*.amazonaws.com"]
      }
    }
  }
}
