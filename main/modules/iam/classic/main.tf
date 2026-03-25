# =============================================================================
# Classic Databricks Workspace IAM Module
# Extracts and modularizes all IAM roles, policies, and trust relationships
# required for a Databricks Classic (Custom VPC) workspace deployment.
# =============================================================================

# =============================================================================
# DATA SOURCES
# =============================================================================

data "aws_caller_identity" "current" {}

data "databricks_aws_assume_role_policy" "cross_account" {
  provider    = databricks.account
  external_id = var.databricks_account_id
}

data "databricks_aws_assume_role_policy" "log_delivery" {
  provider         = databricks.account
  count            = var.create_audit_log_delivery_role ? 1 : 0
  external_id      = var.databricks_account_id
  for_log_delivery = true
  aws_partition    = local.assume_role_partition
}

data "databricks_aws_unity_catalog_assume_role_policy" "this" {
  provider              = databricks.workspace
  count                 = local.create_uc_role ? 1 : 0
  aws_account_id        = var.aws_account_id
  role_name             = local.uc_role_name
  unity_catalog_iam_arn = var.unity_catalog_iam_arn
  external_id           = var.uc_storage_credential_external_id
}

data "databricks_aws_unity_catalog_policy" "this" {
  provider       = databricks.workspace
  count          = local.create_uc_role ? 1 : 0
  aws_account_id = var.aws_account_id
  bucket_name    = var.uc_catalog_bucket_name
  role_name      = local.uc_role_name
  kms_name       = var.uc_catalog_kms_key_arn
}

# =============================================================================
# LOCALS
# =============================================================================

locals {
  computed_aws_partition = var.databricks_gov_shard != null ? "aws-us-gov" : "aws"

  databricks_aws_account_id = var.databricks_gov_shard == "civilian" ? "044793339203" : (
    var.databricks_gov_shard == "dod" ? "170661010020" : "414351767826"
  )

  databricks_ec2_image_account_id = var.databricks_gov_shard != null ? "044732911619" : "601306020600"

  assume_role_partition = var.databricks_gov_shard == "dod" ? "aws-us-gov-dod" : (
    var.databricks_gov_shard == "civilian" ? "aws-us-gov" : "aws"
  )

  create_uc_role = var.create_unity_catalog_role && var.uc_catalog_bucket_name != null && var.uc_catalog_kms_key_arn != null && var.uc_storage_credential_external_id != null
  uc_role_name   = var.uc_catalog_role_name != null ? var.uc_catalog_role_name : "${var.resource_prefix}-catalog-role"
}

# =============================================================================
# CROSS-ACCOUNT IAM ROLE
# Databricks control plane assumes this role to manage EC2 instances, volumes,
# fleets, launch templates, and networking for Classic compute clusters.
# =============================================================================

module "iam_role_cross_account" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 5.0"

  trusted_role_arns = []

  create_role                     = true
  role_name                       = "${var.resource_prefix}-cross-account"
  role_requires_mfa               = false
  create_custom_role_trust_policy = true
  custom_role_trust_policy        = data.databricks_aws_assume_role_policy.cross_account.json

  custom_role_policy_arns = [module.iam_policy_cross_account.arn]

  tags = merge(var.tags, { Name = "${var.resource_prefix}-cross-account" })
}

# =============================================================================
# CROSS-ACCOUNT IAM POLICY
# SRA-aligned: EC2 lifecycle, VPC SG management, AMI restrictions,
# Spot service-linked role creation.
# =============================================================================

module "iam_policy_cross_account" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-policy"
  version = "~> 5.0"

  name        = "${var.resource_prefix}-cross-account-policy"
  description = "Databricks cross-account policy with full EC2 and networking permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CreateEC2ResourcesWithRequestTag"
        Effect = "Allow"
        Action = [
          "ec2:CreateFleet",
          "ec2:CreateLaunchTemplate",
          "ec2:CreateLaunchTemplateVersion",
          "ec2:CreateVolume",
          "ec2:RequestSpotInstances",
          "ec2:RunInstances"
        ]
        Resource = [
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:fleet/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:launch-template/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestTag/Vendor" = "Databricks"
          }
        }
      },
      {
        Sid    = "AllowDatabricksTagOnCreate"
        Effect = "Allow"
        Action = ["ec2:CreateTags"]
        Resource = [
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:launch-template/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:fleet/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*"
        ]
        Condition = {
          StringEquals = {
            "ec2:CreateAction" = [
              "CreateFleet",
              "CreateLaunchTemplate",
              "CreateVolume",
              "RequestSpotInstances",
              "RunInstances"
            ]
            "aws:RequestTag/Vendor" = "Databricks"
          }
        }
      },
      {
        Sid    = "ModifyEC2ResourcesByResourceTags"
        Effect = "Allow"
        Action = [
          "ec2:AssignPrivateIpAddresses",
          "ec2:AssociateIamInstanceProfile",
          "ec2:AttachVolume",
          "ec2:CancelSpotInstanceRequests",
          "ec2:CreateLaunchTemplateVersion",
          "ec2:DetachVolume",
          "ec2:DisassociateIamInstanceProfile",
          "ec2:ModifyFleet",
          "ec2:ModifyLaunchTemplate",
          "ec2:RequestSpotInstances",
          "ec2:CreateFleet",
          "ec2:CreateLaunchTemplate",
          "ec2:CreateVolume",
          "ec2:RunInstances"
        ]
        Resource = [
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:launch-template/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:fleet/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:spot-instance-request/*"
        ]
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Vendor" = "Databricks"
          }
        }
      },
      {
        Sid    = "GetEC2LaunchTemplateDataByTag"
        Effect = "Allow"
        Action = [
          "ec2:GetLaunchTemplateData"
        ]
        Resource = [
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:fleet/*"
        ]
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Vendor" = "Databricks"
          }
        }
      },
      {
        Sid    = "DescribeEC2Resources"
        Effect = "Allow"
        Action = [
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeFleetHistory",
          "ec2:DescribeFleetInstances",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeFleets",
          "ec2:DescribeIamInstanceProfileAssociations",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstances",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:DescribeNatGateways",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribePrefixLists",
          "ec2:DescribeReservedInstancesOfferings",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSpotInstanceRequests",
          "ec2:DescribeSpotPriceHistory",
          "ec2:DescribeSubnets",
          "ec2:DescribeVolumes",
          "ec2:DescribeVpcs",
          "ec2:GetSpotPlacementScores"
        ]
        Resource = "*"
      },
      {
        Sid    = "DeleteEC2ResourcesByTag"
        Effect = "Allow"
        Action = [
          "ec2:DeleteFleets",
          "ec2:DeleteLaunchTemplate",
          "ec2:DeleteLaunchTemplateVersions",
          "ec2:DeleteTags",
          "ec2:DeleteVolume",
          "ec2:TerminateInstances"
        ]
        Resource = [
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:launch-template/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:fleet/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:spot-instance-request/*"
        ]
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Vendor" = "Databricks"
          }
        }
      },
      {
        Sid    = "AllowEC2TaggingOnDatabricksResources"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = [
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:launch-template/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:fleet/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:spot-instance-request/*"
        ]
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Vendor" = "Databricks"
          }
        }
      },
      {
        Sid    = "VpcNonresourceSpecificActions"
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:security-group/${var.security_group_id}"
        Condition = {
          StringEquals = {
            "ec2:vpc" = "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:vpc/${var.vpc_id}"
          }
        }
      },
      {
        Sid    = "RestrictAMIUsageToDatabricksDeny"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances",
          "ec2:CreateFleet",
          "ec2:RequestSpotInstances"
        ]
        Resource = "arn:${local.computed_aws_partition}:ec2:*:*:image/*"
        Condition = {
          StringNotEquals = {
            "ec2:Owner" = local.databricks_ec2_image_account_id
          }
        }
      },
      {
        Sid    = "RestrictAMIUsageToDatabricksAllow"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:CreateFleet",
          "ec2:RequestSpotInstances"
        ]
        Resource = "arn:${local.computed_aws_partition}:ec2:*:*:image/*"
        Condition = {
          StringEquals = {
            "ec2:Owner" = local.databricks_ec2_image_account_id
          }
        }
      },
      {
        Sid    = "AllowRunInstancesWithScopedResources"
        Effect = "Allow"
        Action = "ec2:RunInstances"
        Resource = [
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:subnet/*",
          "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:security-group/*"
        ]
        Condition = {
          StringEqualsIfExists = {
            "ec2:vpc" = "arn:${local.computed_aws_partition}:ec2:${var.aws_region}:${var.aws_account_id}:vpc/${var.vpc_id}"
          }
        }
      },
      {
        Sid    = "IAMRoleForEC2Spot"
        Effect = "Allow"
        Action = ["iam:CreateServiceLinkedRole"]
        Resource = [
          "arn:${local.computed_aws_partition}:iam::*:role/aws-service-role/spot.amazonaws.com/AWSServiceRoleForEC2Spot"
        ]
        Condition = {
          StringLike = {
            "iam:AWSServiceName" = "spot.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.resource_prefix}-cross-account-policy" })
}

# =============================================================================
# IAM ROLE PROPAGATION WAIT
# =============================================================================

resource "time_sleep" "cross_account_role_propagation" {
  depends_on      = [module.iam_role_cross_account]
  create_duration = "20s"
}

# =============================================================================
# AUDIT LOG DELIVERY IAM ROLE
# Allows Databricks to deliver audit logs to a customer-managed S3 bucket.
# =============================================================================

module "iam_role_audit_log_delivery" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 5.0"
  count   = var.create_audit_log_delivery_role ? 1 : 0

  create_role                     = true
  role_name                       = "${var.resource_prefix}-audit-log-delivery-role"
  role_description                = "(${var.resource_prefix}) Audit Log Delivery role"
  role_requires_mfa               = false
  create_custom_role_trust_policy = true
  custom_role_trust_policy        = data.databricks_aws_assume_role_policy.log_delivery[0].json
  trusted_role_arns               = []

  tags = merge(var.tags, {
    Name = "${var.resource_prefix}-audit-log-delivery-role"
  })
}

resource "time_sleep" "audit_log_role_propagation" {
  count = var.create_audit_log_delivery_role ? 1 : 0

  depends_on      = [module.iam_role_audit_log_delivery]
  create_duration = "10s"
}

# =============================================================================
# UNITY CATALOG IAM ROLE
# Provides S3 and KMS access for Unity Catalog storage credential.
# Trust policy allows self-assume and Databricks UC master role.
# =============================================================================

module "iam_role_unity_catalog" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 5.0"
  count   = local.create_uc_role ? 1 : 0

  create_role                     = true
  role_name                       = local.uc_role_name
  role_requires_mfa               = false
  create_custom_role_trust_policy = true
  custom_role_trust_policy        = data.databricks_aws_unity_catalog_assume_role_policy.this[0].json
  trusted_role_arns               = []

  custom_role_policy_arns = [module.iam_policy_unity_catalog[0].arn]

  tags = merge(var.tags, { Name = local.uc_role_name })
}

# =============================================================================
# UNITY CATALOG IAM POLICY
# S3 read/write on catalog bucket, KMS decrypt/encrypt/generate.
# Policy content is generated by the Databricks provider data source.
# =============================================================================

module "iam_policy_unity_catalog" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-policy"
  version = "~> 5.0"
  count   = local.create_uc_role ? 1 : 0

  name   = "${var.resource_prefix}-unity-catalog-policy"
  policy = data.databricks_aws_unity_catalog_policy.this[0].json
}

resource "time_sleep" "unity_catalog_role_propagation" {
  count           = local.create_uc_role ? 1 : 0
  depends_on      = [module.iam_role_unity_catalog]
  create_duration = "60s"
}
