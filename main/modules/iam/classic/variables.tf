# =============================================================================
# Required Variables
# =============================================================================

variable "aws_account_id" {
  description = "AWS account ID where IAM resources will be created"
  type        = string
}

variable "databricks_account_id" {
  description = "Databricks account ID (used as external ID in trust policies)"
  type        = string
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-west-2"
}

variable "resource_prefix" {
  description = "Prefix for all IAM resource names"
  type        = string
}

# =============================================================================
# Network Configuration
# =============================================================================

variable "vpc_id" {
  description = "VPC ID where the Databricks workspace is deployed (used in cross-account policy scoping)"
  type        = string

  validation {
    condition     = can(regex("^vpc-[a-f0-9]{8,}$", var.vpc_id))
    error_message = "VPC ID must be in format: vpc-xxxxxxxx"
  }
}

variable "security_group_id" {
  description = "Security group ID for VPC-scoped IAM policy statements"
  type        = string
}

# =============================================================================
# GovCloud / Partition Configuration
# =============================================================================

variable "databricks_gov_shard" {
  description = "Databricks GovCloud shard type. Only applicable for us-gov-west-1 region."
  type        = string
  default     = null

  validation {
    condition     = var.databricks_gov_shard == null || can(contains(["civilian", "dod"], var.databricks_gov_shard))
    error_message = "Allowed values: null, civilian, dod."
  }
}

# =============================================================================
# Unity Catalog Configuration
# =============================================================================

variable "create_unity_catalog_role" {
  description = "Whether to create the Unity Catalog IAM role and policy"
  type        = bool
  default     = true
}

variable "unity_catalog_iam_arn" {
  description = "Databricks Unity Catalog master role ARN for trust policy"
  type        = string
  default     = "arn:aws:iam::414351767826:role/unity-catalog-prod-UCMasterRole-14S5ZJVKOTYTL"
}

variable "uc_catalog_bucket_name" {
  description = "Name of the S3 bucket used by Unity Catalog"
  type        = string
  default     = null
}

variable "uc_catalog_role_name" {
  description = "Name for the Unity Catalog IAM role"
  type        = string
  default     = null
}

variable "uc_catalog_kms_key_arn" {
  description = "ARN of the KMS key used for Unity Catalog storage encryption"
  type        = string
  default     = null
}

variable "uc_storage_credential_external_id" {
  description = "External ID from the Databricks storage credential (for UC trust policy)"
  type        = string
  default     = null
}

# =============================================================================
# Audit Log Delivery Configuration
# =============================================================================

variable "create_audit_log_delivery_role" {
  description = "Whether to create the audit log delivery IAM role"
  type        = bool
  default     = true
}

# =============================================================================
# Tags
# =============================================================================

variable "tags" {
  description = "Tags to apply to all IAM resources"
  type        = map(string)
  default     = {}
}
