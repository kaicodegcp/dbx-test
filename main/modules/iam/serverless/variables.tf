# =============================================================================
# Required Variables
# =============================================================================

variable "aws_account_id" {
  description = "AWS account ID where IAM resources will be created"
  type        = string
}

variable "databricks_account_id" {
  description = "Databricks account ID (used in S3 bucket policy and KMS key policy conditions)"
  type        = string
}

variable "databricks_aws_account_id" {
  description = "Databricks AWS account ID used as principal in S3 bucket and KMS key policies"
  type        = string
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-west-2"
}

variable "resource_prefix" {
  description = "Prefix for all resource names"
  type        = string
}

# =============================================================================
# S3 Bucket Configuration
# =============================================================================

variable "workspace_root_bucket_arn" {
  description = "ARN of the workspace root S3 bucket (used in bucket policy)"
  type        = string
}

# =============================================================================
# KMS Configuration
# =============================================================================

variable "databricks_cross_account_role_arn" {
  description = "Optional Databricks cross-account IAM role ARN for EBS KMS usage. Only needed if a Classic cross-account role exists."
  type        = string
  default     = null
}

# =============================================================================
# Tags
# =============================================================================

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
