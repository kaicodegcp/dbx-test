# =============================================================================
# Cross-Account Role Outputs
# =============================================================================

output "cross_account_role_arn" {
  description = "ARN of the Databricks cross-account IAM role"
  value       = module.iam_role_cross_account.iam_role_arn
}

output "cross_account_role_name" {
  description = "Name of the Databricks cross-account IAM role"
  value       = module.iam_role_cross_account.iam_role_name
}

output "cross_account_policy_arn" {
  description = "ARN of the Databricks cross-account IAM policy"
  value       = module.iam_policy_cross_account.arn
}

# =============================================================================
# Audit Log Delivery Role Outputs
# =============================================================================

output "audit_log_delivery_role_arn" {
  description = "ARN of the audit log delivery IAM role"
  value       = var.create_audit_log_delivery_role ? module.iam_role_audit_log_delivery[0].iam_role_arn : null
}

output "audit_log_delivery_role_name" {
  description = "Name of the audit log delivery IAM role"
  value       = var.create_audit_log_delivery_role ? module.iam_role_audit_log_delivery[0].iam_role_name : null
}

# =============================================================================
# Unity Catalog Role Outputs
# =============================================================================

output "unity_catalog_role_arn" {
  description = "ARN of the Unity Catalog IAM role"
  value       = local.create_uc_role ? module.iam_role_unity_catalog[0].iam_role_arn : null
}

output "unity_catalog_role_name" {
  description = "Name of the Unity Catalog IAM role"
  value       = local.create_uc_role ? module.iam_role_unity_catalog[0].iam_role_name : null
}

output "unity_catalog_policy_arn" {
  description = "ARN of the Unity Catalog IAM policy"
  value       = local.create_uc_role ? module.iam_policy_unity_catalog[0].arn : null
}
