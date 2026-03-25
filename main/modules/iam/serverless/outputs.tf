# =============================================================================
# S3 Bucket Policy Outputs
# =============================================================================

output "workspace_root_bucket_policy_json" {
  description = "JSON policy document for the workspace root S3 bucket (grants Databricks access)"
  value       = data.aws_iam_policy_document.workspace_root_databricks_access.json
}

# =============================================================================
# KMS Key Policy Outputs
# =============================================================================

output "workspace_kms_key_policy_json" {
  description = "JSON policy document for the workspace KMS key (DBFS, managed services, optional EBS)"
  value       = data.aws_iam_policy_document.workspace_kms.json
}
