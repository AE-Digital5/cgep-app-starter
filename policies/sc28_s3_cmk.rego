# GAP-01 — S3 buckets must use customer-managed KMS encryption.
#
# SOC 2 CC6.1 (Encryption at rest).
# NIST 800-53 control reference: SC-28 (Protection of Information at Rest).
#
# The starter ships its S3 uploads bucket with AWS default encryption,
# which is SSE-S3 (AWS-managed). For PHI workloads, customer-managed
# KMS keys are required so encryption keys can be rotated, audited,
# and revoked independently of AWS. This policy enforces that every
# bucket has a corresponding SSE configuration AND that the SSE
# algorithm is "aws:kms" (which implies a CMK is being used; we further
# verify the kms_master_key_id is set).
#
# This policy operates on Terraform plan JSON produced by:
#   terraform show -json tfplan > plan.json
#   conftest test plan.json --policy policies/
#
# Tested via: policies/tests/sc28_s3_cmk_test.rego

package main

import rego.v1

# Every S3 bucket resource in the plan...
buckets contains addr if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.actions[_] != "delete"
	addr := rc.address
}

# Every bucket that has a corresponding SSE configuration resource...
buckets_with_sse contains addr if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	rc.change.actions[_] != "delete"

	# The bucket attribute references the parent bucket; this is how
	# we associate the SSE configuration with the bucket it protects.
	# We allow this to be any reference (the Terraform graph guarantees
	# it points to a real bucket).
	addr := rc.change.after.bucket
}

# DENY: any bucket without a corresponding SSE configuration.
deny contains msg if {
	some bucket_addr in buckets
	count({addr | some addr in buckets_with_sse; addr == _bucket_id(bucket_addr)}) == 0

	msg := sprintf(
		"GAP-01 (SOC 2 CC6.1 / SC-28): S3 bucket %v has no server-side encryption configuration. Add an aws_s3_bucket_server_side_encryption_configuration resource targeting this bucket with sse_algorithm = \"aws:kms\".",
		[bucket_addr],
	)
}

# DENY: any SSE configuration that uses anything other than aws:kms.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	rc.change.actions[_] != "delete"

	rule := rc.change.after.rule[_]
	sbd := rule.apply_server_side_encryption_by_default[_]
	sbd.sse_algorithm != "aws:kms"

	msg := sprintf(
		"GAP-01 (SOC 2 CC6.1 / SC-28): S3 bucket SSE configuration %v uses sse_algorithm=%v. Required: \"aws:kms\" with a customer-managed key.",
		[rc.address, sbd.sse_algorithm],
	)
}

# DENY: aws:kms encryption that doesn't specify a KMS key ID.
# (Without kms_master_key_id, "aws:kms" defaults to the AWS-managed S3 key,
#  which defeats the purpose of moving away from SSE-S3.)
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	rc.change.actions[_] != "delete"

	rule := rc.change.after.rule[_]
	sbd := rule.apply_server_side_encryption_by_default[_]
	sbd.sse_algorithm == "aws:kms"
	not sbd.kms_master_key_id

	msg := sprintf(
		"GAP-01 (SOC 2 CC6.1 / SC-28): S3 bucket SSE configuration %v uses aws:kms but no kms_master_key_id is specified, which defaults to the AWS-managed S3 key. Specify a customer-managed CMK ARN.",
		[rc.address],
	)
}

# Helper: extract the canonical bucket address from various forms the
# Terraform plan might use to reference the bucket.
_bucket_id(ref) := ref