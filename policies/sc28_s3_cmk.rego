# GAP-01 — S3 buckets must use customer-managed KMS encryption.
#
# SOC 2 CC6.1 (Encryption at rest).
# NIST 800-53 control reference: SC-28 (Protection of Information at Rest).
#
# This policy enforces that every aws_s3_bucket has a corresponding
# aws_s3_bucket_server_side_encryption_configuration resource AND
# that the SSE algorithm is "aws:kms" AND that a kms_master_key_id
# is specified.
#
# Handling of Terraform plan-time unresolved references:
#   When a resource attribute references another resource (e.g.,
#   `bucket = aws_s3_bucket.uploads.id` or `kms_master_key_id =
#   aws_kms_key.phi.arn`), the value is unknown at plan time and
#   appears in `change.after_unknown[<path>] = true` rather than in
#   `change.after`. We treat unknown-at-plan-time as a valid intent:
#   the Terraform graph guarantees the reference will resolve at
#   apply time. If we rejected unknown references, no policy could
#   pass against a fresh apply.
#
# Tested via: policies/tests/sc28_s3_cmk_test.rego

package main

import rego.v1

# Every S3 bucket resource being created/updated.
buckets contains addr if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.actions[_] != "delete"
	addr := rc.address
}

# Every SSE configuration whose `bucket` field references something
# (either a known value or an unknown-at-plan-time reference).
sse_configs contains rc.address if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	rc.change.actions[_] != "delete"
	_has_bucket_field(rc)
}

# An SSE config has a usable bucket field if it's set (known) OR will
# be set at apply (unknown). Both count as "the SSE is targeting some
# bucket the Terraform graph knows about."
_has_bucket_field(rc) if {
	rc.change.after.bucket
}

_has_bucket_field(rc) if {
	rc.change.after_unknown.bucket == true
}

# DENY: there are buckets in the plan but zero SSE configurations,
# i.e. the plan as a whole has no encryption story for its buckets.
# We don't try to match individual buckets to individual SSE configs
# because at plan time the bucket references are unresolved; we instead
# verify the COUNT relationship at the plan level.
deny contains msg if {
	count(buckets) > 0
	count(sse_configs) == 0

	some bucket_addr in buckets
	msg := sprintf(
		"GAP-01 (SOC 2 CC6.1 / SC-28): S3 bucket %v has no server-side encryption configuration anywhere in the plan. Add an aws_s3_bucket_server_side_encryption_configuration resource with sse_algorithm = \"aws:kms\".",
		[bucket_addr],
	)
}

# DENY: when there are buckets, the count of SSE configs must be at
# least the count of buckets. If fewer SSE configs than buckets, some
# bucket is missing one.
deny contains msg if {
	count(buckets) > count(sse_configs)
	count(sse_configs) > 0

	msg := sprintf(
		"GAP-01 (SOC 2 CC6.1 / SC-28): plan has %d S3 buckets but only %d SSE configurations. Each bucket needs its own aws_s3_bucket_server_side_encryption_configuration.",
		[count(buckets), count(sse_configs)],
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

# DENY: aws:kms encryption that doesn't reference a CMK at all.
# "Doesn't reference a CMK" means: kms_master_key_id is neither set
# (known string) nor unknown-at-plan-time (will be set at apply).
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	rc.change.actions[_] != "delete"

	rule := rc.change.after.rule[_]
	sbd := rule.apply_server_side_encryption_by_default[_]
	sbd.sse_algorithm == "aws:kms"

	# Not set (empty or absent) AND not coming-at-apply.
	not _has_kms_key_id(rc.change, rule)

	msg := sprintf(
		"GAP-01 (SOC 2 CC6.1 / SC-28): S3 bucket SSE configuration %v uses aws:kms but no kms_master_key_id is specified. Specify a customer-managed CMK (literal ARN or aws_kms_key.<name>.arn reference).",
		[rc.address],
	)
}

# Helper: is kms_master_key_id set, either known or known-after-apply?
_has_kms_key_id(change, rule) if {
	sbd := rule.apply_server_side_encryption_by_default[_]
	sbd.kms_master_key_id
	sbd.kms_master_key_id != ""
}

_has_kms_key_id(change, _) if {
	# Check the unknown-at-plan-time path. The structure mirrors
	# the change.after.rule[*].apply_server_side_encryption_by_default[*].
	some unknown_rule in change.after_unknown.rule
	some sbd in unknown_rule.apply_server_side_encryption_by_default
	sbd.kms_master_key_id == true
}