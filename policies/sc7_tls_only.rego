# GAP-03 — S3 buckets must reject non-TLS access via bucket policy.
#
# SOC 2 CC6.7 (Encryption in transit).
# NIST 800-53 control references:
#   - SC-7 (Boundary Protection)
#   - SC-8 (Transmission Confidentiality and Integrity)
#
# The starter ships its S3 uploads bucket with no bucket policy. AWS
# defaults allow both HTTPS and HTTP access (HTTP redirects to HTTPS
# at the bucket level, but pre-signed URLs and some legacy clients can
# still establish HTTP connections). For PHI workloads, an explicit
# Deny-on-non-TLS is required.
#
# AWS publishes this exact policy pattern as the canonical TLS-only
# enforcement, see "Restrict access to your S3 buckets or objects to
# only HTTPS" in the S3 user guide. The policy works by attaching a
# Deny statement to the bucket whose condition matches when the
# request's aws:SecureTransport flag is false.
#
# This policy enforces that every bucket has a bucket policy AND that
# the bucket policy contains a Deny statement gated on
# aws:SecureTransport = false targeting s3 actions on the bucket.
#
# Tested via: policies/tests/sc7_tls_only_test.rego

package main

import rego.v1

# Set of bucket addresses that have any bucket policy attached.
buckets_with_policy contains bucket_ref if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_policy"
	rc.change.actions[_] != "delete"
	bucket_ref := rc.change.after.bucket
}

# Set of buckets whose policy contains a TLS-enforcing Deny statement.
buckets_with_tls_deny contains bucket_ref if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_policy"
	rc.change.actions[_] != "delete"

	# Parse the policy JSON string from the plan.
	policy := json.unmarshal(rc.change.after.policy)

	some stmt in policy.Statement
	stmt.Effect == "Deny"

	# The Deny must include S3 actions on this bucket.
	# Action can be a string or array; normalize to a set.
	_action_includes_s3(stmt.Action)

	# The condition must check aws:SecureTransport = false.
	stmt.Condition.Bool["aws:SecureTransport"] == "false"

	bucket_ref := rc.change.after.bucket
}

# Action can be a string ("s3:*") or array (["s3:GetObject", ...]).
# Either is acceptable as long as it covers S3 actions on the bucket.
_action_includes_s3(action) if {
	# String case.
	is_string(action)
	startswith(action, "s3:")
}

_action_includes_s3(action) if {
	# Array case.
	is_array(action)
	some a in action
	startswith(a, "s3:")
}

# DENY: any S3 bucket without an associated bucket policy.
# This catches the starter's default state (no policy at all).
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.actions[_] != "delete"
	bucket_addr := rc.address

	# No bucket policy resource targets this bucket.
	not _has_policy(bucket_addr)

	msg := sprintf(
		"GAP-03 (SOC 2 CC6.7 / SC-7,SC-8): S3 bucket %v has no bucket policy. Add an aws_s3_bucket_policy resource with a Deny statement on aws:SecureTransport = false.",
		[bucket_addr],
	)
}

# DENY: any S3 bucket whose policy lacks a TLS-enforcing Deny statement.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_policy"
	rc.change.actions[_] != "delete"
	bucket_ref := rc.change.after.bucket

	not _has_tls_deny(bucket_ref)

	msg := sprintf(
		"GAP-03 (SOC 2 CC6.7 / SC-7,SC-8): S3 bucket policy %v exists but contains no Deny statement gated on aws:SecureTransport = false. Add a Deny on s3:* with Condition.Bool[aws:SecureTransport] = \"false\".",
		[rc.address],
	)
}

# Helpers
_has_policy(bucket_addr) if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_policy"
	rc.change.actions[_] != "delete"

	# Match if the policy's bucket attribute references this bucket.
	# Plan refs typically resolve to addresses or IDs; we match loosely.
	contains(sprintf("%v", [rc.change.after.bucket]), bucket_addr)
}

_has_tls_deny(bucket_ref) if {
	bucket_ref in buckets_with_tls_deny
}