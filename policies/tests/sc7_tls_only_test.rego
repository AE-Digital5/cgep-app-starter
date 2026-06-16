# Tests for sc7_tls_only.rego (GAP-03).

package main

import rego.v1

# Helper: build a valid TLS-deny policy as a JSON string (matching what
# Terraform produces in plan output).
_tls_deny_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "DenyUnencryptedTransport",
		"Effect": "Deny",
		"Principal": {"AWS": "*"},
		"Action": "s3:*",
		"Resource": [
			"arn:aws:s3:::uploads-12345",
			"arn:aws:s3:::uploads-12345/*",
		],
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}],
})

# Fixture: passing — bucket + bucket policy with TLS-deny.
tls_passing_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {"bucket": "uploads-12345"},
			},
		},
		# Satisfies GAP-01 (S3 SSE-KMS) so the fixture is clean across
		# all policies, not just GAP-03.
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "aws_s3_bucket.uploads",
					"rule": [{
						"apply_server_side_encryption_by_default": [{
							"sse_algorithm": "aws:kms",
							"kms_master_key_id": "arn:aws:kms:us-east-1:000000000000:key/abc-123",
						}],
					}],
				},
			},
		},
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "aws_s3_bucket.uploads",
					"policy": _tls_deny_policy_json,
				},
			},
		},
	],
}

# Fixture: failing — bucket with no policy at all.
tls_no_policy_plan := {
	"resource_changes": [{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"bucket": "uploads-12345"}},
	}],
}

# Fixture: failing — bucket policy exists but only Allows; no Deny.
_allow_only_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": "*",
		"Action": "s3:GetObject",
		"Resource": "arn:aws:s3:::uploads-12345/*",
	}],
})

tls_allow_only_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"actions": ["create"], "after": {"bucket": "uploads-12345"}},
		},
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "aws_s3_bucket.uploads",
					"policy": _allow_only_policy_json,
				},
			},
		},
	],
}

# Fixture: failing — Deny exists but the condition uses the wrong key
# (typo: aws:SecureTransporT) so it doesn't actually enforce TLS.
_wrong_condition_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": "arn:aws:s3:::uploads-12345/*",
		"Condition": {"Bool": {"aws:SecureTransporT": "false"}}, # typo
	}],
})

tls_wrong_condition_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"actions": ["create"], "after": {"bucket": "uploads-12345"}},
		},
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "aws_s3_bucket.uploads",
					"policy": _wrong_condition_policy_json,
				},
			},
		},
	],
}

test_tls_passing_plan_has_no_denies if {
	count(deny) == 0 with input as tls_passing_plan
}

test_tls_no_policy_plan_denies if {
	count(deny) > 0 with input as tls_no_policy_plan
}

test_tls_allow_only_plan_denies if {
	count(deny) > 0 with input as tls_allow_only_plan
}

test_tls_wrong_condition_plan_denies if {
	count(deny) > 0 with input as tls_wrong_condition_plan
}