# Tests for sc28_s3_cmk.rego (GAP-01).
#
# Conftest test fixtures: we hand-craft a minimal plan JSON-like input
# and call the deny rule against it. A test passes when deny returns
# the expected set of messages.

package main

import rego.v1

# Fixture: a passing plan — bucket WITH SSE-KMS configuration including CMK.
passing_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {"bucket": "uploads-12345"},
			},
		},
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
		# Satisfies GAP-03 (TLS-only) so the fixture is clean across all
		# policies, not just GAP-01.
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "aws_s3_bucket.uploads",
					"policy": json.marshal({
						"Version": "2012-10-17",
						"Statement": [{
							"Effect": "Deny",
							"Principal": "*",
							"Action": "s3:*",
							"Resource": "arn:aws:s3:::uploads-12345/*",
							"Condition": {"Bool": {"aws:SecureTransport": "false"}},
						}],
					}),
				},
			},
		},
	],
}

# Fixture: failing — bucket with NO SSE configuration at all.
no_sse_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {"bucket": "uploads-12345"},
			},
		},
	],
}

# Fixture: failing — bucket with AES256 (SSE-S3) encryption.
aes256_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"actions": ["create"], "after": {"bucket": "uploads-12345"}},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "aws_s3_bucket.uploads",
					"rule": [{
						"apply_server_side_encryption_by_default": [{
							"sse_algorithm": "AES256",
						}],
					}],
				},
			},
		},
	],
}

# Fixture: failing — aws:kms but no kms_master_key_id (would use AWS-managed S3 key).
kms_no_cmk_plan := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"actions": ["create"], "after": {"bucket": "uploads-12345"}},
		},
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
						}],
					}],
				},
			},
		},
	],
}

test_passing_plan_has_no_denies if {
	count(deny) == 0 with input as passing_plan
}

test_no_sse_plan_denies if {
	count(deny) > 0 with input as no_sse_plan
}

test_aes256_plan_denies if {
	count(deny) > 0 with input as aes256_plan
}

test_kms_no_cmk_plan_denies if {
	count(deny) > 0 with input as kms_no_cmk_plan
}