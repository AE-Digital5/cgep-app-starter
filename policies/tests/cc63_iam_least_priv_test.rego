# Tests for cc63_iam_least_priv.rego (GAP-07).

package main

import rego.v1

# Helper to build IAM policies as JSON strings (matching plan output).
_policy_specific := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": ["dynamodb:PutItem"],
			"Resource": "arn:aws:dynamodb:us-east-1:000000000000:table/intake",
		},
		{
			"Effect": "Allow",
			"Action": ["s3:PutObject"],
			"Resource": "arn:aws:s3:::uploads-12345/uploads/*",
		},
	],
})

_policy_with_ddb_wildcard := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": "dynamodb:*",
			"Resource": "arn:aws:dynamodb:us-east-1:000000000000:table/intake",
		},
	],
})

_policy_with_s3_wildcard_in_array := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": ["s3:GetObject", "s3:*"], # one specific, one wildcard
			"Resource": ["arn:aws:s3:::uploads-12345", "arn:aws:s3:::uploads-12345/*"],
		},
	],
})

_policy_with_full_wildcard := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": "*",
		"Resource": "*",
	}],
})

_policy_with_action_prefix := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": ["dynamodb:Get*", "dynamodb:Describe*"], # prefix patterns, not service wildcards
			"Resource": "arn:aws:dynamodb:us-east-1:000000000000:table/intake",
		},
	],
})

# Helper to construct a fixture wrapping one of the policy JSON strings.
_fixture(policy_json) := {
	"resource_changes": [{
		"address": "aws_iam_role_policy.lambda_inline",
		"type": "aws_iam_role_policy",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "intake-data-access",
				"policy": policy_json,
			},
		},
	}],
}

# Passing fixtures: should produce zero denies.
test_iam_specific_actions_no_denies if {
	count(deny) == 0 with input as _fixture(_policy_specific)
}

test_iam_action_prefix_no_denies if {
	count(deny) == 0 with input as _fixture(_policy_with_action_prefix)
}

# Failing fixtures: should produce denies.
test_iam_ddb_wildcard_denies if {
	count(deny) > 0 with input as _fixture(_policy_with_ddb_wildcard)
}

test_iam_s3_wildcard_in_array_denies if {
	count(deny) > 0 with input as _fixture(_policy_with_s3_wildcard_in_array)
}

test_iam_full_wildcard_denies if {
	count(deny) > 0 with input as _fixture(_policy_with_full_wildcard)
}