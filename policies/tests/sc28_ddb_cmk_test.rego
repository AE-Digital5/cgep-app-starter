# Tests for sc28_ddb_cmk.rego (GAP-02).

package main

import rego.v1

# Fixture: passing — table with SSE-KMS configured with CMK.
ddb_passing_plan := {
	"resource_changes": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "intake-submissions-12345",
				"server_side_encryption": [{
					"enabled": true,
					"kms_key_arn": "arn:aws:kms:us-east-1:000000000000:key/abc-123",
				}],
			},
		},
	}],
}

# Fixture: failing — table with no SSE block (defaults to AWS-owned key).
ddb_no_sse_plan := {
	"resource_changes": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {
			"actions": ["create"],
			"after": {"name": "intake-submissions-12345"},
		},
	}],
}

# Fixture: failing — table with SSE explicitly disabled.
ddb_sse_disabled_plan := {
	"resource_changes": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "intake-submissions-12345",
				"server_side_encryption": [{"enabled": false}],
			},
		},
	}],
}

# Fixture: failing — table with SSE enabled but no kms_key_arn (AWS-owned key).
ddb_sse_no_cmk_plan := {
	"resource_changes": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "intake-submissions-12345",
				"server_side_encryption": [{"enabled": true}],
			},
		},
	}],
}

test_ddb_passing_plan_has_no_denies if {
	count(deny) == 0 with input as ddb_passing_plan
}

test_ddb_no_sse_plan_denies if {
	count(deny) > 0 with input as ddb_no_sse_plan
}

test_ddb_sse_disabled_plan_denies if {
	count(deny) > 0 with input as ddb_sse_disabled_plan
}

test_ddb_sse_no_cmk_plan_denies if {
	count(deny) > 0 with input as ddb_sse_no_cmk_plan
}