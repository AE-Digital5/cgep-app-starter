# Tests for cc66_lambda_vpc.rego (GAP-05).

package main

import rego.v1

# Fixture: passing — Lambda with full VPC config.
lambda_passing_plan := {
	"resource_changes": [{
		"address": "aws_lambda_function.intake",
		"type": "aws_lambda_function",
		"change": {
			"actions": ["create"],
			"after": {
				"function_name": "intake-handler-12345",
				"vpc_config": [{
					"subnet_ids": ["subnet-aaa", "subnet-bbb"],
					"security_group_ids": ["sg-xyz"],
				}],
			},
		},
	}],
}

# Fixture: failing — Lambda with no vpc_config at all.
lambda_no_vpc_plan := {
	"resource_changes": [{
		"address": "aws_lambda_function.intake",
		"type": "aws_lambda_function",
		"change": {
			"actions": ["create"],
			"after": {"function_name": "intake-handler-12345"},
		},
	}],
}

# Fixture: failing — vpc_config present but subnet_ids empty.
lambda_empty_subnets_plan := {
	"resource_changes": [{
		"address": "aws_lambda_function.intake",
		"type": "aws_lambda_function",
		"change": {
			"actions": ["create"],
			"after": {
				"function_name": "intake-handler-12345",
				"vpc_config": [{
					"subnet_ids": [],
					"security_group_ids": ["sg-xyz"],
				}],
			},
		},
	}],
}

# Fixture: failing — vpc_config present but security_group_ids empty.
lambda_empty_sgs_plan := {
	"resource_changes": [{
		"address": "aws_lambda_function.intake",
		"type": "aws_lambda_function",
		"change": {
			"actions": ["create"],
			"after": {
				"function_name": "intake-handler-12345",
				"vpc_config": [{
					"subnet_ids": ["subnet-aaa"],
					"security_group_ids": [],
				}],
			},
		},
	}],
}

test_lambda_passing_plan_has_no_denies if {
	count(deny) == 0 with input as lambda_passing_plan
}

test_lambda_no_vpc_plan_denies if {
	count(deny) > 0 with input as lambda_no_vpc_plan
}

test_lambda_empty_subnets_plan_denies if {
	count(deny) > 0 with input as lambda_empty_subnets_plan
}

test_lambda_empty_sgs_plan_denies if {
	count(deny) > 0 with input as lambda_empty_sgs_plan
}