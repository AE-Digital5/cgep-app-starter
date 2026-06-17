# GAP-05 — Lambda functions must be deployed inside a VPC.
#
# SOC 2 CC6.6 (Logical access / Network segmentation).
# NIST 800-53 control reference: SC-7 (Boundary Protection).
#
# The starter ships its Lambda function with no vpc_config block, which
# means it runs in AWS's managed Lambda network. For PHI workloads,
# Lambda should run inside the customer VPC so:
#   1. Egress is controlled by VPC routes (no internet by default if
#      subnets are private; AWS services reachable via VPC endpoints).
#   2. Network access is auditable via VPC Flow Logs.
#   3. Compromise of the Lambda doesn't grant access to the public
#      internet from a PHI-handling identity.
#
# This policy enforces that every aws_lambda_function has:
#   - A vpc_config block
#   - Non-empty subnet_ids (at least one private subnet)
#   - Non-empty security_group_ids (at least one SG)
#
# Tested via: policies/tests/cc66_lambda_vpc_test.rego

package main

import rego.v1

# DENY: any Lambda function with no vpc_config block.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_lambda_function"
	rc.change.actions[_] != "delete"

	not rc.change.after.vpc_config

	msg := sprintf(
		"GAP-05 (SOC 2 CC6.6 / SC-7): Lambda function %v has no vpc_config block. PHI-handling Lambdas must run inside the VPC. Add vpc_config { subnet_ids = [...], security_group_ids = [...] }.",
		[rc.address],
	)
}

# DENY: vpc_config present but subnet_ids is empty.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_lambda_function"
	rc.change.actions[_] != "delete"

	vpc_config := rc.change.after.vpc_config[_]
	count(vpc_config.subnet_ids) == 0

	msg := sprintf(
		"GAP-05 (SOC 2 CC6.6 / SC-7): Lambda function %v has vpc_config but no subnet_ids. Specify at least one private subnet.",
		[rc.address],
	)
}

# DENY: vpc_config present but security_group_ids is empty.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_lambda_function"
	rc.change.actions[_] != "delete"

	vpc_config := rc.change.after.vpc_config[_]
	count(vpc_config.security_group_ids) == 0

	msg := sprintf(
		"GAP-05 (SOC 2 CC6.6 / SC-7): Lambda function %v has vpc_config but no security_group_ids. Specify at least one security group.",
		[rc.address],
	)
}