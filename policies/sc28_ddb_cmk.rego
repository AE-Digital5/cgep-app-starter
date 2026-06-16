# GAP-02 — DynamoDB tables must use customer-managed KMS encryption.
#
# SOC 2 CC6.1 (Encryption at rest).
# NIST 800-53 control reference: SC-28 (Protection of Information at Rest).
#
# The starter ships its DynamoDB table with default encryption, which
# uses an AWS-owned key (not even an AWS-managed key — invisible in
# KMS, with no audit, rotation, or revocation capability).
#
# This policy enforces that every aws_dynamodb_table resource has:
#   - server_side_encryption.enabled = true
#   - server_side_encryption.kms_key_arn pointing at a customer-managed CMK
#
# A table with no server_side_encryption block at all fails: the
# default is "use AWS-owned key" which doesn't meet CC6.1 for PHI.
#
# Tested via: policies/tests/sc28_ddb_cmk_test.rego

package main

import rego.v1

# DENY: any DynamoDB table without a server_side_encryption block.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_dynamodb_table"
	rc.change.actions[_] != "delete"
	not rc.change.after.server_side_encryption

	msg := sprintf(
		"GAP-02 (SOC 2 CC6.1 / SC-28): DynamoDB table %v has no server_side_encryption block; defaults to AWS-owned key. Add server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.phi.arn }.",
		[rc.address],
	)
}

# DENY: any DynamoDB table where server_side_encryption is explicitly disabled.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_dynamodb_table"
	rc.change.actions[_] != "delete"

	sse := rc.change.after.server_side_encryption[_]
	sse.enabled == false

	msg := sprintf(
		"GAP-02 (SOC 2 CC6.1 / SC-28): DynamoDB table %v has server_side_encryption.enabled = false. PHI workloads require server-side encryption with a customer-managed key.",
		[rc.address],
	)
}

# DENY: any DynamoDB table that's encrypted but uses AWS-owned key (no kms_key_arn).
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_dynamodb_table"
	rc.change.actions[_] != "delete"

	sse := rc.change.after.server_side_encryption[_]
	sse.enabled == true
	not sse.kms_key_arn

	msg := sprintf(
		"GAP-02 (SOC 2 CC6.1 / SC-28): DynamoDB table %v has server-side encryption enabled but no kms_key_arn set; this uses the AWS-owned key. Specify kms_key_arn pointing at a customer-managed CMK.",
		[rc.address],
	)
}