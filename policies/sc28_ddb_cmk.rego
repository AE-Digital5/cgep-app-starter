# GAP-02 — DynamoDB tables must use customer-managed KMS encryption.
#
# SOC 2 CC6.1. NIST 800-53 SC-28.
#
# Handling plan-time unresolved references: same pattern as GAP-01.
# The kms_key_arn is often a reference to aws_kms_key.phi.arn, which
# is unknown at plan time. We accept that as valid intent.

package main

import rego.v1

# DENY: any DynamoDB table with no server_side_encryption block AND
# no unknown-at-plan-time SSE configuration. The "no SSE block at all"
# state means defaults to AWS-owned key.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_dynamodb_table"
	rc.change.actions[_] != "delete"
	not _has_sse(rc.change)

	msg := sprintf(
		"GAP-02 (SOC 2 CC6.1 / SC-28): DynamoDB table %v has no server_side_encryption block; defaults to AWS-owned key. Add server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.phi.arn }.",
		[rc.address],
	)
}

# DENY: SSE explicitly disabled.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_dynamodb_table"
	rc.change.actions[_] != "delete"

	sse := rc.change.after.server_side_encryption[_]
	sse.enabled == false

	msg := sprintf(
		"GAP-02 (SOC 2 CC6.1 / SC-28): DynamoDB table %v has server_side_encryption.enabled = false.",
		[rc.address],
	)
}

# DENY: SSE enabled but no kms_key_arn (neither known nor unknown-at-plan-time).
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_dynamodb_table"
	rc.change.actions[_] != "delete"

	sse := rc.change.after.server_side_encryption[_]
	sse.enabled == true
	not _has_kms_key_arn(rc.change)

	msg := sprintf(
		"GAP-02 (SOC 2 CC6.1 / SC-28): DynamoDB table %v has SSE enabled but no kms_key_arn set (or coming via reference). Use kms_key_arn = aws_kms_key.phi.arn.",
		[rc.address],
	)
}

# Helpers
_has_sse(change) if {
	change.after.server_side_encryption
	count(change.after.server_side_encryption) > 0
}

_has_sse(change) if {
	change.after_unknown.server_side_encryption == true
}

_has_kms_key_arn(change) if {
	sse := change.after.server_side_encryption[_]
	sse.kms_key_arn
	sse.kms_key_arn != ""
}

_has_kms_key_arn(change) if {
	some unknown_sse in change.after_unknown.server_side_encryption
	unknown_sse.kms_key_arn == true
}