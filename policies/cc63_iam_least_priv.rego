# GAP-07 — IAM role policies must not grant service-wide wildcards.
#
# SOC 2 CC6.3 (Privileged access / Least privilege).
# NIST 800-53 control reference: AC-6 (Least Privilege).
#
# The starter ships its Lambda's inline IAM policy with dynamodb:* and
# s3:* on the workload's resources. Even though the resources are
# scoped, action wildcards grant the Lambda role far more permission
# than the handler code uses (handler.py only does PutItem and
# PutObject). Compromising the Lambda would let an attacker delete,
# enumerate, or modify data not just write new records.
#
# This policy defines "service-wide wildcard" as:
#   - Action = "*"           (full wildcard)
#   - Action = "service:*"   (e.g. "dynamodb:*", "s3:*", "kms:*")
#
# Action-prefix patterns like "s3:Get*" or "dynamodb:Describe*" are
# allowed — they bound the action surface to a documented category
# even if specific actions vary. Production teams sometimes need this
# breadth for legitimate reasons (e.g., describing all resources for
# inventory tooling); rejecting them would be too strict.
#
# Tested via: policies/tests/cc63_iam_least_priv_test.rego

package main

import rego.v1

# Iterate over every IAM role policy resource being created/updated.
# For each, parse the JSON policy and check every Statement's Action.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role_policy"
	rc.change.actions[_] != "delete"

	policy := json.unmarshal(rc.change.after.policy)
	some stmt in policy.Statement
	stmt.Effect == "Allow"

	action := _service_wide_wildcard(stmt.Action)

	msg := sprintf(
		"GAP-07 (SOC 2 CC6.3 / AC-6): IAM role policy %v grants Allow on service-wide wildcard action %q. Use specific actions (e.g. dynamodb:PutItem) or action-prefix patterns (e.g. dynamodb:Get*) instead.",
		[rc.address, action],
	)
}

# Returns the offending action string when Action is a service-wide
# wildcard. Handles both string and array Action forms.

# String form: Action = "s3:*" or Action = "*"
_service_wide_wildcard(action) := action if {
	is_string(action)
	_is_service_wildcard(action)
}

# Array form: Action = ["s3:GetObject", "s3:*"] — return the first offender
_service_wide_wildcard(actions) := offender if {
	is_array(actions)
	some a in actions
	_is_service_wildcard(a)
	offender := a
}

# An action is a service wildcard if it's exactly "*" or matches "<service>:*"
_is_service_wildcard(action) if {
	action == "*"
}

_is_service_wildcard(action) if {
	endswith(action, ":*")
}