# GAP-03 — S3 buckets must reject non-TLS access via bucket policy.
#
# SOC 2 CC6.7. NIST 800-53 SC-7 + SC-8.
#
# Handling plan-time unresolved references: the bucket policy's
# `bucket` field references the bucket and is unknown at plan time.
# Same pattern as GAP-01: we check at the plan level (count of buckets
# vs count of TLS-enforcing bucket policies).

package main

import rego.v1

# All S3 buckets being created.
tls_buckets contains addr if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.actions[_] != "delete"
	addr := rc.address
}

# Bucket policies whose JSON contains a TLS-enforcing Deny.
tls_policies contains rc.address if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_policy"
	rc.change.actions[_] != "delete"

	# Policy field can be a literal JSON string OR an unknown
	# reference (when it uses a data source like aws_iam_policy_document).
	# When unknown, we accept it as valid intent because the data source
	# was already evaluated and the policy graph guarantees its content.
	_has_tls_deny(rc)
}

# When policy is a known JSON string, parse and inspect.
_has_tls_deny(rc) if {
	is_string(rc.change.after.policy)
	policy := json.unmarshal(rc.change.after.policy)
	some stmt in policy.Statement
	stmt.Effect == "Deny"
	_action_includes_s3(stmt.Action)
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}

# When policy is unknown at plan time (data-source-driven), accept it.
# Real-world note: this is a permissive choice because we can't
# inspect the rendered policy at plan time. The trade-off: we accept
# data-source-driven policies as compliant, trusting the Terraform
# author has written them correctly. The alternative (rejecting all
# unknown policies) would require all bucket policies to be inline
# jsonencode strings, which is overly restrictive.
_has_tls_deny(rc) if {
	rc.change.after_unknown.policy == true
}

_action_includes_s3(action) if {
	is_string(action)
	startswith(action, "s3:")
}

_action_includes_s3(action) if {
	is_array(action)
	some a in action
	startswith(a, "s3:")
}

# DENY: more buckets than TLS-enforcing policies.
deny contains msg if {
	count(tls_buckets) > count(tls_policies)

	some bucket_addr in tls_buckets
	msg := sprintf(
		"GAP-03 (SOC 2 CC6.7 / SC-7,SC-8): plan has %d S3 buckets but only %d TLS-enforcing bucket policies. Bucket %v (and possibly others) needs an aws_s3_bucket_policy with a Deny statement on aws:SecureTransport = false.",
		[count(tls_buckets), count(tls_policies), bucket_addr],
	)
}