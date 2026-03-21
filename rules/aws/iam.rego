# iam.rego — IAM least-privilege policy rules (CRITICAL)
#
# Rules:
#   iam/no-wildcard-action     IAM policies must not use Action: "*".
#   iam/no-wildcard-resource   IAM policies must not use Resource: "*" with Allow.
#   iam/trust-service-match    IAM trust policy principal service must be a known AWS service.
#
# Input: full composition graph as JSON.

package xptest.iam

import rego.v1

# Known AWS service principals that are valid in trust policies.
_known_service_principals := {
	"ec2.amazonaws.com",
	"ecs-tasks.amazonaws.com",
	"lambda.amazonaws.com",
	"rds.amazonaws.com",
	"s3.amazonaws.com",
	"sts.amazonaws.com",
	"elasticmapreduce.amazonaws.com",
	"eks.amazonaws.com",
	"states.amazonaws.com",
	"events.amazonaws.com",
	"sns.amazonaws.com",
	"sqs.amazonaws.com",
	"logs.amazonaws.com",
	"cloudformation.amazonaws.com",
	"apigateway.amazonaws.com",
	"codebuild.amazonaws.com",
	"codepipeline.amazonaws.com",
}

# iam/no-wildcard-action: policies must not use Action: "*"
violations[result] if {
	some r in input.resources
	r.kind == "Role"
	policy_doc := r.spec.forProvider.assumeRolePolicyDocument
	policy := json.unmarshal(policy_doc)
	some stmt in policy.Statement
	_has_wildcard_action(stmt)

	result := {
		"rule": "iam/no-wildcard-action",
		"resource": r.name,
		"path": "spec.forProvider.assumeRolePolicyDocument",
		"severity": "CRITICAL",
		"message": sprintf("IAM role '%s' has a policy statement with Action: '*'.", [r.name]),
		"remediation": "Replace wildcard Action with specific actions following least-privilege.",
	}
}

# Also check inline policies if present
violations[result] if {
	some r in input.resources
	r.kind == "Policy"
	policy_doc := r.spec.forProvider.policy
	policy := json.unmarshal(policy_doc)
	some stmt in policy.Statement
	_has_wildcard_action(stmt)

	result := {
		"rule": "iam/no-wildcard-action",
		"resource": r.name,
		"path": "spec.forProvider.policy",
		"severity": "CRITICAL",
		"message": sprintf("IAM policy '%s' has a statement with Action: '*'.", [r.name]),
		"remediation": "Replace wildcard Action with specific actions following least-privilege.",
	}
}

# iam/no-wildcard-resource: Allow statements must not use Resource: "*"
violations[result] if {
	some r in input.resources
	r.kind == "Policy"
	policy_doc := r.spec.forProvider.policy
	policy := json.unmarshal(policy_doc)
	some stmt in policy.Statement
	stmt.Effect == "Allow"
	_has_wildcard_resource(stmt)

	result := {
		"rule": "iam/no-wildcard-resource",
		"resource": r.name,
		"path": "spec.forProvider.policy",
		"severity": "CRITICAL",
		"message": sprintf("IAM policy '%s' has an Allow statement with Resource: '*'.", [r.name]),
		"remediation": "Scope the Resource field to specific ARNs or ARN patterns.",
	}
}

# iam/trust-service-match: trust policy service principal must be known
violations[result] if {
	some r in input.resources
	r.kind == "Role"
	policy_doc := r.spec.forProvider.assumeRolePolicyDocument
	policy := json.unmarshal(policy_doc)
	some stmt in policy.Statement
	stmt.Effect == "Allow"
	service := stmt.Principal.Service
	is_string(service)
	not service in _known_service_principals

	result := {
		"rule": "iam/trust-service-match",
		"resource": r.name,
		"path": "spec.forProvider.assumeRolePolicyDocument",
		"severity": "WARNING",
		"message": sprintf("IAM role '%s' trusts service principal '%s' which is not in the known-services list.", [r.name, service]),
		"remediation": sprintf("Verify that '%s' is the correct service principal for this trust relationship.", [service]),
	}
}

_has_wildcard_action(stmt) if {
	stmt.Action == "*"
}

_has_wildcard_action(stmt) if {
	some a in stmt.Action
	a == "*"
}

_has_wildcard_resource(stmt) if {
	stmt.Resource == "*"
}

_has_wildcard_resource(stmt) if {
	some r in stmt.Resource
	r == "*"
}
