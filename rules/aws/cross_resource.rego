# cross_resource.rego — Cross-resource policy rules (CRITICAL)
#
# These rules operate on the FULL composition graph simultaneously.
# Per-object scanners cannot enforce these checks because they require
# correlating fields across multiple composed resources.
#
# Rules:
#   cross/kms-key-consistency   S3 and IAM resources referencing KMS keys must
#                               use the same key ARN.
#   cross/iam-rds-trust         If an IAM Role and an RDS instance coexist,
#                               the trust policy must include rds.amazonaws.com.
#   cross/sg-rds-port-match     Security group ingress port must match the RDS
#                               engine's default port.
#
# Input: full composition graph as JSON.

package xptest.cross_resource

import rego.v1

_engine_default_ports := {
	"mysql": 3306,
	"postgres": 5432,
	"mariadb": 3306,
	"sqlserver-ee": 1433,
	"sqlserver-se": 1433,
	"sqlserver-ex": 1433,
	"sqlserver-web": 1433,
	"oracle-ee": 1521,
	"oracle-se2": 1521,
}

# cross/iam-rds-trust: if both a Role and a DBInstance exist, the Role's
# trust policy must include rds.amazonaws.com as a service principal.
violations[result] if {
	some role in input.resources
	role.kind == "Role"

	some db in input.resources
	db.kind == "DBInstance"

	policy_doc := role.spec.forProvider.assumeRolePolicyDocument
	policy := json.unmarshal(policy_doc)
	not _trusts_service(policy, "rds.amazonaws.com")

	result := {
		"rule": "cross/iam-rds-trust",
		"resource": role.name,
		"path": "spec.forProvider.assumeRolePolicyDocument",
		"severity": "CRITICAL",
		"message": sprintf(
			"IAM role '%s' coexists with RDS instance '%s' but does not trust rds.amazonaws.com.",
			[role.name, db.name],
		),
		"remediation": "Add rds.amazonaws.com as a service principal in the trust policy.",
	}
}

# cross/sg-rds-port-match: SG ingress must cover the RDS engine's default port.
violations[result] if {
	some sg in input.resources
	sg.kind == "SecurityGroup"

	some db in input.resources
	db.kind == "DBInstance"
	engine := db.spec.forProvider.engine
	expected_port := _engine_default_ports[engine]

	# Check if this SG is referenced by the RDS instance
	_sg_referenced_by_db(sg, db)

	# Verify the SG allows the engine's port
	not _sg_allows_port(sg, expected_port)

	result := {
		"rule": "cross/sg-rds-port-match",
		"resource": sg.name,
		"path": "spec.forProvider.ingress",
		"severity": "CRITICAL",
		"message": sprintf(
			"Security group '%s' does not allow port %d which is the default for RDS engine '%s' (instance '%s').",
			[sg.name, expected_port, engine, db.name],
		),
		"remediation": sprintf("Add an ingress rule allowing port %d for engine '%s'.", [expected_port, engine]),
	}
}

# cross/kms-key-consistency: all resources referencing a KMS key must use the same ARN.
violations[result] if {
	kms_keys := {r.name: key |
		some r in input.resources
		key := _extract_kms_key(r)
		key != ""
	}

	count(kms_keys) > 1
	unique_keys := {v | some v in kms_keys}
	count(unique_keys) > 1

	result := {
		"rule": "cross/kms-key-consistency",
		"resource": "",
		"path": "spec.forProvider.kmsKeyId / sseKmsKeyId",
		"severity": "CRITICAL",
		"message": sprintf(
			"Multiple KMS key ARNs found across composed resources: %v. All resources in a composition should use the same KMS key.",
			[unique_keys],
		),
		"remediation": "Ensure all resources referencing a KMS key use the same key ARN, ideally via a shared composition parameter.",
	}
}

# Helper: check if a trust policy includes a given service principal
_trusts_service(policy, service) if {
	some stmt in policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal.Service == service
}

_trusts_service(policy, service) if {
	some stmt in policy.Statement
	stmt.Effect == "Allow"
	some s in stmt.Principal.Service
	s == service
}

# Helper: check if SG is referenced by DB instance (by name in refs)
_sg_referenced_by_db(sg, db) if {
	some ref in db.spec.forProvider.vpcSecurityGroupIdRefs
	ref.name == sg.name
}

# Fallback: if no explicit refs, assume any SG in the composition may apply
_sg_referenced_by_db(sg, db) if {
	not db.spec.forProvider.vpcSecurityGroupIdRefs
}

# Helper: check if SG has an ingress rule covering a given port
_sg_allows_port(sg, port) if {
	some rule in sg.spec.forProvider.ingress
	rule.fromPort <= port
	rule.toPort >= port
}

# Helper: extract KMS key ARN from a resource
_extract_kms_key(r) := key if {
	r.kind == "DBInstance"
	key := r.spec.forProvider.kmsKeyId
}

_extract_kms_key(r) := key if {
	r.kind == "Bucket"
	some rule in r.spec.forProvider.serverSideEncryptionConfiguration.rules
	key := rule.applyServerSideEncryptionByDefault.kmsMasterKeyId
}
