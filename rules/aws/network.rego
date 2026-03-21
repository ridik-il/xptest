# network.rego — Network isolation policy rules (CRITICAL)
#
# Rules:
#   net/sg-no-open-ssh     Security groups must not allow 0.0.0.0/0 on port 22.
#   net/sg-no-open-db      Security groups must not allow 0.0.0.0/0 on common DB ports.
#   net/rds-not-public     RDS instances must not be publicly accessible.
#   net/s3-public-block    S3 buckets must have public access block configured.
#
# Input: full composition graph as JSON.

package xptest.network

import rego.v1

_open_cidrs := {"0.0.0.0/0", "::/0"}
_db_ports := {3306, 5432, 1433, 1521, 27017}

# net/sg-no-open-ssh: no SSH from 0.0.0.0/0
violations[result] if {
	some r in input.resources
	r.kind == "SecurityGroup"
	some rule in r.spec.forProvider.ingress
	rule.fromPort <= 22
	rule.toPort >= 22
	some cidr in rule.ipRanges
	cidr.cidrIp in _open_cidrs

	result := {
		"rule": "net/sg-no-open-ssh",
		"resource": r.name,
		"path": "spec.forProvider.ingress",
		"severity": "CRITICAL",
		"message": sprintf("Security group '%s' allows SSH (port 22) from %s.", [r.name, cidr.cidrIp]),
		"remediation": "Restrict SSH access to specific CIDR ranges or remove the ingress rule.",
	}
}

# net/sg-no-open-db: no common DB ports from 0.0.0.0/0
violations[result] if {
	some r in input.resources
	r.kind == "SecurityGroup"
	some rule in r.spec.forProvider.ingress
	some port in _db_ports
	rule.fromPort <= port
	rule.toPort >= port
	some cidr in rule.ipRanges
	cidr.cidrIp in _open_cidrs

	result := {
		"rule": "net/sg-no-open-db",
		"resource": r.name,
		"path": "spec.forProvider.ingress",
		"severity": "CRITICAL",
		"message": sprintf("Security group '%s' allows database port %d from %s.", [r.name, port, cidr.cidrIp]),
		"remediation": sprintf("Restrict port %d access to specific CIDR ranges or VPC-internal sources.", [port]),
	}
}

# net/rds-not-public: RDS must not be publicly accessible
violations[result] if {
	some r in input.resources
	r.kind == "DBInstance"
	r.spec.forProvider.publiclyAccessible == true

	result := {
		"rule": "net/rds-not-public",
		"resource": r.name,
		"path": "spec.forProvider.publiclyAccessible",
		"severity": "CRITICAL",
		"message": sprintf("RDS instance '%s' is set to publicly accessible.", [r.name]),
		"remediation": "Set publiclyAccessible: false in the DBInstance spec.",
	}
}

# net/s3-public-block: S3 bucket must have public access block
violations[result] if {
	some r in input.resources
	r.kind == "Bucket"
	spec := r.spec.forProvider
	not _has_public_access_block(spec)

	result := {
		"rule": "net/s3-public-block",
		"resource": r.name,
		"path": "spec.forProvider.publicAccessBlockConfiguration",
		"severity": "CRITICAL",
		"message": sprintf("S3 bucket '%s' does not have public access block configured.", [r.name]),
		"remediation": "Add publicAccessBlockConfiguration with all four block settings set to true.",
	}
}

_has_public_access_block(spec) if {
	spec.publicAccessBlockConfiguration.blockPublicAcls == true
}

_has_public_access_block(spec) if {
	spec.publicAccessBlockConfiguration.blockPublicPolicy == true
}
