# encryption.rego — Encryption-at-rest policy rules (CRITICAL)
#
# Rules:
#   enc/s3-sse         S3 buckets must have server-side encryption enabled.
#   enc/rds-encrypted  RDS instances must have storageEncrypted set to true.
#
# Input: full composition graph as JSON (all composed resources).

package xptest.encryption

import rego.v1

# enc/s3-sse: S3 bucket must have server-side encryption configured
violations[result] if {
	some r in input.resources
	r.kind == "Bucket"
	spec := r.spec.forProvider

	# No encryption configuration present
	not spec.serverSideEncryptionConfiguration
	not _has_sse_rule(spec)

	result := {
		"rule": "enc/s3-sse",
		"resource": r.name,
		"path": "spec.forProvider.serverSideEncryptionConfiguration",
		"severity": "CRITICAL",
		"message": sprintf("S3 bucket '%s' does not have server-side encryption configured.", [r.name]),
		"remediation": "Add serverSideEncryptionConfiguration with AES256 or aws:kms to the bucket spec.",
	}
}

# enc/rds-encrypted: RDS instance must have storageEncrypted = true
violations[result] if {
	some r in input.resources
	r.kind == "DBInstance"
	spec := r.spec.forProvider
	not spec.storageEncrypted

	result := {
		"rule": "enc/rds-encrypted",
		"resource": r.name,
		"path": "spec.forProvider.storageEncrypted",
		"severity": "CRITICAL",
		"message": sprintf("RDS instance '%s' does not have storage encryption enabled.", [r.name]),
		"remediation": "Set storageEncrypted: true in the DBInstance spec.",
	}
}

_has_sse_rule(spec) if {
	spec.serverSideEncryptionConfiguration.rules
}
