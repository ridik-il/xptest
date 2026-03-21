# tagging.rego — Tagging policy rules (WARNING by default)
#
# Rules:
#   tag/mandatory-keys   Each resource with a tags field must include all
#                        mandatory tag keys specified in the config.
#
# Input: full composition graph as JSON.
#        input.config.mandatory_tag_keys: list of required tag keys.

package xptest.tagging

import rego.v1

# tag/mandatory-keys: check that all mandatory tags are present
violations[result] if {
	some r in input.resources
	tags := r.spec.forProvider.tags
	tags != null

	some required_key in input.config.mandatory_tag_keys
	not _has_tag(tags, required_key)

	result := {
		"rule": "tag/mandatory-keys",
		"resource": r.name,
		"path": "spec.forProvider.tags",
		"severity": "WARNING",
		"message": sprintf("Resource '%s' is missing mandatory tag '%s'.", [r.name, required_key]),
		"remediation": sprintf("Add tag '%s' to the resource's tags.", [required_key]),
	}
}

_has_tag(tags, key) if {
	_ = tags[key]
}
