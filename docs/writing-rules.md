# Writing Custom OPA Rules

xptest evaluates Crossplane Compositions against OPA Rego rules in **full-document mode** — all composed resources are passed as a single JSON input. This enables cross-resource rules that per-object scanners cannot enforce.

## Rule Location

Place `.rego` files in the directory configured via `rules_path` in `xptest.yaml`:

```yaml
rules_path: ./rules/aws
```

All `.rego` files in this directory are loaded during Layer 3 evaluation.

## Package Namespace

Rules must use the `xptest.*` package namespace. The package suffix determines the rule category:

```rego
package xptest.encryption      # Built-in: encryption rules
package xptest.network         # Built-in: network rules
package xptest.iam             # Built-in: IAM rules
package xptest.cross_resource  # Built-in: cross-resource rules
package xptest.tagging         # Built-in: tagging rules
package xptest.custom          # Your custom rules
package xptest.myteam          # Any name under xptest.*
```

## Input Schema

The input document has this structure:

```json
{
  "resources": [
    {
      "name": "my-vpc",
      "apiVersion": "ec2.aws.upbound.io/v1beta1",
      "kind": "VPC",
      "spec": {
        "forProvider": {
          "region": "us-east-1",
          "cidrBlock": "10.0.0.0/16",
          "enableDnsSupport": true,
          "tags": {
            "Environment": "production"
          }
        }
      },
      "patches": [...],
      "readinessChecks": [...]
    },
    {
      "name": "my-subnet",
      "apiVersion": "ec2.aws.upbound.io/v1beta1",
      "kind": "Subnet",
      "spec": {
        "forProvider": {
          "region": "us-east-1",
          "cidrBlock": "10.0.1.0/24",
          "vpcIdRef": { "name": "my-vpc" }
        }
      }
    }
  ]
}
```

Each resource in `input.resources[]` is a composed resource extracted from the Composition YAML. The `spec` field mirrors the resource's `spec` block in the composition.

## Violation Schema

Rules produce violations as a set comprehension. Each violation must be an object with these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rule` | string | yes | Rule identifier (e.g., `"custom/bucket-needs-tags"`) |
| `resource` | string | yes | Resource name that triggered the violation |
| `path` | string | yes | Dot-path to the offending field |
| `severity` | string | yes | `"CRITICAL"`, `"WARNING"`, or `"INFO"` |
| `message` | string | yes | Human-readable explanation |
| `remediation` | string | yes | How to fix the issue |

The rule set must be named `violations`:

```rego
violations[v] {
    # ... rule logic ...
    v := {
        "rule": "category/rule-name",
        "resource": resource.name,
        "path": "spec.forProvider.fieldName",
        "severity": "WARNING",
        "message": "Description of what is wrong",
        "remediation": "How to fix it"
    }
}
```

## Examples

### Single-resource rule: require encryption on S3 buckets

```rego
package xptest.custom

violations[v] {
    resource := input.resources[_]
    resource.kind == "Bucket"
    not resource.spec.forProvider.serverSideEncryptionConfiguration
    v := {
        "rule": "custom/s3-needs-encryption",
        "resource": resource.name,
        "path": "spec.forProvider.serverSideEncryptionConfiguration",
        "severity": "CRITICAL",
        "message": sprintf("S3 bucket '%s' has no server-side encryption configured", [resource.name]),
        "remediation": "Add serverSideEncryptionConfiguration with AES256 or aws:kms algorithm."
    }
}
```

### Single-resource rule: enforce minimum RDS instance class

```rego
package xptest.custom

_allowed_classes := {"db.t3.medium", "db.t3.large", "db.r5.large", "db.r5.xlarge"}

violations[v] {
    resource := input.resources[_]
    resource.kind == "DBInstance"
    cls := resource.spec.forProvider.instanceClass
    not _allowed_classes[cls]
    v := {
        "rule": "custom/rds-min-instance-class",
        "resource": resource.name,
        "path": "spec.forProvider.instanceClass",
        "severity": "WARNING",
        "message": sprintf("RDS instance '%s' uses class '%s' which is not in the approved list", [resource.name, cls]),
        "remediation": sprintf("Use one of: %v", [_allowed_classes])
    }
}
```

### Cross-resource rule: subnet must reference a VPC in the same composition

```rego
package xptest.custom

# Collect all VPC names in the composition
_vpc_names[name] {
    resource := input.resources[_]
    resource.kind == "VPC"
    name := resource.name
}

violations[v] {
    resource := input.resources[_]
    resource.kind == "Subnet"
    ref := resource.spec.forProvider.vpcIdRef.name
    not _vpc_names[ref]
    v := {
        "rule": "custom/subnet-vpc-ref",
        "resource": resource.name,
        "path": "spec.forProvider.vpcIdRef.name",
        "severity": "CRITICAL",
        "message": sprintf("Subnet '%s' references VPC '%s' which is not in this composition", [resource.name, ref]),
        "remediation": "Ensure the VPC resource exists in the composition or use vpcIdSelector instead."
    }
}
```

### Cross-resource rule: security group port must match RDS port

```rego
package xptest.custom

violations[v] {
    sg := input.resources[_]
    sg.kind == "SecurityGroup"

    db := input.resources[_]
    db.kind == "DBInstance"

    # Check if SG has an ingress rule for the DB port
    rule := sg.spec.forProvider.ingress[_]
    db_port := db.spec.forProvider.port

    rule.fromPort != db_port
    rule.toPort != db_port

    v := {
        "rule": "custom/sg-rds-port-mismatch",
        "resource": sg.name,
        "path": "spec.forProvider.ingress",
        "severity": "CRITICAL",
        "message": sprintf("SecurityGroup '%s' does not allow traffic on RDS port %d", [sg.name, db_port]),
        "remediation": sprintf("Add an ingress rule allowing port %d for the RDS instance.", [db_port])
    }
}
```

## Severity Overrides

Default severities defined in Rego can be overridden in `xptest.yaml`:

```yaml
severity_overrides:
  custom/s3-needs-encryption: WARNING    # downgrade from CRITICAL
  custom/rds-min-instance-class: CRITICAL  # upgrade from WARNING
```

The override applies after OPA evaluation, replacing the severity in the Finding object.

## Testing Rules

### With OPA CLI directly

```bash
# Create a test input
cat > /tmp/test-input.json << 'EOF'
{
  "resources": [
    {
      "name": "test-bucket",
      "kind": "Bucket",
      "apiVersion": "s3.aws.upbound.io/v1beta1",
      "spec": {
        "forProvider": {
          "region": "us-east-1"
        }
      }
    }
  ]
}
EOF

# Evaluate your rule
opa eval \
  -d rules/aws/ \
  -i /tmp/test-input.json \
  'data.xptest.custom.violations'
```

### With xptest

```bash
xptest validate \
  --composition fixtures/policy-violations/s3-no-encryption.yaml \
  --xrd fixtures/xrd.yaml \
  --config xptest.yaml
```

### With pytest

Create a test fixture composition with the expected violation, add an `expected.json` alongside it, and run the evaluation suite:

```bash
pytest tests/test_evaluation.py -v
```

## Built-in Rules Reference

| Rule ID | Package | Description |
|---------|---------|-------------|
| `enc/s3-sse` | `xptest.encryption` | S3 bucket must have server-side encryption |
| `enc/rds-encrypted` | `xptest.encryption` | RDS instance must have storage encryption enabled |
| `net/sg-no-open-ssh` | `xptest.network` | Security group must not allow 0.0.0.0/0 on port 22 |
| `net/sg-no-open-db` | `xptest.network` | Security group must not allow 0.0.0.0/0 on DB ports |
| `net/rds-not-public` | `xptest.network` | RDS instance must not be publicly accessible |
| `net/s3-public-block` | `xptest.network` | S3 bucket must have public access block enabled |
| `iam/no-wildcard-action` | `xptest.iam` | IAM policy must not use `Action: "*"` |
| `iam/no-wildcard-resource` | `xptest.iam` | IAM policy must not use `Resource: "*"` |
| `iam/trust-service-match` | `xptest.iam` | Trust policy service must match the resource's purpose |
| `cross/kms-key-consistency` | `xptest.cross_resource` | Resources sharing a KMS key must reference the same key |
| `cross/iam-rds-trust` | `xptest.cross_resource` | RDS-associated IAM role must trust `rds.amazonaws.com` |
| `cross/sg-rds-port-match` | `xptest.cross_resource` | Security group must allow the RDS instance's port |
| `tag/mandatory-keys` | `xptest.tagging` | All taggable resources must have required tag keys |

## Tips

- **Use `sprintf`** for dynamic messages — it makes findings actionable.
- **Use helper sets** (like `_vpc_names` above) to collect resources by kind for cross-resource rules.
- **Test with `opa eval` first** before running through xptest — faster iteration cycle.
- **One violation per resource** — if a resource violates multiple aspects of the same rule, emit separate violations with distinct paths.
- **Keep rule IDs stable** — changing a rule ID breaks severity overrides and evaluation fixtures.
