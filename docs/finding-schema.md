# Finding Schema Reference

All xptest outputs share a common finding format. This document describes the schema, severity levels, exit codes, and the complete rule catalog.

## Finding Object

Every finding is a JSON object with these fields:

```json
{
  "layer": 2,
  "rule": "L2-02/cycle",
  "resource": "vpc",
  "path": "spec.forProvider.vpcId",
  "severity": "CRITICAL",
  "message": "Cycle detected: vpc -> subnet -> vpc",
  "remediation": "Break the circular dependency by removing one edge."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `layer` | integer | Validation layer that produced the finding (1-4, 6 for extended checks, or 7 for exploration) |
| `rule` | string | Unique rule identifier (e.g., `L1-01/schema`, `enc/s3-sse`, `bc/resource-removed`) |
| `resource` | string | Name of the composed resource, or `""` for composition-level findings |
| `path` | string | Dot-path to the offending field (e.g., `spec.forProvider.encryption`) |
| `severity` | string | `CRITICAL`, `WARNING`, or `INFO` |
| `message` | string | Human-readable explanation of the finding |
| `remediation` | string | Suggested fix |

### Optional fields

These fields appear in findings from specific modules:

| Field | Type | Appears in | Description |
|-------|------|-----------|-------------|
| `finding_id` | string | All | Auto-generated unique ID |
| `category` | string | Layer 3 | OPA rule category |
| `case_id` | string | Exploration | Input case that triggered the finding |
| `baseline_case_id` | string | Breaking change | Baseline case for comparison |
| `perturbation_id` | string | Chaos/perturbation | Perturbation that triggered the finding |
| `evidence` | object | Various | Additional structured data |

## Severity Levels

| Level | Meaning | Exit code impact | CI behavior |
|-------|---------|-----------------|-------------|
| `CRITICAL` | Must fix before merge. Structural error or security violation. | Exit 1 | Blocks PR |
| `WARNING` | Should investigate. May indicate a problem but not definitively wrong. | Exit 0 | Passes PR |
| `INFO` | Informational. Included in reports for completeness. | Exit 0 | Passes PR |

### Severity overrides

Default severities can be overridden in `xptest.yaml`:

```yaml
severity_overrides:
  tag/mandatory-keys: CRITICAL   # Upgrade from WARNING
  net/sg-no-open-ssh: WARNING    # Downgrade from CRITICAL
```

## Exit Codes

| Code | Condition |
|------|-----------|
| `0` | No CRITICAL findings across all layers |
| `1` | At least one CRITICAL finding |

## Output Files

| Subcommand | Default output | Content |
|-----------|---------------|---------|
| `xptest validate` | `findings.json` | Array of Finding objects |
| `xptest drift` | `drift-findings.json` | Array of DriftFinding objects |
| `xptest explore` | `exploration-report.json` | Exploration report with nested findings |

Override with `--output <path>`.

## Complete Rule Catalog

### Layer 1 — Static Validation

| Rule ID | Description | Default severity |
|---------|-------------|-----------------|
| `L1-01/schema` | Resource spec fails validation against CRD `openAPIV3Schema` | CRITICAL |
| `L1-02/field-path` | `fromFieldPath` or `toFieldPath` has invalid syntax | CRITICAL |
| `L1-03/duplicate-name` | Two composed resources share the same name | CRITICAL |
| `L1-04/provider-lock` | `apiVersion`/`kind` pair not found in CRD bundle | WARNING |
| `L1-05/deprecated` | Resource uses a deprecated field (stub) | INFO |

### Layer 2 — Dependency Validation

| Rule ID | Description | Default severity |
|---------|-------------|-----------------|
| `L2-01/ref-completeness` | Referenced `atProvider` field does not exist in producer CRD | WARNING |
| `L2-02/cycle` | Dependency graph contains a cycle | CRITICAL |
| `L2-03/dangling` | Patch reads from a resource not in the composition | CRITICAL |
| `L2-04/readiness` | Producer resource lacks a readiness check | CRITICAL |

### Layer 3 — Policy Compliance (OPA)

| Rule ID | Category | Description | Default severity |
|---------|----------|-------------|-----------------|
| `enc/s3-sse` | Encryption | S3 bucket missing server-side encryption | CRITICAL |
| `enc/rds-encrypted` | Encryption | RDS instance missing storage encryption | CRITICAL |
| `net/sg-no-open-ssh` | Network | Security group allows 0.0.0.0/0 on port 22 | CRITICAL |
| `net/sg-no-open-db` | Network | Security group allows 0.0.0.0/0 on DB ports | CRITICAL |
| `net/rds-not-public` | Network | RDS instance is publicly accessible | CRITICAL |
| `net/s3-public-block` | Network | S3 bucket missing public access block | CRITICAL |
| `iam/no-wildcard-action` | IAM | IAM policy uses `Action: "*"` | CRITICAL |
| `iam/no-wildcard-resource` | IAM | IAM policy uses `Resource: "*"` | CRITICAL |
| `iam/trust-service-match` | IAM | Trust policy service does not match resource purpose | CRITICAL |
| `cross/kms-key-consistency` | Cross-resource | Resources reference inconsistent KMS keys | CRITICAL |
| `cross/iam-rds-trust` | Cross-resource | RDS-associated IAM role does not trust `rds.amazonaws.com` | CRITICAL |
| `cross/sg-rds-port-match` | Cross-resource | Security group does not allow the RDS port | CRITICAL |
| `tag/mandatory-keys` | Tagging | Resource missing required tag keys | WARNING |

### Drift Detection

| Rule ID | Description | Default severity |
|---------|-------------|-----------------|
| `drift/field-mismatch` | Field value in AWS differs from desired state in composition | WARNING |

### Behavioral Exploration

| Rule ID | Description | Default severity |
|---------|-------------|-----------------|
| `bc/resource-removed` | Baseline resource absent from all current renders | CRITICAL |
| `bc/deletion-policy-escalated` | `deletionPolicy` changed from Orphan to Delete | CRITICAL |
| `bc/management-delete-added` | Delete verb added to `managementPolicies` | CRITICAL |
| `fi/resource-disappeared-under-fault` | Resource absent when another resource is faulted | WARNING |
| `fi/render-failed-under-fault` | Render fails entirely when a resource is faulted | WARNING |
| `inv/type-coverage` | Declared GVK absent from all renders | CRITICAL |
| `inv/deletion-policy-escalation` | Orphan to Delete escalation detected across renders | CRITICAL |
| `inv/minimum-resource-count` | Non-fault render produces fewer resources than baseline | WARNING |

### Layer 6 — Extended Checks

| Rule ID | Description | Default severity |
|---------|-------------|-----------------|
| `L6-ENV-01` | Structural or security-sensitive divergence across EnvironmentConfigs | WARNING / CRITICAL |
| `L6-NET-01` | SecurityGroup ingress CIDRs do not cover VPC subnet CIDRs | CRITICAL (WARNING if addDefaultIPRanges) |
| `L6-MRC-01` | Resources disappeared or count shrank across render cycles | CRITICAL / WARNING |
| `L6-DEL-01` | Resource deletionPolicy does not match XR deletionPolicy | WARNING |
| `L6-TAG-01` | Missing mandatory tags on AWS resources with forProvider | WARNING |
| `L6-XCC-01` | providerConfigRef not found in EnvironmentConfig known configs | WARNING |

### Offline Analysis (Logic + Chaos)

| Rule ID | Description | Default severity |
|---------|-------------|-----------------|
| `L5-H01/hash-dup` | Two inputs produce identical rendered graph hashes | INFO |
| `L5-H02/sig-dup` | Two inputs produce identical coverage signatures | INFO |
| `L5-D01/resource-appeared` | Nearby input causes a new resource to appear | WARNING |
| `L5-D02/resource-vanished` | Nearby input causes a resource to disappear | CRITICAL |
| `L5-D03/edge-appeared` | Nearby input creates a new dependency edge | INFO |
| `L5-D04/edge-vanished` | Nearby input removes a dependency edge | WARNING |
| `C1/deletion-policy-to-delete` | Perturbation changes deletion policy to Delete | CRITICAL |
| `C2/management-delete-added` | Perturbation adds Delete to management policies | CRITICAL |
| `C3/resource-removed` | Perturbation removes a resource | CRITICAL |
| `C4/critical-field-changed` | Perturbation changes a field on a critical resource | WARNING |
| `C5/resource-count-decreased` | Perturbation decreases total resource count | WARNING |

## Programmatic Access

Findings can be loaded in Python:

```python
import json

with open("findings.json") as f:
    findings = json.load(f)

critical = [f for f in findings if f["severity"] == "CRITICAL"]
print(f"{len(critical)} critical findings")
```

Or filtered with `jq`:

```bash
# Count critical findings
jq '[.[] | select(.severity == "CRITICAL")] | length' findings.json

# List all rule IDs
jq '[.[].rule] | unique' findings.json

# Show Layer 2 findings only
jq '[.[] | select(.layer == 2)]' findings.json
```
