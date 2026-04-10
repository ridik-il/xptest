# Configuration Reference

xptest is configured through an optional YAML file (default: `./xptest.yaml`). All CLI subcommands accept `--config <path>` to specify a custom location.

## Path Resolution

All relative paths in the config file resolve from the **config file's parent directory**, not the current working directory. This ensures portable configs regardless of where xptest is invoked.

```yaml
# If xptest.yaml is at /repo/platform/xptest.yaml
# then ./schemas/crds resolves to /repo/platform/schemas/crds
crd_bundle_path: ./schemas/crds
```

## Complete Reference

```yaml
# ─── Layer 1: Static Validation ───────────────────────────────

# Path to directory containing CRD YAML files.
# Used for schema validation (L1-01) and provider lock (L1-04).
# Each file should contain a CustomResourceDefinition with
# spec.versions[].schema.openAPIV3Schema.
# Default: "" (schema validation skipped)
crd_bundle_path: ./schemas/crds

# ─── Layer 3: Policy Compliance ───────────────────────────────

# Path to directory containing OPA Rego rule files.
# All .rego files in this directory are loaded.
# Rules must use the xptest.* package namespace.
# Default: "" (policy checks skipped)
rules_path: ./rules/aws

# Path or command name for the OPA binary.
# Default: "opa"
opa_binary: opa

# Expected OPA version string for reproducibility.
# Recorded in reports but not enforced at runtime.
# Default: ""
opa_expected_version: "0.68.0"

# ─── Rendering ────────────────────────────────────────────────

# Paths to EnvironmentConfig YAML fixtures.
# Passed to crossplane render via --environment-configs flag.
# Used when rendering Pipeline mode compositions.
# Default: []
environment_config_paths:
  - ./envconfig.yaml
  - ./envconfig-prod.yaml

# ─── Severity Overrides ──────────────────────────────────────

# Map of rule ID to severity level.
# Overrides the default severity for specific rules.
# Valid values: CRITICAL, WARNING, INFO
# Default: {}
severity_overrides:
  tag/mandatory-keys: CRITICAL
  net/sg-no-open-ssh: WARNING

# ─── Tagging ─────────────────────────────────────────────────

# List of tag keys that must be present on all taggable resources.
# Used by the tag/mandatory-keys OPA rule.
# Default: []
mandatory_tag_keys:
  - Environment
  - Owner
  - CostCenter

# ─── Extended Checks (Layer 6) ────────────────────────────────

# Resource kinds exempt from tag propagation checks.
# These kinds are skipped by L6-TAG-01.
# Default: ["DBClusterParameterGroup", "DBParameterGroup"]
tag_exempt_kinds:
  - DBClusterParameterGroup
  - DBParameterGroup

# Glob patterns for known provider config names.
# Used by L6-XCC-01 to avoid false positives on variant names.
# Default: ["providerconfig-aws*"]
known_provider_config_patterns:
  - "providerconfig-aws*"

# ─── Drift Detection (Stage 3) ───────────────────────────────

# AWS region for drift detection API calls.
# Can be overridden by --region CLI flag.
# Default: ""
aws_region: us-east-1

# Filter which resource kinds to check for drift.
# If empty, all supported kinds are checked.
# Supported: VPC, Subnet, SecurityGroup, RouteTable,
#            Bucket, DBInstance, DBSubnetGroup, Role
# Default: []
drift_resource_filter:
  - VPC
  - DBInstance

# ─── Behavioral Exploration (Stage 4) ────────────────────────

# Path to golden baseline JSON file.
# Used by breaking change detection to compare against.
# Generate with: xptest explore --save-baseline
# Default: ""
baseline_path: ./baselines/my-composition.json

# Maximum number of pairwise input combinations to generate.
# Controls the size of the seed suite in xptest explore.
# Default: 100
max_exploration_inputs: 100

# Minimum Go template branch coverage percentage.
# Set to 0 to disable enforcement.
# When set > 0 and coverage is below threshold, a WARNING finding is emitted.
# Default: 0.0
coverage_threshold: 80.0
```

## Field Summary

| Field | Type | Default | Used by |
|-------|------|---------|---------|
| `crd_bundle_path` | string | `""` | Layer 1 |
| `rules_path` | string | `""` | Layer 3 |
| `opa_binary` | string | `"opa"` | Layer 3 |
| `opa_expected_version` | string | `""` | Layer 3 |
| `environment_config_paths` | list[string] | `[]` | Loader (render) |
| `severity_overrides` | dict[string, string] | `{}` | Layer 3, Layer 4 |
| `mandatory_tag_keys` | list[string] | `[]` | Layer 3 (`tag/mandatory-keys`) |
| `tag_exempt_kinds` | list[string] | `["DBClusterParameterGroup", "DBParameterGroup"]` | Layer 6 (`L6-TAG-01`) |
| `known_provider_config_patterns` | list[string] | `["providerconfig-aws*"]` | Layer 6 (`L6-XCC-01`) |
| `aws_region` | string | `""` | Drift detection |
| `drift_resource_filter` | list[string] | `[]` | Drift detection |
| `baseline_path` | string | `""` | Exploration |
| `max_exploration_inputs` | int | `100` | Exploration |
| `coverage_threshold` | float | `0.0` | Exploration |

## Minimal Configs

### Layers 1-2 only (no OPA, no CRDs)

```yaml
# Empty config or no config file at all.
# Layers 1-2 run with built-in checks only.
# Schema validation (L1-01) and provider lock (L1-04) are skipped.
```

### Layers 1-3 with OPA

```yaml
rules_path: ./rules/aws
```

### Full validation with CRD bundle

```yaml
crd_bundle_path: ./schemas/provider-aws-v1.6.0
rules_path: ./rules/aws
mandatory_tag_keys:
  - Environment
  - Owner
```

### Drift detection

```yaml
aws_region: us-east-1
drift_resource_filter:
  - VPC
  - DBInstance
  - Bucket
```

### Exploration with baseline

```yaml
rules_path: ./rules/aws
baseline_path: ./baselines/vpc-network.json
max_exploration_inputs: 50
coverage_threshold: 80.0
environment_config_paths:
  - ./envconfig.yaml
```

## Environment Variables

xptest does not read environment variables directly. AWS credentials for drift detection are expected to be configured through standard AWS SDK mechanisms:

- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (local development)
- `AWS_WEB_IDENTITY_TOKEN_FILE` / `AWS_ROLE_ARN` (OIDC in CI)
- `~/.aws/credentials` (AWS CLI profiles)

## Config Errors

If the config file exists but contains invalid YAML or unrecognized severity values, xptest raises a `ConfigError` with a descriptive message and exits with code 1.

```bash
$ xptest validate --config broken.yaml ...
Error: invalid severity override 'FATAL' for rule 'enc/s3-sse' (expected CRITICAL, WARNING, or INFO)
```
