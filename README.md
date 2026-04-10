# xptest

A modular validation framework for Crossplane Compositions in AWS environments.

xptest automates validation of functional and non-functional requirements of Crossplane Compositions through a four-layer sequential pipeline, a pull-based drift detector, and a behavioral exploration module for automated input discovery.

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | Installation, prerequisites, and first validation run |
| [Architecture](docs/architecture.md) | Four-layer pipeline design and module structure |
| [Configuration](docs/configuration.md) | Complete `xptest.yaml` field reference with examples |
| [Finding Schema](docs/finding-schema.md) | Output format, severity levels, exit codes, and full rule catalog |
| [Writing Custom OPA Rules](docs/writing-rules.md) | Authoring and testing Rego rules with cross-resource examples |
| [Drift Detection](docs/drift-detection.md) | AWS drift monitoring setup, IAM policy, and OIDC configuration |
| [Behavioral Exploration](docs/exploration.md) | Input synthesis, baselines, fault injection, and coverage |
| [CI/CD Integration](docs/ci-cd.md) | GitHub Actions workflows for all three stages |

## Architecture

```
Composition YAML + XRD
        |
   +---------+
   |  Loader  |  Parse Resources / Pipeline mode, or render via crossplane CLI
   +---------+
        |
  Layer 1: Static Validation
   - Schema validation against CRD bundle
   - Patch field path syntax
   - Duplicate resource names
   - Provider lock (apiVersion/kind vs bundle)
        |
  Layer 2: Dependency Validation
   - Directed dependency graph from patches and selectors
   - Cycle detection (topological sort)
   - Dangling references
   - Missing readiness gates
        |
  Layer 3: Policy Compliance (OPA Rego)
   - Full-document evaluation (all resources as one input)
   - 13 rules across 5 categories
   - Per-rule severity overrides
        |
  Layer 4: Reporting
   - Structured JSON findings
   - CRITICAL -> exit 1, WARNING -> exit 0
        |
  Drift Detection (Stage 3, optional)
   - Pull-based AWS API queries (read-only)
   - Field-level desired vs observed comparison
        |
  Behavioral Exploration (optional)
   - Pairwise input synthesis from XRD schema
   - Breaking change detection against golden baseline
   - Fault injection via observed-state mutation
   - Resource preservation invariants
   - Go template branch coverage
        |
  Layer 6: Extended Checks (optional, --extended-checks)
   - EnvironmentConfig coverage matrix
   - Security group network reachability
   - Multi-render-cycle simulation
   - Deletion policy consistency
   - Tag propagation validation
   - Cross-composition dependency validation
```

## Requirements

- Python 3.11+
- PyYAML, jsonschema (installed automatically)
- OPA binary on PATH (for Layer 3 policy checks)
- Crossplane CLI (for Pipeline mode rendering and exploration)
- Docker (for crossplane render function execution)
- Go 1.21+ (only to build template-coverage helper)

## Installation

```bash
# Clone and install
cd xptest
python -m venv .venv
source .venv/bin/activate
pip install -e .

# With optional dependencies
pip install -e ".[dev]"        # pytest + ruff
pip install -e ".[drift]"     # boto3 for drift detection
pip install -e ".[explore]"   # allpairspy for pairwise input generation
```

## Quick Start

### Validate a composition

```bash
# Static + dependency validation (Layers 1-4)
xptest validate \
  --composition compositions/my-vpc.yaml \
  --xrd definitions/xvpcnetwork.yaml

# With OPA policy checks (requires OPA on PATH)
xptest validate \
  --composition compositions/my-vpc.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --config xptest.yaml
```

### Validate with rendered output (Pipeline mode)

```bash
xptest validate \
  --composition compositions/my-vpc.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --xr claims/my-claim.yaml \
  --functions functions.yaml
```

### Auto-generate inputs from XRD

```bash
xptest validate \
  --composition compositions/my-vpc.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --functions functions.yaml \
  --auto-xr-combinations 20 \
  --logic-test \
  --auto-perturb
```

### Drift detection (Stage 3)

```bash
pip install -e ".[drift]"

xptest drift \
  --composition compositions/my-vpc.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --region us-east-1
```

### Behavioral exploration

```bash
xptest explore \
  --composition compositions/my-vpc.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --functions functions.yaml \
  --max-inputs 50 \
  --save-baseline
```

## Configuration

Create `xptest.yaml` in your project root:

```yaml
# CRD bundle for schema validation (Layer 1)
crd_bundle_path: ./schemas/crds

# OPA Rego rules directory (Layer 3)
rules_path: ./rules/aws
opa_binary: opa
opa_expected_version: "0.68.0"

# EnvironmentConfig fixtures for render
environment_config_paths:
  - ./envconfig.yaml

# Per-rule severity overrides
severity_overrides:
  tag/mandatory-keys: CRITICAL

# Required tag keys for tag/mandatory-keys rule
mandatory_tag_keys:
  - Environment
  - Owner

# Drift detection
aws_region: us-east-1
drift_resource_filter:
  - VPC
  - DBInstance

# Exploration
baseline_path: ./baselines/my-composition.json
max_exploration_inputs: 100
coverage_threshold: 80.0
```

All relative paths resolve from the config file's directory, not the working directory.

## CLI Reference

### `xptest validate`

Run static, dependency, and policy validation (Layers 1-4).

```
xptest validate --composition <path> --xrd <path> [options]

Options:
  --xr PATH                   XR/claim YAML for crossplane render
  --functions PATH             functions.yaml for crossplane render
  --observed-resources PATH    Observed resources YAML for conditional logic
  --auto-xr-combinations N    Auto-generate N input combinations from XRD (auto-discovers base XRs from composition-tests)
  --logic-test                 Run offline logic testing (snapshots, coverage, heuristics)
  --auto-perturb               Run perturbation analysis (implies --logic-test)
  --nearby-distance N          Max input distance for diff comparisons (default: 1)
  --persist-snapshots          Save snapshots to disk
  --snapshot-dir PATH          Artifact directory (default: xptest-artifacts)
  --config PATH                Config file (default: ./xptest.yaml)
  --output PATH                Output JSON (default: findings.json)
  --halt-on-critical           Stop on first CRITICAL finding (default: true)
  --extended-checks            Run Layer 6 extended validation checks
  --env-matrix                 Auto-discover envconfig files and validate across all environments
  --save-baseline              Save current findings as suppression baseline (.xptest-baseline.json)
  --baseline PATH              Path to baseline file for finding suppression
```

### `xptest drift`

Run Stage 3 drift detection against live AWS.

```
xptest drift --composition <path> --xrd <path> [options]

Options:
  --config PATH     Config file
  --region REGION   AWS region (overrides config)
  --output PATH     Output JSON (default: drift-findings.json)
```

Requires AWS credentials (OIDC in CI, local credentials for development).
Uses 12 read-only API actions only (Describe/Get/List).

### `xptest explore`

Run the Behavioral Exploration Module.

```
xptest explore --composition <path> --xrd <path> --functions <path> [options]

Options:
  --xr PATH                    Base XR YAML (if omitted, inputs are auto-generated)
  --observed-resources PATH    Observed resources for baseline renders
  --baseline PATH              Golden baseline JSON
  --max-inputs N               Max pairwise inputs (default: from config or 100)
  --coverage-threshold PCT     Min branch coverage % (0 = no enforcement)
  --fault-inject               Run fault injection sweep (default: true)
  --save-baseline              Save renders as new golden baseline
  --config PATH                Config file
  --output PATH                Output JSON (default: exploration-report.json)
```

## Baseline / Suppression

xptest supports a baseline workflow to suppress known findings and only surface new issues:

1. Run with `--save-baseline` to capture current findings into `.xptest-baseline.json`
2. Commit `.xptest-baseline.json` to your repository
3. Subsequent runs auto-detect the baseline file and only report NEW findings
4. Exit code is `0` when all findings are suppressed by the baseline

```bash
# Save baseline
xptest validate \
  --composition compositions/my-vpc.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --functions functions.yaml \
  --save-baseline

# Later runs only show new findings
xptest validate \
  --composition compositions/my-vpc.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --functions functions.yaml \
  --baseline .xptest-baseline.json
```

## Extended Checks (Layer 6)

Layer 6 provides six additional validation rules that go beyond static and dependency analysis. Enable with `--extended-checks`.

| Rule | ID | Severity | Description |
|------|----|----------|-------------|
| Env Matrix | L6-ENV-01 | WARNING / CRITICAL | Structural or security-sensitive divergence across EnvironmentConfigs |
| SG Reachability | L6-NET-01 | CRITICAL / WARNING | SecurityGroup ingress CIDRs do not cover VPC subnet CIDRs |
| Multi-Render | L6-MRC-01 | CRITICAL / WARNING | Resources disappear or count shrinks across render cycles |
| Deletion Policy | L6-DEL-01 | WARNING | Resource deletionPolicy does not match XR deletionPolicy |
| Tag Propagation | L6-TAG-01 | WARNING | Missing mandatory tags on AWS resources with forProvider |
| Cross-Composition | L6-XCC-01 | WARNING | providerConfigRef not found in EnvironmentConfig known configs |

Use `--env-matrix` alongside `--extended-checks` to auto-discover envconfig files and validate across all environments.

## Layer Details

### Layer 1 — Static Validation

| Rule | Description | Severity |
|------|-------------|----------|
| L1-01 | Schema validation against CRD bundle | CRITICAL |
| L1-02 | Patch field path syntax validation | CRITICAL |
| L1-03 | Duplicate composed resource names | CRITICAL |
| L1-04 | Provider lock (apiVersion/kind in CRD bundle) | WARNING |
| L1-05 | Deprecated field detection | INFO |

No AWS credentials required. Target: < 5 seconds.

### Layer 2 — Dependency Validation

| Rule | Description | Severity |
|------|-------------|----------|
| L2-01 | Reference completeness (atProvider fields exist in CRD) | WARNING |
| L2-02 | Cycle detection in dependency graph | CRITICAL |
| L2-03 | Dangling references (patch reads from non-existent resource) | CRITICAL |
| L2-04 | Missing readiness gates on producer resources | CRITICAL |
| L2-05 | Cross-composition ordering (stub) | — |

Dependency edges are extracted from `FromCompositeFieldPath` and `CombineFromComposite` patches
(when reading `status.atProvider.<resource>.<field>`), and from `matchLabels` selectors.

No AWS credentials required. Target: < 10 seconds.

### Layer 3 — Policy Compliance (OPA Rego)

All composed resources are passed simultaneously as one JSON input document,
enabling cross-resource rules that per-object scanners cannot enforce.

| Category | Rules | Description |
|----------|-------|-------------|
| Encryption | `enc/s3-sse`, `enc/rds-encrypted` | S3 SSE, RDS storage encryption |
| Network | `net/sg-no-open-ssh`, `net/sg-no-open-db`, `net/rds-not-public`, `net/s3-public-block` | Security group restrictions, public access |
| IAM | `iam/no-wildcard-action`, `iam/no-wildcard-resource`, `iam/trust-service-match` | Least-privilege, trust policy validation |
| Cross-resource | `cross/kms-key-consistency`, `cross/iam-rds-trust`, `cross/sg-rds-port-match` | Multi-resource consistency |
| Tagging | `tag/mandatory-keys` | Required tag enforcement |

No AWS credentials required. Target: < 10 seconds.

### Layer 4 — Reporting

Findings are written to `findings.json` with the schema:

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

Exit codes: `1` if any CRITICAL finding, `0` otherwise.

### Drift Detection (Stage 3)

Pull-based comparison of desired state (from composition) against observed AWS state.

| Family | AWS APIs | Checked fields |
|--------|----------|---------------|
| VPC | DescribeVpcs, DescribeSubnets, DescribeSecurityGroups, DescribeRouteTables | CIDR, DNS settings, tags |
| S3 | GetBucketEncryption, GetBucketPolicy, GetPublicAccessBlock | Encryption config, public access |
| RDS | DescribeDBInstances, DescribeDBSubnetGroups, DescribeDBParameterGroups | Engine, encryption, public access |
| IAM | GetRole, GetRolePolicy, ListAttachedRolePolicies | Trust policy, attached policies |

Requires read-only AWS credentials (12 IAM actions). See `docs/iam-policy.json` for reference policy.

### Behavioral Exploration Module

Discovers failures invisible to single-input testing:

**Input Synthesis** — Pairwise covering array (t=2) from XRD schema. Uses `allpairspy` if installed, falls back to greedy algorithm. Domain enumeration is type-aware (regions, CIDRs, namespaces).

**Breaking Change Detection** — Compares render outputs against a committed golden baseline. Four rules:
- `bc/resource-removed` — resource in baseline absent from renders (CRITICAL)
- `bc/deletion-policy-escalated` — Orphan changed to Delete (CRITICAL)
- `bc/management-delete-added` — Delete verb added to managementPolicies (CRITICAL)

**Fault Injection** — Sweeps resources in reverse topological order (leaves first), injecting `ReconcileError` fault state via `--observed-resources`, then checking if the composition handles it gracefully.

**Resource Preservation Invariants** — Three invariants enforced across all renders:
- Type coverage: every declared GVK appears in at least one render (CRITICAL)
- Deletion policy escalation: Orphan to Delete is flagged (CRITICAL)
- Minimum resource count: non-fault renders must not contract (WARNING)

**Template Branch Coverage** — Go helper binary parses Go template AST, instruments `if`/`range`/`with` branches, and reports coverage percentage.

## CI/CD Integration

Three stages designed for GitHub Actions:

| Stage | Trigger | Layers | AWS Credentials | Blocks Merge |
|-------|---------|--------|-----------------|-------------|
| Stage 1+2 | Pull request | L1 + L2 + L3 | None | Yes (on CRITICAL) |
| Stage 3 | Scheduled (6h) | Drift | Read-only (OIDC) | No (alerts) |
| Stage 4 | Nightly / manual | Exploration | None (Docker required) | Configurable |

Workflow files: `.github/workflows/pr-validate.yml`, `.github/workflows/drift-scheduled.yml`.

## Project Structure

```
xptest/
├── src/xptest/
│   ├── cli.py                  # CLI entry point (validate, drift, explore)
│   ├── config.py               # xptest.yaml loader
│   ├── loader.py               # Composition + XRD parser (Resources + Pipeline)
│   ├── models.py               # Finding, ComposedResource, CompositionObject
│   ├── evaluate.py             # Evaluation runner (thesis metrics)
│   ├── metrics.py              # TP/FP/FN/recall/precision/FPR
│   ├── layer1/static.py        # Layer 1: schema, field paths, duplicates, provider lock
│   ├── layer2/dependency.py    # Layer 2: cycles, dangling, readiness, references
│   ├── layer3/policy.py        # Layer 3: OPA subprocess, full-document evaluation
│   ├── layer4/reporting.py     # Layer 4: JSON output, exit codes
│   ├── validation/facade.py    # Unified L1-L3 orchestrator
│   ├── layer5_rules.py         # Layer 6: Extended validation rules (6 rules)
│   ├── drift/                  # Stage 3: AWS drift detection
│   │   ├── aws_checker.py      # Per-family AWS API queries (VPC, S3, RDS, IAM)
│   │   ├── comparator.py       # Field-level desired vs observed diff
│   │   └── models.py           # DriftFinding dataclass
│   ├── logic/                  # Offline logic testing
│   │   ├── snapshot.py         # Rendered graph snapshots, edge inference
│   │   ├── coverage.py         # Coverage signatures, nearby-pair detection
│   │   └── heuristics.py       # 6 heuristic rules (L5-H01/H02, L5-D01-D04)
│   ├── chaos/                  # Offline perturbation analysis
│   │   ├── engine.py           # 4 perturbation types (P1-P4), 5 risk rules (C1-C5)
│   │   └── criticality.py     # Kind/fan-out/role-hint scoring
│   └── exploration/            # Behavioral Exploration Module
│       ├── input_synthesis.py  # Pairwise covering array from XRD
│       ├── breaking_change.py  # Golden baseline + 4 bc rules
│       ├── fault_injection.py  # Observed-state mutation sweep
│       ├── invariants.py       # 3 resource preservation invariants
│       └── template_coverage.py # Go helper wrapper
├── rules/aws/                  # OPA Rego rules (13 rules, 5 packages)
│   ├── encryption.rego
│   ├── network.rego
│   ├── iam.rego
│   ├── cross_resource.rego
│   └── tagging.rego
├── schemas/sample-bundle/      # Minimal CRD stubs for evaluation
├── fixtures/                   # 16 test compositions with expected.json
│   ├── valid/                  # 4 valid compositions
│   ├── dep-errors/             # 7 dependency error compositions
│   └── policy-violations/      # 6 policy violation compositions
├── tools/template-coverage/    # Go helper for template branch coverage
│   ├── main.go
│   ├── go.mod
│   └── bin/template-coverage   # Pre-compiled binary
├── tests/                      # ~350 tests
│   ├── test_baseline.py        # Baseline/suppression tests (7 tests)
│   ├── test_extended_rules.py  # Extended validation rule tests (23 tests)
│   └── ...                     # Existing test modules
├── docs/iam-policy.json        # Reference IAM policy for drift detection
├── .github/workflows/          # CI/CD workflow files
├── pyproject.toml
└── xptest.yaml                 # Sample configuration
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linter
ruff check src/ tests/

# Run evaluation (thesis metrics)
python -c "from xptest.evaluate import main; main()"

# Build Go helper (requires Go 1.21+)
cd tools/template-coverage
go build -o bin/template-coverage .
```

## Test Results

```
~350 collected, ~343 passed, 7 skipped

Skipped: 7 OPA integration tests (require OPA binary on PATH)

Layer 2 evaluation: TP=7, FP=0, FN=0 — Recall=100%, Precision=100%
Layer 3 evaluation: requires OPA installation
Layer 6 extended checks: 23 tests covering all 6 rules
```

## Writing Custom OPA Rules

Place `.rego` files in the rules directory (configured via `rules_path`).
Rules must use the `xptest.*` package namespace and produce violations as:

```rego
package xptest.custom

violations[v] {
    resource := input.resources[_]
    resource.kind == "Bucket"
    not resource.spec.forProvider.tags
    v := {
        "rule": "custom/bucket-needs-tags",
        "resource": resource.name,
        "path": "spec.forProvider.tags",
        "severity": "WARNING",
        "message": "S3 bucket should have tags",
        "remediation": "Add tags to the bucket spec."
    }
}
```

All resources are passed as `input.resources[]` in a single evaluation,
enabling cross-resource rules.

## Acknowledgements

This tool is the reference implementation for a master's thesis:
*Testing Framework for Crossplane Compositions in AWS Environments*,
Transport and Telecommunication Institute, 2026.
