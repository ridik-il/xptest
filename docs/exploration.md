# Behavioral Exploration Guide

The Behavioral Exploration Module discovers failures that are invisible to single-input static analysis. It runs as a parallel track alongside the four-layer pipeline, not as a fifth sequential layer.

## Overview

```
XRD Schema
    │
    ├── Input Synthesis ──── Pairwise covering array (t=2)
    │         │
    │    crossplane render ×N
    │         │
    │   ┌─────┴──────────────────────────┐
    │   │                                │
    │   ├── Breaking Change Detection    │  Compare against golden baseline
    │   ├── Resource Preservation        │  Type coverage, deletion policy, min count
    │   ├── Fault Injection Sweep        │  ReconcileError per resource (leaves first)
    │   └── Template Branch Coverage     │  Go AST instrumentation
    │                                    │
    │   exploration-report.json          │
    └────────────────────────────────────┘
```

## Prerequisites

- Crossplane CLI (`crossplane` on PATH)
- Docker (for `crossplane render` function execution)
- Optional: `pip install -e ".[explore]"` for `allpairspy` (pairwise library)
- Optional: Go helper binary for template coverage (`tools/template-coverage/bin/template-coverage`)

## Usage

```bash
# Basic exploration run
xptest explore \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --functions functions.yaml

# Save a golden baseline for future comparison
xptest explore \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --functions functions.yaml \
  --save-baseline

# Compare against existing baseline
xptest explore \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --functions functions.yaml \
  --baseline baselines/vpc-network.json

# Limit inputs and set coverage threshold
xptest explore \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --functions functions.yaml \
  --max-inputs 50 \
  --coverage-threshold 80

# Provide a base XR instead of auto-generating
xptest explore \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --functions functions.yaml \
  --xr claims/my-vpc.yaml

# Disable fault injection
xptest explore \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --functions functions.yaml \
  --no-fault-inject
```

## Components

### 1. Input Synthesis (`exploration/input_synthesis.py`)

Generates a diverse set of XR claim inputs from the XRD schema using pairwise covering arrays.

**How it works:**

1. Extracts parameters from `spec.versions[].schema.openAPIV3Schema.properties.spec`
2. Enumerates domains per parameter type:

| Type | Domain values |
|------|--------------|
| `enum` | All enum values |
| `boolean` | `[true, false]` |
| `integer` / `number` | `[minimum, maximum, midpoint]` |
| `string` | Domain-aware: regions, CIDRs, namespaces, ARNs, or generic samples |
| `array` | `[[], [single-element]]` |
| `object` | `[{}]` |

3. Builds a pairwise covering array (strength t=2) ensuring every pair of parameter values appears in at least one test case
4. Uses `allpairspy` library if installed; falls back to a built-in greedy algorithm

**Coverage-guided extension:**

After the initial seed suite, `extend_suite()` can mutate inputs targeting uncovered template branches. For each uncovered branch, the nearest seed input is selected and one parameter is mutated.

### 2. Breaking Change Detection (`exploration/breaking_change.py`)

Compares current render outputs against a committed golden baseline to detect unintended destructive changes.

**Baseline format** (`baselines/<composition>.json`):

```json
{
  "composition": "my-vpc-network",
  "resources": [
    {
      "composition-resource-name": "vpc",
      "apiVersion": "ec2.aws.upbound.io/v1beta1",
      "kind": "VPC",
      "deletionPolicy": "Orphan",
      "managementPolicies": ["Observe", "Create", "Update"]
    }
  ]
}
```

**Breaking change rules:**

| Rule | Condition | Severity |
|------|-----------|----------|
| `bc/resource-removed` | Resource in baseline absent from all current renders | CRITICAL |
| `bc/deletion-policy-escalated` | `deletionPolicy` changed from `Orphan` to `Delete` | CRITICAL |
| `bc/management-delete-added` | `Delete` verb added to `managementPolicies` | CRITICAL |

**Workflow:**

1. First run: `xptest explore --save-baseline` to create the golden baseline
2. Commit the baseline JSON to version control
3. Subsequent runs: `xptest explore --baseline baselines/my-composition.json` to detect changes

### 3. Fault Injection (`exploration/fault_injection.py`)

Systematically injects `ReconcileError` fault states into each composed resource and checks whether the composition handles degraded state gracefully.

**Algorithm:**

1. Build dependency graph from Layer 2 edges
2. Sort resources in **reverse topological order** (leaf nodes first — resources with no dependents are faulted before their producers)
3. For each resource:
   - Generate observed-resources YAML with `ReconcileError` status for the target
   - All other resources have healthy status
   - Execute `crossplane render` with the fault state
   - Check resource preservation invariants on the rendered output
   - Emit findings for violations

**Fault state injected:**

```yaml
apiVersion: <resource apiVersion>
kind: <resource kind>
metadata:
  name: <resource name>
  annotations:
    crossplane.io/composition-resource-name: <resource name>
status:
  conditions:
    - type: Ready
      status: "False"
      reason: ReconcileError
  atProvider: {}
```

**Why leaves first?** Faulting a leaf resource tests whether the composition correctly handles the absence of a dependency without cascading failures up the graph.

### 4. Resource Preservation Invariants (`exploration/invariants.py`)

Three invariants enforced across all exploration renders:

| Invariant | Condition | Severity |
|-----------|-----------|----------|
| Type coverage | Every declared `(apiVersion, kind)` pair must appear in at least one render | CRITICAL |
| Deletion policy escalation | `deletionPolicy` changing from `Orphan` to `Delete` in any render | CRITICAL |
| Minimum resource count | Non-fault renders must produce at least as many resources as the baseline minimum | WARNING |

Fault injection renders are excluded from the minimum resource count check (a faulted resource is expected to be absent).

### 5. Template Branch Coverage (`exploration/template_coverage.py`)

Measures Go template branch coverage for Pipeline mode compositions that use Go-templating functions.

**How it works:**

1. A Go helper binary (`tools/template-coverage/bin/template-coverage`) parses the Go template source
2. It identifies branch nodes: `{{if}}`, `{{range}}`, `{{with}}`
3. Each branch node generates two branch IDs (true path and false/else path)
4. The template is instrumented with probe markers (`##XPTEST_COV##<branch-id>`)
5. The instrumented template is executed with each input from the seed suite
6. Probe markers in the output identify which branches were exercised
7. Coverage percentage = covered branches / total branches

**For Resources mode:** No Go templates are involved, so coverage is trivially 100%.

**Building the Go helper:**

```bash
cd tools/template-coverage
go build -o bin/template-coverage .
```

A pre-compiled `linux/amd64` binary is committed at `tools/template-coverage/bin/template-coverage`.

## Output

The exploration report is written to `exploration-report.json` (or `--output` path):

```json
{
  "total_inputs": 24,
  "successful_renders": 22,
  "failed_renders": 2,
  "breaking_changes": [],
  "invariant_violations": [],
  "fault_injection_findings": [
    {
      "layer": 7,
      "rule": "fi/resource-disappeared-under-fault",
      "resource": "subnet-a",
      "severity": "WARNING",
      "message": "Resource subnet-a disappeared when vpc was faulted"
    }
  ],
  "template_coverage": {
    "total_branches": 8,
    "covered_branches": 7,
    "coverage_pct": 87.5,
    "uncovered": [
      {
        "branch_id": "composition:15:if:false",
        "node_type": "if",
        "line": 15,
        "guard_expression": "!.spec.enableDns"
      }
    ]
  }
}
```

## Configuration

Relevant `xptest.yaml` fields:

```yaml
baseline_path: ./baselines/vpc-network.json   # Golden baseline
max_exploration_inputs: 100                     # Max pairwise inputs
coverage_threshold: 80.0                        # Min branch coverage %
environment_config_paths:                       # For crossplane render
  - ./envconfig.yaml
```

## Tips

- **Start with `--save-baseline`** on a known-good composition to establish the golden baseline before iterating.
- **Use `--max-inputs`** to control exploration time. 20-50 inputs is usually sufficient for compositions with < 10 parameters.
- **Coverage threshold of 0** means coverage is measured and reported but never causes a finding. Set to 80+ when you want to enforce coverage.
- **Fault injection is enabled by default.** Use `--no-fault-inject` to skip it if your composition does not use `--observed-resources`.
