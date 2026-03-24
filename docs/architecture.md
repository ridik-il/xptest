# Architecture

xptest implements a four-layer sequential validation pipeline, a pull-based drift detector, and a behavioral exploration module. Each component is a separate Python module with no circular dependencies.

## Pipeline Overview

```
                    Composition YAML + XRD
                            │
                    ┌───────┴───────┐
                    │    Loader     │  Parse Resources / Pipeline mode
                    │  (loader.py)  │  or render via crossplane CLI
                    └───────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              │    Sequential Pipeline     │
              │                            │
         ┌────┴────┐                       │
         │ Layer 1  │  Static Validation   │
         │ (L1-01   │  Schema, field paths │
         │  ..L1-05)│  duplicates, lock    │
         └────┬────┘                       │
              │  halt if CRITICAL          │
         ┌────┴────┐                       │
         │ Layer 2  │  Dependency Valid.   │
         │ (L2-01   │  Graph, cycles,      │
         │  ..L2-05)│  dangling, readiness │
         └────┬────┘                       │
              │  halt if CRITICAL          │
         ┌────┴────┐                       │
         │ Layer 3  │  Policy Compliance   │
         │  (OPA)   │  13 Rego rules,      │
         │          │  full-document eval  │
         └────┬────┘                       │
              │                            │
         ┌────┴────┐                       │
         │ Layer 4  │  Reporting           │
         │          │  JSON + exit codes   │
         └─────────┘                       │
              └────────────────────────────┘

         ┌─────────────────────────────────┐
         │  Drift Detection (Stage 3)      │
         │  Pull-based AWS API queries     │
         │  Read-only, OIDC credentials    │
         └─────────────────────────────────┘

         ┌─────────────────────────────────┐
         │  Behavioral Exploration         │
         │  Pairwise inputs, baselines,    │
         │  fault injection, coverage      │
         └─────────────────────────────────┘
```

## Layer Details

### Loader (`loader.py`)

The loader parses Composition and XRD YAML into a unified `CompositionObject`. It auto-detects the composition mode:

- **Resources mode** (`spec.resources[]`) — resources are extracted directly from the composition YAML.
- **Pipeline mode** (`spec.pipeline[].input.resources[]`) — resources are extracted from pipeline step inputs, or rendered via `crossplane render` when `--xr` and `--functions` are provided.

Key data models:

| Model | Fields | Purpose |
|-------|--------|---------|
| `CompositionObject` | `composition_name`, `mode`, `resources`, `xrd_spec` | Top-level parsed composition |
| `ComposedResource` | `name`, `api_version`, `kind`, `spec`, `patches`, `readiness_checks` | Single composed resource |

### Layer 1 — Static Validation (`layer1/static.py`)

Validates individual resources without considering inter-resource relationships.

| Rule | Check | Severity |
|------|-------|----------|
| L1-01 | Resource spec validates against CRD `openAPIV3Schema` | CRITICAL |
| L1-02 | `fromFieldPath` / `toFieldPath` syntax is valid | CRITICAL |
| L1-03 | No two resources share the same `name` | CRITICAL |
| L1-04 | Every `apiVersion`/`kind` pair exists in the CRD bundle | WARNING |
| L1-05 | Deprecated field usage (stub) | INFO |

No external dependencies. Target: < 5 seconds.

### Layer 2 — Dependency Validation (`layer2/dependency.py`)

Builds a directed dependency graph and checks structural properties.

**Edge sources:**
- `FromCompositeFieldPath` patches where the source reads `status.atProvider.<resource>.<field>` (4+ segments)
- `CombineFromComposite` patches with any source reading `status.atProvider.*`
- `matchLabels` selectors referencing another composed resource

| Rule | Check | Severity |
|------|-------|----------|
| L2-01 | Referenced `atProvider` field exists in producer CRD schema | WARNING |
| L2-02 | Dependency graph is acyclic (topological sort) | CRITICAL |
| L2-03 | Patch reads from a resource that exists in the composition | CRITICAL |
| L2-04 | Producer resource has a `readinessCheck` when consumed | CRITICAL |

No external dependencies. Target: < 10 seconds.

### Layer 3 — Policy Compliance (`layer3/policy.py`)

Evaluates all composed resources simultaneously against OPA Rego rules. This full-document evaluation mode is the architectural differentiator — it enables cross-resource rules that per-object scanners (Checkov, Tfsec) and admission controllers (Gatekeeper, Kyverno) cannot enforce.

**Evaluation flow:**
1. Build JSON input: `{"resources": [...all composed resources...]}`
2. For each Rego package, run: `opa eval -d <rules_dir> -i <input.json> 'data.<package>.violations'`
3. Parse violation objects from OPA stdout
4. Apply severity overrides from config
5. Convert to Finding objects

| Category | Rules | Description |
|----------|-------|-------------|
| Encryption | `enc/s3-sse`, `enc/rds-encrypted` | Storage encryption |
| Network | `net/sg-no-open-ssh`, `net/sg-no-open-db`, `net/rds-not-public`, `net/s3-public-block` | Network isolation |
| IAM | `iam/no-wildcard-action`, `iam/no-wildcard-resource`, `iam/trust-service-match` | Least-privilege |
| Cross-resource | `cross/kms-key-consistency`, `cross/iam-rds-trust`, `cross/sg-rds-port-match` | Multi-resource consistency |
| Tagging | `tag/mandatory-keys` | Required tags |

Requires OPA binary on PATH. Target: < 10 seconds.

### Layer 4 — Reporting (`layer4/reporting.py`)

Aggregates findings into structured JSON and prints a text summary.

- **Output format:** JSON array of Finding objects
- **Exit code:** `1` if any CRITICAL finding, `0` otherwise
- **Text summary:** layer-by-layer finding counts to stderr

### Validation Facade (`validation/facade.py`)

Orchestrates Layers 1-3 sequentially. When `halt_on_critical=True` (default), a CRITICAL finding in Layer N prevents Layers N+1..3 from running. Returns a `ValidationRunResult` with all findings and the halted layer (if any).

## Drift Detection (`drift/`)

Pull-based comparison of desired composition state against live AWS resources. Runs as a separate CLI subcommand (`xptest drift`).

| Module | Purpose |
|--------|---------|
| `aws_checker.py` | Per-family AWS API queries (VPC, S3, RDS, IAM) |
| `comparator.py` | Recursive field-level diff with boolean normalization |
| `models.py` | `DriftFinding` dataclass |

Uses 12 read-only AWS API actions. No write permissions. See [Drift Detection Guide](drift-detection.md).

## Behavioral Exploration (`exploration/`)

Parallel track (not a fifth sequential layer) that discovers failures invisible to single-input testing. Runs as `xptest explore`.

| Module | Purpose |
|--------|---------|
| `input_synthesis.py` | Pairwise covering array from XRD schema |
| `breaking_change.py` | Golden baseline comparison (3 breaking change rules) |
| `fault_injection.py` | Observed-state mutation sweep in reverse topological order |
| `invariants.py` | Resource preservation invariants (type coverage, deletion policy, min count) |
| `template_coverage.py` | Go template branch coverage via helper binary |

See [Behavioral Exploration Guide](exploration.md).

## Offline Analysis (`logic/`, `chaos/`)

Two supporting modules provide offline analysis without subprocess calls:

| Module | Purpose |
|--------|---------|
| `logic/snapshot.py` | Build `RenderedGraphSnapshot` from rendered outputs |
| `logic/coverage.py` | Coverage signatures, input distance, nearby-pair detection |
| `logic/heuristics.py` | 6 heuristic rules (duplicate detection, nearby-diff analysis) |
| `chaos/engine.py` | 4 perturbation types (P1-P4), 5 destructive-change rules (C1-C5) |
| `chaos/criticality.py` | Kind/fan-out/role-hint criticality scoring |

## Module Dependency Graph

```
cli.py
├── config.py
├── loader.py
├── validation/facade.py
│   ├── layer1/static.py
│   ├── layer2/dependency.py
│   └── layer3/policy.py
├── layer4/reporting.py
├── logic/
│   ├── snapshot.py ── models.py
│   ├── coverage.py
│   └── heuristics.py
├── chaos/
│   ├── engine.py
│   └── criticality.py
├── exploration/
│   ├── input_synthesis.py
│   ├── breaking_change.py ── logic/snapshot.py
│   ├── fault_injection.py ── loader.py
│   ├── invariants.py ── logic/snapshot.py
│   └── template_coverage.py
├── drift/
│   ├── aws_checker.py (lazy boto3)
│   ├── comparator.py
│   └── models.py
├── models.py (Finding, Severity, ComposedResource, CompositionObject)
├── evaluate.py
└── metrics.py
```

## Design Principles

1. **No live cluster required** — all validation runs against YAML files and local CRD bundles.
2. **Lazy external dependencies** — boto3 is imported only when drift detection runs; OPA is invoked only when Layer 3 is configured; Docker is needed only for Pipeline mode rendering.
3. **Deterministic output** — identical inputs produce identical findings (no network calls in Layers 1-3).
4. **Severity gating** — CRITICAL findings halt the pipeline in CI; WARNING findings are informational.
5. **Full-document evaluation** — Layer 3 passes all resources as one input, enabling cross-resource rules.
