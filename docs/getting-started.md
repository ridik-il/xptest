# Getting Started

This guide walks through installing xptest and running your first composition validation.

## Prerequisites

| Dependency | Required for | Install |
|-----------|-------------|---------|
| Python 3.11+ | All commands | [python.org](https://www.python.org/downloads/) |
| OPA binary | Layer 3 policy checks | [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#running-opa) |
| Crossplane CLI | Pipeline mode, exploration | [docs.crossplane.io](https://docs.crossplane.io/latest/cli/) |
| Docker | `crossplane render` functions | [docker.com](https://docs.docker.com/get-docker/) |
| Go 1.21+ | Building template-coverage helper | [go.dev](https://go.dev/dl/) |

Only Python is required for basic static and dependency validation (Layers 1-2).

## Installation

```bash
cd xptest
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Optional dependency groups

```bash
pip install -e ".[dev]"        # pytest + ruff (development)
pip install -e ".[drift]"     # boto3 (drift detection)
pip install -e ".[explore]"   # allpairspy (pairwise input generation)
```

### Verify installation

```bash
xptest --help
```

Expected output:

```
usage: xptest [-h] {validate,drift,explore} ...

Modular validation framework for Crossplane Compositions in AWS.

positional arguments:
  {validate,drift,explore}
```

## Prepare your inputs

xptest needs at minimum two files:

1. **Composition YAML** — the Crossplane Composition to validate
2. **XRD YAML** — the CompositeResourceDefinition that defines the claim schema

Example directory layout:

```
my-platform/
├── compositions/
│   └── vpc-network.yaml       # Composition
├── definitions/
│   └── xvpcnetwork.yaml       # XRD
├── claims/
│   └── my-vpc.yaml            # XR claim (optional, for Pipeline mode)
├── functions.yaml              # Function refs (optional, for Pipeline mode)
├── schemas/
│   └── crds/                   # CRD bundle (optional, for schema validation)
├── rules/
│   └── aws/                    # OPA Rego rules (optional, for policy checks)
└── xptest.yaml                 # Config file (optional)
```

## Run your first validation

### Minimal run (Layers 1-2 only)

```bash
xptest validate \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml
```

This runs static validation (Layer 1) and dependency validation (Layer 2) without any external dependencies. Output goes to `findings.json`.

### With schema validation against CRDs

Create `xptest.yaml`:

```yaml
crd_bundle_path: ./schemas/crds
```

```bash
xptest validate \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --config xptest.yaml
```

Layer 1 now validates resource specs against your CRD bundle.

### With OPA policy checks (Layer 3)

Add OPA rules to the config:

```yaml
crd_bundle_path: ./schemas/crds
rules_path: ./rules/aws
opa_binary: opa
```

```bash
xptest validate \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --config xptest.yaml
```

Layer 3 evaluates all 13 built-in rules across encryption, network, IAM, cross-resource, and tagging categories. Requires the OPA binary on PATH.

### Pipeline mode (rendered output)

For compositions that use `spec.mode: Pipeline` with Go-templating functions:

```bash
xptest validate \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --xr claims/my-vpc.yaml \
  --functions functions.yaml \
  --config xptest.yaml
```

This calls `crossplane render` under the hood and validates the rendered output. Requires Crossplane CLI and Docker.

### Extended checks and baseline

```bash
# Extended checks with environment matrix
xptest validate \
  --composition compositions/my-rds.yaml \
  --xrd definitions/xrdsaurora.yaml \
  --functions functions.yaml \
  --environment-configs envconfig.yaml \
  --auto-xr-combinations 20 \
  --extended-checks \
  --env-matrix

# Save baseline to suppress known findings
xptest validate \
  --composition compositions/my-rds.yaml \
  --xrd definitions/xrdsaurora.yaml \
  --functions functions.yaml \
  --auto-xr-combinations 20 \
  --save-baseline

# Subsequent runs only show NEW findings
xptest validate \
  --composition compositions/my-rds.yaml \
  --xrd definitions/xrdsaurora.yaml \
  --functions functions.yaml \
  --auto-xr-combinations 20
```

## Read the output

Findings are written to `findings.json` (or the path given with `--output`):

```json
[
  {
    "layer": 2,
    "rule": "L2-02/cycle",
    "resource": "vpc",
    "path": "spec.forProvider.vpcId",
    "severity": "CRITICAL",
    "message": "Cycle detected: vpc -> subnet -> vpc",
    "remediation": "Break the circular dependency by removing one edge."
  }
]
```

A text summary is printed to stderr:

```
xptest: loaded composition 'my-vpc' (Resources mode, 5 resources)
xptest: Layer 1 — 0 findings
xptest: Layer 2 — 1 finding (1 CRITICAL)
xptest: 1 finding written to findings.json
```

**Exit codes:**
- `0` — no CRITICAL findings
- `1` — at least one CRITICAL finding

## Next steps

- [Configuration Reference](configuration.md) — all config fields explained
- [Architecture](architecture.md) — how the four-layer pipeline works
- [Drift Detection](drift-detection.md) — set up AWS drift monitoring
- [Behavioral Exploration](exploration.md) — automated input discovery
- [Writing Custom OPA Rules](writing-rules.md) — extend policy checks
- [CI/CD Integration](ci-cd.md) — GitHub Actions workflows
