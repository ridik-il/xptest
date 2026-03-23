# CI/CD Integration Guide

xptest is designed for integration into GitHub Actions pipelines with three stages that run at different trigger points.

## Stage Overview

| Stage | Trigger | What runs | AWS Credentials | Blocks Merge |
|-------|---------|-----------|-----------------|-------------|
| Stage 1+2 | Pull request | Layers 1 + 2 + 3 | None | Yes (on CRITICAL) |
| Stage 3 | Scheduled (every 6h) | Drift detection | Read-only (OIDC) | No (alerts only) |
| Stage 4 | Nightly / manual | Behavioral exploration | None (Docker required) | Configurable |

## Stage 1+2: PR Validation

Runs static validation, dependency validation, and policy compliance on every pull request. No AWS credentials needed.

### Workflow: `.github/workflows/pr-validate.yml`

```yaml
name: Validate Compositions

on:
  pull_request:
    paths:
      - 'compositions/**'
      - 'definitions/**'
      - 'rules/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install xptest
        run: |
          cd xptest
          pip install -e .

      - name: Install OPA
        run: |
          curl -L -o /usr/local/bin/opa \
            https://openpolicyagent.org/downloads/v0.68.0/opa_linux_amd64_static
          chmod +x /usr/local/bin/opa

      - name: Validate compositions
        run: |
          xptest validate \
            --composition compositions/vpc-network.yaml \
            --xrd definitions/xvpcnetwork.yaml \
            --config xptest.yaml \
            --output findings.json

      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: validation-findings
          path: findings.json
```

**Key points:**
- Triggers only when composition, definition, or rule files change
- OPA is downloaded as a static binary (no package manager needed)
- Exit code 1 on CRITICAL findings blocks the PR
- Findings are uploaded as artifacts for review

### Validating multiple compositions

```yaml
      - name: Validate all compositions
        run: |
          exit_code=0
          for comp in compositions/*.yaml; do
            name=$(basename "$comp" .yaml)
            xrd="definitions/x${name}.yaml"
            if [ -f "$xrd" ]; then
              xptest validate \
                --composition "$comp" \
                --xrd "$xrd" \
                --config xptest.yaml \
                --output "findings-${name}.json" || exit_code=1
            fi
          done
          exit $exit_code
```

## Stage 3: Drift Detection

Runs on a schedule to detect drift between compositions and live AWS state. Uses OIDC for credentials.

### Workflow: `.github/workflows/drift-scheduled.yml`

```yaml
name: Drift Detection

on:
  schedule:
    - cron: '0 */6 * * *'   # Every 6 hours
  workflow_dispatch:          # Manual trigger

permissions:
  id-token: write
  contents: read

jobs:
  drift:
    runs-on: ubuntu-latest
    environment: aws-drift

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install xptest with drift support
        run: |
          cd xptest
          pip install -e ".[drift]"

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/xptest-drift-role
          aws-region: us-east-1

      - name: Run drift detection
        run: |
          xptest drift \
            --composition compositions/vpc-network.yaml \
            --xrd definitions/xvpcnetwork.yaml \
            --config xptest.yaml \
            --output drift-findings.json

      - name: Upload drift report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: drift-findings
          path: drift-findings.json

      - name: Alert on drift (optional)
        if: failure()
        run: |
          echo "Drift detected — see artifacts for details"
          # Add Slack/email notification here
```

**Key points:**
- Uses OIDC federation (no static AWS keys)
- Requires a GitHub environment `aws-drift` with the IAM role ARN
- Does not block merges — generates alerts
- See [Drift Detection Guide](drift-detection.md) for IAM setup

## Stage 4: Behavioral Exploration

Runs nightly or on manual trigger. Requires Docker for `crossplane render`.

### Workflow: `.github/workflows/explore-scheduled.yml`

```yaml
name: Behavioral Exploration

on:
  schedule:
    - cron: '0 2 * * *'    # Nightly at 02:00
  workflow_dispatch:

jobs:
  explore:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install xptest with exploration support
        run: |
          cd xptest
          pip install -e ".[explore]"

      - name: Install Crossplane CLI
        run: |
          curl -sL https://raw.githubusercontent.com/crossplane/crossplane/master/install.sh | sh
          sudo mv crossplane /usr/local/bin/

      - name: Run exploration
        run: |
          xptest explore \
            --composition compositions/vpc-network.yaml \
            --xrd definitions/xvpcnetwork.yaml \
            --functions functions.yaml \
            --baseline baselines/vpc-network.json \
            --config xptest.yaml \
            --output exploration-report.json

      - name: Upload exploration report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: exploration-report
          path: exploration-report.json
```

**Key points:**
- No AWS credentials needed (renders are local via Docker)
- Docker is available by default on `ubuntu-latest`
- Baseline JSON should be committed to the repo (generated with `--save-baseline`)

## Exit Codes

All xptest subcommands follow the same convention:

| Exit code | Meaning |
|-----------|---------|
| `0` | No CRITICAL findings |
| `1` | At least one CRITICAL finding |

This maps directly to GitHub Actions job success/failure.

## Caching

Speed up CI by caching the Python virtual environment:

```yaml
      - uses: actions/cache@v4
        with:
          path: xptest/.venv
          key: xptest-${{ hashFiles('xptest/pyproject.toml') }}

      - name: Install xptest
        run: |
          cd xptest
          python -m venv .venv
          source .venv/bin/activate
          pip install -e .
```

## Matrix Strategy

Validate multiple compositions in parallel:

```yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        composition:
          - vpc-network
          - rds-database
          - s3-storage
      fail-fast: false

    steps:
      # ... setup steps ...

      - name: Validate ${{ matrix.composition }}
        run: |
          xptest validate \
            --composition compositions/${{ matrix.composition }}.yaml \
            --xrd definitions/x${{ matrix.composition }}.yaml \
            --config xptest.yaml
```

## GitLab CI

While the examples above use GitHub Actions, xptest works in any CI system. The key is:

1. Install Python 3.11+ and xptest
2. Install OPA binary (for Layer 3)
3. Run `xptest validate` / `xptest drift` / `xptest explore`
4. Check exit code

```yaml
# .gitlab-ci.yml
validate-compositions:
  image: python:3.11
  stage: test
  before_script:
    - cd xptest && pip install -e .
    - curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/v0.68.0/opa_linux_amd64_static
    - chmod +x /usr/local/bin/opa
  script:
    - xptest validate --composition compositions/vpc-network.yaml --xrd definitions/xvpcnetwork.yaml --config xptest.yaml
  artifacts:
    paths:
      - findings.json
    when: always
```
