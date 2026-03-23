# Drift Detection Guide

Drift detection (Stage 3) compares the desired state declared in your Crossplane Composition against the observed state in a live AWS account. It uses pull-based, read-only AWS API queries.

## How It Works

```
Composition YAML + XRD
        │
   ┌────┴────┐
   │  Loader  │  Parse composed resources
   └────┬────┘
        │
   ┌────┴────┐
   │ Classify │  Group resources by kind (VPC, S3, RDS, IAM)
   └────┬────┘
        │
   ┌────┴────────────┐
   │  AWS API Query   │  Read-only Describe/Get/List calls
   │  (per family)    │  via boto3
   └────┬────────────┘
        │
   ┌────┴────────────┐
   │   Comparator     │  Field-level desired vs. observed diff
   └────┬────────────┘
        │
   DriftFinding[]
```

1. The loader parses the composition and extracts `spec.forProvider` fields from each composed resource.
2. Resources are grouped by kind into four families: VPC/EC2, S3, RDS, and IAM.
3. For each resource, the appropriate AWS API is called to retrieve the current live state.
4. The comparator performs a recursive field-level diff between desired and observed values.
5. Mismatches are emitted as `DriftFinding` objects with the specific field path, desired value, and observed value.

## Prerequisites

```bash
pip install -e ".[drift]"   # installs boto3
```

AWS credentials must be available through any standard boto3 mechanism.

## Usage

```bash
# Basic drift check
xptest drift \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --region us-east-1

# With config file
xptest drift \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --config xptest.yaml

# Filter to specific resource kinds
# (via xptest.yaml: drift_resource_filter: [VPC, DBInstance])
xptest drift \
  --composition compositions/vpc-network.yaml \
  --xrd definitions/xvpcnetwork.yaml \
  --config xptest.yaml \
  --output vpc-drift.json
```

## Supported Resource Families

### VPC / EC2

| AWS API | Checked fields |
|---------|---------------|
| `DescribeVpcs` | CIDR block, DNS support, DNS hostnames, tags |
| `DescribeSubnets` | CIDR block, availability zone, map public IP, tags |
| `DescribeSecurityGroups` | Ingress/egress rules, protocol, ports, CIDR ranges |
| `DescribeRouteTables` | Routes, associations, tags |

### S3

| AWS API | Checked fields |
|---------|---------------|
| `GetBucketEncryption` | SSE algorithm, KMS key ID |
| `GetBucketPolicy` | Policy document |
| `GetPublicAccessBlock` | Block public ACLs, block public policy, ignore public ACLs, restrict public buckets |

### RDS

| AWS API | Checked fields |
|---------|---------------|
| `DescribeDBInstances` | Engine, engine version, instance class, storage encrypted, publicly accessible, multi-AZ |
| `DescribeDBSubnetGroups` | Subnet IDs, VPC ID |
| `DescribeDBParameterGroups` | Parameter group family |

### IAM

| AWS API | Checked fields |
|---------|---------------|
| `GetRole` | Trust policy (assume role policy document) |
| `GetRolePolicy` | Inline policy document |
| `ListAttachedRolePolicies` | Attached managed policy ARNs |

## IAM Permissions

Drift detection requires exactly 12 read-only IAM actions. A reference policy is provided at `docs/iam-policy.json`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "XptestDriftReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRouteTables",
        "s3:GetBucketEncryption",
        "s3:GetBucketPolicy",
        "s3:GetPublicAccessBlock",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSubnetGroups",
        "rds:DescribeDBParameterGroups",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    }
  ]
}
```

**No write permissions are used.** The framework only reads AWS state.

## OIDC Federation (CI/CD)

For GitHub Actions, use OIDC federation instead of static IAM keys:

1. Create an IAM OIDC identity provider for `token.actions.githubusercontent.com`
2. Create an IAM role with the read-only policy above
3. Attach a trust policy (see `docs/iam-policy.json` for the template):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:OWNER/REPO:environment:aws-drift"
        }
      }
    }
  ]
}
```

4. In your workflow, use `aws-actions/configure-aws-credentials` with `role-to-assume`.

## Output

Drift findings are written to `drift-findings.json` (or `--output` path):

```json
[
  {
    "resource_name": "my-vpc",
    "resource_kind": "VPC",
    "field_path": "spec.forProvider.enableDnsSupport",
    "desired": true,
    "observed": false,
    "severity": "WARNING",
    "message": "Field drift: enableDnsSupport is false in AWS but true in composition"
  }
]
```

## Resource Filtering

Use `drift_resource_filter` in `xptest.yaml` to limit which resource kinds are checked:

```yaml
drift_resource_filter:
  - VPC
  - DBInstance
```

When the filter is empty (default), all supported kinds are checked.

## Comparator Behavior

The field comparator handles several normalization cases:

- **Boolean normalization:** AWS may return `"true"` (string) vs. `true` (boolean). The comparator normalizes before comparing.
- **AWS-managed fields:** Fields added by AWS (e.g., `VpcId`, `OwnerId`) that are not in the desired state are ignored.
- **Nested comparison:** Objects and lists are compared recursively at the field level.

## Scheduling

Drift detection is designed to run on a schedule (e.g., every 6 hours) rather than on every PR. It does not block merges — it generates alerts. See [CI/CD Integration](ci-cd.md) for workflow configuration.
