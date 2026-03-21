# schemas/

This directory holds CRD bundle directories used by Layers 1 and 2.

## How to use

Point `crd_bundle_path` in `xptest.yaml` to a directory that contains the
`CustomResourceDefinition` YAML files for your provider version.

```yaml
# xptest.yaml
crd_bundle_path: ./schemas/my-provider-v1.2.3
```

## sample-bundle/

`schemas/sample-bundle/` contains minimal CRD stubs for four AWS resource
families used in the thesis evaluation:

- `ec2.vpc.yaml`          — VPC (ec2.aws.upbound.io or ec2.aws.crossplane.io)
- `ec2.subnet.yaml`       — Subnet
- `iam.role.yaml`         — IAM Role
- `rds.dbinstance.yaml`   — RDS DB Instance

These stubs include only the fields needed by the framework tests.
Replace them with real CRD files from your provider package before
running against production compositions.

## Generating a real bundle

For Upbound provider-aws, export CRDs with:
```
kubectl get crds -o yaml > schemas/provider-aws-v<version>/all.yaml
```
or fetch individual CRD YAML files from the provider's GitHub release assets.

For crossplane-contrib/provider-aws, follow the equivalent export procedure
for your provider version.
