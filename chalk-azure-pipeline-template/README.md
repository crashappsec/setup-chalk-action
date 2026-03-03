# chalk-azure-pipeline-template

Azure DevOps YAML Pipeline Templates for installing and configuring [Chalk](https://crashoverride.run) in your Azure Pipelines.

## PoC Usage

Templates are currently in the `nettrino/expandbuildpipes` branch of
`crashappsec/setup-chalk-action`. Reference them via a GitHub service connection
until a dedicated Azure Repos project is set up.

### Step template

```yaml
resources:
  repositories:
    - repository: chalk-templates
      type: github
      name: crashappsec/setup-chalk-action
      ref: refs/heads/nettrino/expandbuildpipes
      endpoint: github-crashappsec  # GitHub service connection name

variables:
  - group: chalk-secrets    # Variable group containing CHALK_TOKEN

steps:
  - template: chalk-azure-pipeline-template/templates/install-chalk.yml@chalk-templates
    parameters:
      version: '0.6.5'
      connect: true
  - script: docker build -t myapp:$(Build.BuildId) .
```

### Job template

```yaml
extends:
  template: chalk-azure-pipeline-template/templates/chalk-job.yml@chalk-templates
  parameters:
    chalkVersion: '0.6.5'
    chalkConnect: true
    buildSteps:
      - script: docker build -t myapp:$(Build.BuildId) .
        displayName: Docker Build
```

## Template Parameters

### `install-chalk.yml`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `version` | string | `''` | Chalk version (empty = latest) |
| `load` | string | `''` | Config URLs to load |
| `connect` | boolean | `false` | Connect to CrashOverride |
| `profile` | string | `'default'` | Profile name |
| `noWrap` | boolean | `false` | Skip command wrapping |
| `chalkTokenVar` | string | `'CHALK_TOKEN'` | Variable name holding the token |

## Setup (PoC)

1. Create an Azure DevOps account and project at dev.azure.com
2. Create a **GitHub service connection** named `github-crashappsec`:
   - Project Settings → Service connections → New → GitHub
3. Create a Variable Group `chalk-secrets` with `CHALK_TOKEN` (secret):
   - Pipelines → Library → Variable groups
4. Create a pipeline using `examples/azure-pipelines.yml`

## Setup (Production)

1. Create Azure DevOps project `chalk-pipeline-templates`
2. Push this directory's contents to it
3. Update `resources.repositories` to use `type: git, name: MyOrg/chalk-pipeline-templates`
4. Remove the `endpoint:` line and update template paths to remove the `chalk-azure-pipeline-template/` prefix
5. Tag a release: `v1.0.0`
