# chalk-azure-pipeline-template

Azure DevOps YAML Pipeline Templates for installing and configuring [Chalk](https://crashoverride.run) in your Azure Pipelines.

## Usage

### Step template

```yaml
resources:
  repositories:
    - repository: chalk-templates
      type: git
      name: MyOrg/chalk-pipeline-templates
      ref: refs/tags/v1.0.0

variables:
  - group: chalk-secrets    # Variable group containing CHALK_TOKEN

steps:
  - template: templates/install-chalk.yml@chalk-templates
    parameters:
      version: '0.6.5'
      connect: true
  - script: docker build -t myapp:$(Build.BuildId) .
```

### Job template

```yaml
extends:
  template: templates/chalk-job.yml@chalk-templates
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

## Setup

1. Create two Azure DevOps projects: `chalk-pipeline-templates` and a test project
2. Push this directory's contents to `chalk-pipeline-templates` repo
3. Create a Variable Group `chalk-secrets` with `CHALK_TOKEN` (secret)
4. In the test project, authorize access to the `chalk-pipeline-templates` repo
5. Tag a release: push a tag `v1.0.0`
