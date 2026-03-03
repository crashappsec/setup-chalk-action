# bitbucket-chalk-pipe

A [Bitbucket Pipe](https://support.atlassian.com/bitbucket-cloud/docs/pipes/) (Docker-based) for installing and configuring [Chalk](https://crashoverride.run) in your Bitbucket Pipelines.

**Docker image:** `crashappsec/bitbucket-chalk-pipe`

## Usage

### Option A: Using the pipe

```yaml
pipelines:
  default:
    - step:
        name: Build with Chalk
        services:
          - docker
        script:
          - pipe: docker://crashappsec/bitbucket-chalk-pipe:1.0.0
            variables:
              CHALK_VERSION: "0.6.5"
              CHALK_TOKEN: $CHALK_TOKEN
              CHALK_COMMAND: "chalk wrap -- docker build -t myapp:$BITBUCKET_COMMIT ."
```

### Option B: Direct script (no Docker Hub required)

```yaml
pipelines:
  default:
    - step:
        name: Build with Chalk
        services:
          - docker
        script:
          - curl -fsSL https://raw.githubusercontent.com/crashappsec/setup-chalk-action/main/setup.sh -o /tmp/chalk-setup.sh
          - chmod +x /tmp/chalk-setup.sh
          - CHALK_TOKEN=$CHALK_TOKEN /tmp/chalk-setup.sh --version=0.6.5
          - docker build -t myapp:$BITBUCKET_COMMIT .
```

## Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CHALK_TOKEN` | No | CrashOverride API token |
| `CHALK_VERSION` | No | Chalk version (empty = latest) |
| `CHALK_COMMAND` | No | Command to run after install (default: `chalk --version`) |
| `CHALK_CONNECT` | No | Set `true` to connect to CrashOverride |
| `CHALK_PROFILE` | No | CrashOverride profile name |
| `CHALK_NO_WRAP` | No | Set `true` to skip command wrapping |
| `CHALK_LOAD` | No | Config URLs to load |

## Setup

1. Create accounts: Bitbucket.org and Docker Hub
2. Create Bitbucket repo `bitbucket-chalk-pipe`, enable Pipelines
3. Add repo variables: `CHALK_TOKEN`, `DOCKER_HUB_USERNAME`, `DOCKER_HUB_PASSWORD`
4. Push this directory's contents, then tag: `git tag v1.0.0 && git push origin v1.0.0`
5. Build and push image:
   ```bash
   docker build -t crashappsec/bitbucket-chalk-pipe:1.0.0 .
   docker push crashappsec/bitbucket-chalk-pipe:1.0.0
   ```
