# Chalk Bitbucket Pipe

> **PoC:** Source lives in `bitbucket/` on the `nettrino/expandbuildpipes`
> branch of `crashappsec/setup-chalk-action`. The Docker image
> `crashappsec/bitbucket-chalk-pipe` has not been published yet. Use **Option B**
> (direct script) below until the image is built and pushed.

A [Bitbucket Pipe](https://support.atlassian.com/bitbucket-cloud/docs/pipes/) (Docker-based) for installing and configuring [Chalk](https://crashoverride.run) in your Bitbucket Pipelines.

**Docker image:** `crashappsec/bitbucket-chalk-pipe` _(not yet published)_

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

## Setup (PoC — direct script, no Docker image needed)

Copy `examples/consumer-script.yml` as your `bitbucket-pipelines.yml`. It fetches
`setup.sh` from `crashappsec/setup-chalk-action` directly — no pipe image required.

## Setup (Production — publish the Docker image)

1. Create accounts: Bitbucket.org and Docker Hub
2. Clone and push the subdirectory to a new Bitbucket repo:
   ```bash
   git clone --branch nettrino/expandbuildpipes \
     https://github.com/crashappsec/setup-chalk-action.git
   cd setup-chalk-action/bitbucket
   git init && git add . && git commit -m "initial"
   git remote add origin git@bitbucket.org:<your-workspace>/bitbucket-chalk-pipe.git
   git push -u origin main
   ```
3. Add repo variables: `CHALK_TOKEN`, `DOCKER_HUB_USERNAME`, `DOCKER_HUB_PASSWORD`
4. Build and push the image:
   ```bash
   docker build -t crashappsec/bitbucket-chalk-pipe:1.0.0 .
   docker push crashappsec/bitbucket-chalk-pipe:1.0.0
   ```
