# chalk-buildkite-plugin

A [Buildkite Plugin](https://buildkite.com/docs/plugins) for installing and configuring
[Chalk](https://crashoverride.run) in your Buildkite pipelines. Chalk wraps build
commands (e.g. `docker build`) to capture metadata and chalk-mark artifacts automatically.

> **PoC status:** Source lives in `chalk-buildkite-plugin/` on the
> `nettrino/expandbuildpipes` branch of `crashappsec/setup-chalk-action`.
> Buildkite requires a dedicated public repo named
> `crashappsec/chalk-buildkite-plugin` before pipelines can reference the plugin as
> `crashappsec/chalk#v1.0.0`. Until then, use the **vendored plugin** or
> **local testing** approaches described below.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Configuration](#configuration)
3. [Quick Start — Vendored Plugin (PoC)](#quick-start--vendored-plugin-poc)
4. [Local Agent Setup](#local-agent-setup)
   - [Create a Buildkite Account](#1-create-a-buildkite-account)
   - [Get an Agent Token](#2-get-an-agent-token)
   - [Run the Agent](#3-run-the-agent)
   - [Create a Pipeline](#4-create-a-pipeline)
   - [Trigger a Build](#5-trigger-a-build)
5. [Local Hook Testing with BATS](#local-hook-testing-with-bats)
6. [Production Setup](#production-setup)
7. [Examples](#examples)
8. [Troubleshooting](#troubleshooting)

---

## How It Works

The plugin runs two hook scripts during the Buildkite job lifecycle:

| Hook | Phase | What it does |
|------|-------|-------------|
| `hooks/environment` | Before checkout completes | Downloads `setup.sh` from `crashappsec/setup-chalk-action`, installs chalk into a build-specific directory, adds it to `PATH`, and persists the environment for subsequent steps |
| `hooks/pre-command` | Before command runs | Verifies chalk is available and logs the version; warns (non-fatal) if chalk is missing |

Once installed, chalk wraps `docker build` and other build tools to capture metadata
and inject chalk marks into the resulting artifacts.

---

## Configuration

All options are set under the plugin key in your `pipeline.yml`:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `version` | string | `latest` | Chalk version to install |
| `load` | string | | Comma- or newline-separated config file paths or URLs to load |
| `connect` | boolean | `false` | Connect to the CrashOverride platform via `CHALK_TOKEN` |
| `profile` | string | `default` | CrashOverride profile name |
| `no_wrap` | boolean | `false` | Skip wrapping docker and other commands |
| `install_dir` | string | build-specific temp dir | Override the chalk installation directory |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CHALK_TOKEN` | API token for the CrashOverride platform (required when `connect: true`) |

Set `CHALK_TOKEN` as a pipeline-level environment variable in the Buildkite UI
(see [Create a Pipeline](#4-create-a-pipeline) below).

---

## Quick Start — Vendored Plugin (PoC)

While the dedicated repo `crashappsec/chalk-buildkite-plugin` does not exist yet,
you can reference the plugin as a **vendored plugin** from within the same repository.
The plugin directory is checked out alongside your code, and Buildkite resolves it
via the relative `./` prefix.

```yaml
# .buildkite/pipeline.yml (at the repo root)
steps:
  - label: ":docker: Build with Chalk"
    command: "docker build -t myapp:${BUILDKITE_BUILD_NUMBER} ."
    plugins:
      - ./chalk-buildkite-plugin:
          version: "0.6.5"
```

This works because:

1. The Buildkite agent checks out the repo (including `chalk-buildkite-plugin/`).
2. Buildkite sees the `./` prefix and loads the plugin from the checkout directory.
3. The `hooks/environment` and `hooks/pre-command` scripts run exactly as they would
   with a published plugin.

---

## Local Agent Setup

Follow these steps end-to-end to test the plugin with a real Buildkite agent.

### 1. Create a Buildkite Account

1. Go to [buildkite.com](https://buildkite.com) and sign up.
2. Create an **Organization** when prompted (e.g. your company name or a test org).

### 2. Get an Agent Token

The agent token authenticates your local agent with the Buildkite platform.

1. In the Buildkite dashboard, click **Settings** (gear icon, top-right).
2. Select **Agents** from the left sidebar.
3. Under **Agent Token**, copy the token value.
   - It looks like `bkct_xxxx...`.
4. Store it locally (do **not** commit it):
   ```bash
   # Option A: direnv (.envrc is already in .gitignore for this repo)
   echo 'export BUILDKITE_AGENT_TOKEN=bkct_xxxx...' >> .envrc
   direnv allow

   # Option B: export directly
   export BUILDKITE_AGENT_TOKEN=bkct_xxxx...
   ```

### 3. Run the Agent

The fastest way to run an agent locally is via Docker. The agent needs:

- The agent token
- Access to the Docker socket (so it can run `docker build` inside jobs)

```bash
docker run -d \
  --name buildkite-agent \
  -e BUILDKITE_AGENT_TOKEN="${BUILDKITE_AGENT_TOKEN}" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  buildkite/agent
```

Verify the agent is connected:

```bash
docker logs -f buildkite-agent
```

You should see output like:

```
Registering agent with Buildkite...
Successfully registered agent "xxxxx" with tags []
Waiting for work...
```

The agent also appears under **Settings → Agents** in the Buildkite dashboard.

#### Alternative: Native Install (Linux)

```bash
# Add the Buildkite apt repo
curl -fsSL https://keys.openpgp.org/vks/v1/by-fingerprint/32A37959C2FA5C3C99EFBC32A79206696BBB0E16 \
  | sudo gpg --dearmor -o /usr/share/keyrings/buildkite-agent-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/buildkite-agent-archive-keyring.gpg] \
  https://apt.buildkite.com/buildkite-agent stable main" \
  | sudo tee /etc/apt/sources.list.d/buildkite-agent.list

sudo apt-get update && sudo apt-get install -y buildkite-agent

# Configure the token
sudo sed -i "s/xxx/${BUILDKITE_AGENT_TOKEN}/g" /etc/buildkite-agent/buildkite-agent.cfg

# Start the agent
sudo systemctl enable buildkite-agent && sudo systemctl start buildkite-agent
```

### 4. Create a Pipeline

1. In the Buildkite dashboard, click **Pipelines** → **New Pipeline**.
2. Fill in:
   - **Name:** `chalk-plugin-test` (or any name)
   - **Repository:** `https://github.com/crashappsec/setup-chalk-action`
   - **Default Branch:** `nettrino/expandbuildpipes`
3. Under **Steps**, select **Read steps from repository** and set the path to:
   ```
   .buildkite/pipeline.yml
   ```
4. Click **Create Pipeline**.

#### Set Environment Variables

If you plan to use `connect: true` in the plugin config:

1. Go to the pipeline's **Settings** → **Environment Variables**.
2. Add `CHALK_TOKEN` with your CrashOverride API token as the value.

### 5. Trigger a Build

1. Make sure the `.buildkite/pipeline.yml` and any test Dockerfile are pushed to the branch:
   ```bash
   git add .buildkite/pipeline.yml .buildkite/Dockerfile.test
   git commit -m "add Buildkite test pipeline"
   git push origin nettrino/expandbuildpipes
   ```
2. In the Buildkite dashboard, open the `chalk-plugin-test` pipeline and click **New Build**.
3. Set **Branch** to `nettrino/expandbuildpipes` and click **Create Build**.
4. Watch the build log. You should see:
   - `--- :chalk: Setting up Chalk` (from the environment hook)
   - `Chalk installed successfully: chalk x.y.z`
   - `--- :chalk: Chalk ready: chalk x.y.z` (from the pre-command hook)
   - The `docker build` output, wrapped by chalk

#### Example Test Pipeline

A minimal pipeline that builds a test image is included at the repo root:

```yaml
# .buildkite/pipeline.yml
steps:
  - label: ":docker: Build with Chalk"
    command: "docker build -f .buildkite/Dockerfile.test -t chalk-test:${BUILDKITE_BUILD_NUMBER} ."
    plugins:
      - ./chalk-buildkite-plugin:
          version: "0.6.5"
```

```dockerfile
# .buildkite/Dockerfile.test
FROM alpine:3.19
RUN echo "Hello from chalk-wrapped build"
CMD ["echo", "Chalk build test successful"]
```

---

## Local Hook Testing with BATS

You can test the plugin hooks without a running agent using
[bats-core](https://github.com/bats-core/bats-core):

```bash
# Install bats
brew install bats-core   # macOS
sudo apt-get install bats # Ubuntu/Debian

# Clone and run tests
git clone --branch nettrino/expandbuildpipes \
  https://github.com/crashappsec/setup-chalk-action.git
cd setup-chalk-action/chalk-buildkite-plugin
bats tests/
```

The test suite covers:

| Test | File | What it verifies |
|------|------|-----------------|
| Environment hook installs chalk | `tests/environment.bats` | Hook exits 0 and prints "Chalk installed successfully" |
| Chalk binary is executable | `tests/environment.bats` | `chalk --version` runs after hook completes |
| Pre-command warns when chalk missing | `tests/pre-command.bats` | Hook prints warning but does not fail the build |
| Pre-command reports chalk version | `tests/pre-command.bats` | Hook prints "Chalk ready" when `CHALK_HOME` is set |

---

## Production Setup

When the plugin graduates from PoC to production:

1. Create a **public** GitHub repository: `crashappsec/chalk-buildkite-plugin`
   (Buildkite requires the `-buildkite-plugin` suffix).
2. Push the contents of `chalk-buildkite-plugin/` to the new repo:
   ```bash
   cd chalk-buildkite-plugin
   git init && git add . && git commit -m "initial release"
   git remote add origin git@github.com:crashappsec/chalk-buildkite-plugin.git
   git push -u origin main
   git tag v1.0.0 && git push --tags
   ```
3. Update pipeline references from the vendored path to the published plugin:
   ```yaml
   # Before (vendored / PoC)
   plugins:
     - ./chalk-buildkite-plugin:
         version: "0.6.5"

   # After (published)
   plugins:
     - crashappsec/chalk#v1.0.0:
         version: "0.6.5"
   ```
4. Set `CHALK_TOKEN` as a pipeline environment variable in the Buildkite dashboard.

---

## Examples

### Basic: Docker build with chalk wrapping

```yaml
steps:
  - label: ":docker: Build"
    command: "docker build -t myapp:${BUILDKITE_COMMIT} ."
    plugins:
      - crashappsec/chalk#v1.0.0:
          version: "0.6.5"
```

### Connected: Report to CrashOverride platform

```yaml
steps:
  - label: ":docker: Build"
    command: "docker build -t myapp:${BUILDKITE_COMMIT} ."
    plugins:
      - crashappsec/chalk#v1.0.0:
          version: "0.6.5"
          connect: true
          profile: "production"
    env:
      CHALK_TOKEN: "${CHALK_TOKEN}"
```

### Build and verify chalk marks

```yaml
steps:
  - label: ":docker: Build with Chalk"
    key: "build"
    command: "docker build -t myapp:${BUILDKITE_COMMIT} ."
    plugins:
      - crashappsec/chalk#v1.0.0:
          version: "0.6.5"
          connect: true
    env:
      CHALK_TOKEN: "${CHALK_TOKEN}"

  - label: ":white_check_mark: Verify Chalk Mark"
    depends_on: "build"
    command: "chalk extract myapp:${BUILDKITE_COMMIT}"
    plugins:
      - crashappsec/chalk#v1.0.0:
          no_wrap: true
    env:
      CHALK_TOKEN: "${CHALK_TOKEN}"
```

### Custom chalk config

```yaml
steps:
  - label: ":gear: Build with custom config"
    command: "docker build -t myapp:${BUILDKITE_COMMIT} ."
    plugins:
      - crashappsec/chalk#v1.0.0:
          version: "0.6.5"
          load: "https://example.com/my-chalk-config.c4m"
```

---

## Troubleshooting

### Agent not picking up jobs

- Verify the agent is running: `docker logs buildkite-agent`
- Check the agent appears in **Settings → Agents** in the Buildkite dashboard.
- If the pipeline specifies `agents:` tags (e.g. `os: linux`), make sure
  your agent was started with matching tags:
  ```bash
  docker run -d \
    -e BUILDKITE_AGENT_TOKEN="${BUILDKITE_AGENT_TOKEN}" \
    -e BUILDKITE_AGENT_TAGS="os=linux" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    buildkite/agent
  ```

### `docker build` fails inside the agent

- The agent container needs access to the Docker socket:
  ```bash
  -v /var/run/docker.sock:/var/run/docker.sock
  ```
- If you get permission errors, the agent process may need to be in the
  `docker` group, or run the container with `--privileged` for testing.

### Chalk installation fails

- The environment hook downloads `setup.sh` from GitHub. Verify the agent
  has outbound internet access:
  ```bash
  docker exec buildkite-agent curl -fsSL https://raw.githubusercontent.com
  ```
- Check the build log for the specific error from `setup.sh`.

### Vendored plugin not found

- Make sure the pipeline YAML uses the `./` prefix:
  ```yaml
  plugins:
    - ./chalk-buildkite-plugin:   # correct
  ```
  not:
  ```yaml
  plugins:
    - chalk-buildkite-plugin:     # wrong — Buildkite will try GitHub
  ```
- Confirm the `chalk-buildkite-plugin/` directory is committed and pushed
  to the branch the pipeline is building.

### `CHALK_TOKEN` not available

- Pipeline environment variables set in the Buildkite UI are only available
  if the pipeline's **Settings → Environment Variables** section includes them.
- For vendored plugin (PoC) testing without CrashOverride, omit `connect: true`
  and the token is not needed — chalk still wraps builds and captures metadata locally.
