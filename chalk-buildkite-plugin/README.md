# chalk-buildkite-plugin

> **PoC:** Source lives in `chalk-buildkite-plugin/` on the `nettrino/expandbuildpipes`
> branch of `crashappsec/setup-chalk-action`. Buildkite requires a dedicated public repo
> named `crashappsec/chalk-buildkite-plugin` before pipelines can reference the plugin
> as `crashappsec/chalk#v1.0.0`. Until then, use the hooks directly for local testing.

A [Buildkite Plugin](https://buildkite.com/docs/plugins) for installing and configuring [Chalk](https://crashoverride.run) in your Buildkite pipelines.

## Usage

```yaml
steps:
  - label: "Build with Chalk"
    command: "docker build -t myapp:$BUILDKITE_COMMIT ."
    plugins:
      - crashappsec/chalk#v1.0.0:
          version: "0.6.5"
          connect: true
          profile: "production"
    env:
      CHALK_TOKEN: "${CHALK_TOKEN}"
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `version` | string | latest | Chalk version to install |
| `load` | string | | Config file paths or URLs to load |
| `connect` | boolean | `false` | Connect to CrashOverride platform |
| `profile` | string | `default` | CrashOverride profile name |
| `no_wrap` | boolean | `false` | Skip wrapping docker and other commands |
| `install_dir` | string | build-specific temp | Override installation directory |

## Setup (PoC — local hook testing)

```bash
git clone --branch nettrino/expandbuildpipes \
  https://github.com/crashappsec/setup-chalk-action.git
cd setup-chalk-action/chalk-buildkite-plugin
bats tests/
```

## Setup (Production)

1. Create a public GitHub repository `crashappsec/chalk-buildkite-plugin`
2. Push this directory's contents to it and tag `v1.0.0`
3. In your Buildkite pipeline settings, add `CHALK_TOKEN` as an environment variable

## Testing

```bash
# Install bats-core
brew install bats-core  # macOS
apt-get install bats    # Ubuntu

# Run tests
bats tests/
```
