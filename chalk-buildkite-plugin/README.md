# chalk-buildkite-plugin

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

## Setup

1. Create a public GitHub repository `chalk-buildkite-plugin`
2. Push this directory's contents to it
3. In your Buildkite pipeline settings, add `CHALK_TOKEN` as an environment variable

## Testing

```bash
# Install bats-core
brew install bats-core  # macOS
apt-get install bats    # Ubuntu

# Run tests
bats tests/
```
