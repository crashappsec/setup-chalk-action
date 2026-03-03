# chalk-circleci-orb

> **PoC:** Source lives in `chalk-circleci-orb/` on the `nettrino/expandbuildpipes`
> branch of `crashappsec/setup-chalk-action`. Pack and publish from that subdirectory
> directly — no separate GitHub repo needed to publish to the orb registry.

A [CircleCI Orb](https://circleci.com/orbs/) for installing and configuring [Chalk](https://crashoverride.run) in your CircleCI pipelines.

**Published Orb:** `crashappsec/chalk`

## Usage

```yaml
version: 2.1

orbs:
  chalk: crashappsec/chalk@1.0.0

jobs:
  build:
    docker:
      - image: cimg/base:current
    steps:
      - checkout
      - chalk/install:
          version: "0.6.5"
          connect: true
      - run:
          name: Build
          command: docker build -t myapp:$CIRCLE_SHA1 .

workflows:
  main:
    jobs:
      - build
```

## Commands

### `chalk/install`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `version` | string | `""` | Chalk version (empty = latest) |
| `load` | string | `""` | Config URLs to load |
| `connect` | boolean | `false` | Connect to CrashOverride |
| `profile` | string | `"default"` | Profile name |
| `no_wrap` | boolean | `false` | Skip command wrapping |
| `install_dir` | string | `/usr/local/bin` | Install directory |
| `use_cache` | boolean | `true` | Cache binary between runs |

## Setup

```bash
# Install CircleCI CLI
curl -fLSs https://raw.githubusercontent.com/CircleCI-Public/circleci-cli/master/install.sh | bash
circleci setup

# Create namespace (one-time)
circleci namespace create crashappsec github crashappsec

# Create orb (one-time)
circleci orb create crashappsec/chalk

# Clone branch and publish from subdirectory
git clone --branch nettrino/expandbuildpipes \
  https://github.com/crashappsec/setup-chalk-action.git
cd setup-chalk-action/chalk-circleci-orb

circleci orb pack src/ > /tmp/chalk-orb.yml
circleci orb validate /tmp/chalk-orb.yml
circleci orb publish /tmp/chalk-orb.yml crashappsec/chalk@dev:first

# Promote to production
circleci orb publish promote crashappsec/chalk@dev:first patch
```
