# Setup Chalk

GitHub Action for setting up [Chalk].

Chalk captures metadata at build time, and adds a small 'chalk mark' (metadata)
to any artifacts, so they can be identified in production. This GitHub action
simplifies the process of deploying `chalk` for GitHub action users. The
action:

- Installs `chalk` CLI in the GitHub runner (hosted and
  self-hosted). You can then start using `chalk` in your GitHub workflows.
- Wraps `docker` with `chalk`. As such, any GitHub workflows using `docker`
  will automatically start using `chalk` when building any Docker images.
- Allows to `load` `chalk` configuration from a file or an URL. For
  example this can configure `chalk` to send metadata reports to an
  external server for metadata collection.

## Usage

```yaml
name: ci

on:
  push:

jobs:
  buildx:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Set up Chalk
        uses: crashappsec/setup-chalk-action@main
```

## Customizing

The following parameters can be provided to the action.

| Name      | Type   | Default | Description                                                                                                     |
| --------- | ------ | ------- | --------------------------------------------------------------------------------------------------------------- |
| `version` | String |         | Version of chalk to install. By default latest version is installed. See [releases] for all available versions. |
| `load`    | String |         | Chalk config to load. Can be either path to a file or an URL.                                                   |

For example:

```yaml
- name: Set up Chalk
  uses: crashappsec/setup-chalk-action@main
  with:
    version: "0.2.0"
    load: "https://chalkdust.io/compliance-docker.c4m"
```

[chalk]: https://github.com/crashappsec/chalk/
[releases]: https://crashoverride.com/releases

## Contributing

We welcome contributions but do require you to complete a contributor
license agreement or CLA. You can read the CLA and about our process
[here](https://github.com/crashappsec/.github/blob/main/CLA-process.md).
