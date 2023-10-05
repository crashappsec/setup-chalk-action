# Setup Chalk

GitHub Action for setting up [Chalk].

This action will install `chalk` and will also wrap other commands
`chalk` supports such as `docker`.

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
        uses: crashappsec/setup-chalk-version
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
  uses: crashappsec/setup-chalk-version
  with:
    version: "0.1.2"
    load: "https://chalkdust.io/compliance-docker.c4m"
```

[chalk]: https://github.com/crashappsec/chalk/
[releases]: https://crashoverride.com/releases

## Contributing

We welcome contributions but do require you to complete a contributor
license agreement or CLA. You can read the CLA and about our process
[here](https://crashoverride.com/docs/other/contributing).
