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

| Name          | Type    | Default   | Description                                                                                                                                     |
| ------------- | ------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`     | String  | `latest`  | Version of chalk to install. By default latest version is installed. See [releases] for all available versions.                                 |
| `load`        | String  |           | Chalk config(s) to load - comma or new-line delimited. Can be either paths to files or URLs.                                                    |
| `params`      | String  |           | Chalk components params to load. Should be JSON array with all parameter values. JSON structure is the same as provided by `chalk dump params`. |
| `connect`     | Boolean | `false`   | Whether to automatically connect to https://crashoverride.run.                                                                                  |
| `profile`     | String  | `default` | Key of the custom CrashOverride profile to load.                                                                                                |
| `token`       | String  |           | CrashOverride API Token. It is automatically fetched via OpenID connect if not provided when `connect=true`.                                    |
| `password`    | String  |           | Password for chalk signing key. Password is displayed as part of `chalk setup`.                                                                 |
| `public_key`  | String  |           | Content of chalk signing public key). Copy from `chalk.pub` after `chalk setup`.                                                                |
| `private_key` | String  |           | Content of chalk signing encrypted private key (with the provided password). Copy from `chalk.key` after `chalk setup`.                         |

For example:

```yaml
- name: Set up Chalk
  uses: crashappsec/setup-chalk-action@main
  with:
    version: 0.5.7
    connect: true
    profile: myprofile
    load: https://chalkdust.io/debug.c4m
    password: ${{ secrets.CHALK_PASSWORD }}
    public_key: ${{ secrets.CHALK_PUBLIC_KEY }}
    private_key: ${{ secrets.CHALK_PRIVATE_KEY }}
```

[chalk]: https://github.com/crashappsec/chalk/
[releases]: https://crashoverride.com/releases
[CrashOverride]: https://crashoverride.run

## Contributing

We welcome contributions but do require you to complete a contributor
license agreement or CLA. You can read the CLA and about our process
[here](https://github.com/crashappsec/.github/blob/main/CLA-process.md).
