# GitHub Action — Setup Chalk

GitHub Action for installing and configuring [Chalk](https://crashoverride.run) in your GitHub workflows.

> **Note:** `action.yml` and `setup.sh` live at the repository root for backwards
> compatibility (`uses: crashappsec/setup-chalk-action@main`).

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

## Inputs

| Name                 | Type    | Default   | Description                                                                                                                                                                                                       |
| -------------------- | ------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`            | String  |           | Version of chalk to install. By default latest version is installed. See [releases] for all available versions. When `connect` is true, if version is left empty, its looked up from CrashOverride Chalk profile. |
| `latest_version_url` | String  |           | URL where to query for the latest chalk version.                                                                                                                                                                  |
| `load`               | String  |           | Chalk config(s) to load - comma or new-line delimited. Can be either paths to files or URLs.                                                                                                                      |
| `params`             | String  |           | Chalk components params to load. Should be JSON array with all parameter values. JSON structure is the same as provided by `chalk dump params`.                                                                   |
| `connect`            | Boolean | `false`   | Whether to automatically connect to https://crashoverride.run.                                                                                                                                                    |
| `profile`            | String  | `default` | Key of the custom CrashOverride profile to load.                                                                                                                                                                  |
| `token`              | String  |           | CrashOverride API Token. It is automatically fetched via OpenID connect if not provided when `connect=true`.                                                                                                      |
| `password`           | String  |           | Password for chalk signing key. Password is displayed as part of `chalk setup`.                                                                                                                                   |
| `public_key`         | String  |           | Content of chalk signing public key). Copy from `chalk.pub` after `chalk setup`.                                                                                                                                  |
| `private_key`        | String  |           | Content of chalk signing encrypted private key (with the provided password). Copy from `chalk.key` after `chalk setup`.                                                                                           |

## Example

```yaml
- name: Set up Chalk
  uses: crashappsec/setup-chalk-action@main
  with:
    version: 0.6.5
    latest_version_url: https://dl.crashoverride.run/chalk/current-version.txt
    connect: true
    profile: myprofile
    load: https://chalkdust.io/debug.c4m
    password: ${{ secrets.CHALK_PASSWORD }}
    public_key: ${{ secrets.CHALK_PUBLIC_KEY }}
    private_key: ${{ secrets.CHALK_PRIVATE_KEY }}
```

## How It Works

The action:

- Installs the `chalk` CLI in the GitHub runner (hosted and self-hosted).
- Wraps `docker` with `chalk` so any Docker builds automatically capture metadata.
- Allows loading `chalk` configuration from a file or URL.

[chalk]: https://github.com/crashappsec/chalk/
[releases]: https://crashoverride.com/releases
[CrashOverride]: https://crashoverride.run
