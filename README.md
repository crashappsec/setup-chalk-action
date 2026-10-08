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

| Name                 | Type    | Default              | Description                                                                                                                                                                                                       |
| -------------------- | ------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`            | String  |                      | Version of chalk to install. By default latest version is installed. See [releases] for all available versions. When `connect` is true, if version is left empty, its looked up from CrashOverride Chalk profile. |
| `latest_version_url` | String  |                      | URL where to query for the latest chalk version.                                                                                                                                                                  |
| `load`               | String  |                      | Chalk config(s) to load - comma or new-line delimited. Can be either paths to files or URLs.                                                                                                                      |
| `params`             | String  |                      | Chalk components params to load. Should be JSON array with all parameter values. JSON structure is the same as provided by `chalk dump params`.                                                                   |
| `connect`            | Boolean | `false`              | Whether to automatically connect to https://crashoverride.run.                                                                                                                                                    |
| `profile`            | String  | `default`            | Key of the custom CrashOverride profile to load.                                                                                                                                                                  |
| `token`              | String  |                      | CrashOverride API Token. It is automatically fetched via OpenID connect if not provided when `connect=true`.                                                                                                      |
| `password`           | String  |                      | Password for chalk signing key. Password is displayed as part of `chalk setup`.                                                                                                                                   |
| `public_key`         | String  |                      | Content of chalk signing public key). Copy from `chalk.pub` after `chalk setup`.                                                                                                                                  |
| `private_key`        | String  |                      | Content of chalk signing encrypted private key (with the provided password). Copy from `chalk.key` after `chalk setup`.                                                                                           |
| `policy_report`      | Boolean | `true`               | Whether to show chalk build policy findings at the end of the job as a job summary and annotations on the Dockerfile. See [Build policies](#build-policies).                                                      |
| `policy_check`       | Boolean | `false`              | Whether to also create a check run for build policies on the commit, which can be made a required check. Needs `checks: write`.                                                                                   |
| `policy_check_name`  | String  | `Chalk build policy` | Name of the build policy check run.                                                                                                                                                                               |

For example:

```yaml
- name: Set up Chalk
  uses: crashappsec/setup-chalk-action@main
  with:
    version: 1.0.0
    latest_version_url: https://dl.crashoverride.run/chalk/current-version.txt
    connect: true
    profile: myprofile
    load: https://chalkdust.io/debug.c4m
    password: ${{ secrets.CHALK_PASSWORD }}
    public_key: ${{ secrets.CHALK_PUBLIC_KEY }}
    private_key: ${{ secrets.CHALK_PRIVATE_KEY }}
```

## Build policies

When chalk [build policies][policies] are enabled (for example via the
Crash Override profile), chalk evaluates them on every wrapped
`docker build` and `docker push`. An `enforce` policy with a violation
stops the command before docker runs, failing the step.

At the end of the job, the action shows what the policies found:

- a **job summary** with the evaluated policies and every finding;
- **annotations** on the Dockerfile line that referenced the image, shown
  on the workflow run and in the pull request's "Files changed" tab.
  Blocking findings are errors and audit findings are warnings.

Nothing is shown when policies are off or find nothing.

With `policy_check: true` the action also creates a check run
(`Chalk build policy` by default) on the commit. Its conclusion is
`failure` when a policy blocked a command, `neutral` for findings that are
not enforced and `success` otherwise, so it can be made a required check
in branch protection or rulesets:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      checks: write
    steps:
      - uses: actions/checkout@v4
      - uses: crashappsec/setup-chalk-action@main
        with:
          connect: true
          policy_check: true
      - run: docker build -t app .
```

Notes:

- The check run is created for jobs that ran at least one
  `docker build` or `docker push`. A required check is never reported for
  pull requests that do not run such a job.
- Pull requests from forks get a read-only token, so no check run is
  created for them; the summary and annotations still work.
- Every job that builds creates its own check run with the same name.

[chalk]: https://github.com/crashappsec/chalk/
[releases]: https://crashoverride.com/releases
[CrashOverride]: https://crashoverride.run
[policies]: https://github.com/crashappsec/chalk/blob/main/docs/design-build-policy.md

## Contributing

We welcome contributions but do require you to complete a contributor
license agreement or CLA. You can read the CLA and about our process
[here](https://github.com/crashappsec/.github/blob/main/CLA-process.md).
