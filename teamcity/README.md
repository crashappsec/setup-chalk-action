# Chalk TeamCity Integration

> **PoC:** Source lives in `teamcity/` on the `nettrino/expandbuildpipes`
> branch of `crashappsec/setup-chalk-action`. No dedicated repo is required —
> the meta-runner XML is uploaded directly to TeamCity via the UI.

TeamCity Meta-Runner and Kotlin DSL configuration for installing and configuring [Chalk](https://crashoverride.run) in your TeamCity builds.

## Files

- `.teamcity/chalk-meta-runner.xml` — TeamCity Meta-Runner (upload via UI)
- `.teamcity/settings.kts` — Kotlin DSL build configuration
- `docker-compose.yml` — Local TeamCity server for testing

## Quick Start (Local TeamCity)

```bash
git clone --branch nettrino/expandbuildpipes \
  https://github.com/crashappsec/setup-chalk-action.git
cd setup-chalk-action/teamcity
docker-compose up -d
# Open http://localhost:8111
# Complete setup wizard, choose Internal DB, create admin user
```

## Installing the Meta-Runner

1. In TeamCity: Administration → Meta-Runners → Upload Meta-Runner
2. Upload `.teamcity/chalk-meta-runner.xml`
3. The "Setup Chalk" runner will now appear in build step options

## Using the Meta-Runner

In a build configuration:
1. Add a build step, select "Setup Chalk" runner
2. Configure parameters:
   - **Chalk Version**: leave empty for latest, or specify e.g. `0.6.5`
   - **Connect to CrashOverride**: check to enable
   - **Profile**: `default` or your profile name
3. Add a password parameter `env.CHALK_TOKEN` with your API token

## Kotlin DSL

To use the provided `settings.kts` configuration:
1. Enable versioned settings in your project
2. Copy `.teamcity/settings.kts` to your project's `.teamcity/` directory
3. Update the `credentialsJSON:chalk-token-id` reference with your actual credential ID

## Setup (Local PoC)

```bash
# Start server and agent
docker-compose up -d

# Wait for server to start (~60 seconds), then open:
open http://localhost:8111

# After completing wizard:
# 1. Authorize the build agent
# 2. Create a project
# 3. Add env.CHALK_TOKEN as a password parameter
# 4. Upload the meta-runner XML
# 5. Create a build configuration using the Setup Chalk step
```
