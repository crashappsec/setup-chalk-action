# Chalk CI/CD Integrations — Setup Guide

## Current State (PoC)

All integration code lives in subdirectories of this repo on the
**`nettrino/expandbuildpipes`** branch of
[`crashappsec/setup-chalk-action`](https://github.com/crashappsec/setup-chalk-action/tree/nettrino/expandbuildpipes).
No separate repos have been created yet.

| Platform | Subdirectory | Branch path |
|----------|-------------|-------------|
| GitLab CI/CD | `chalk-gitlab-component/` | [`nettrino/expandbuildpipes/chalk-gitlab-component`](https://github.com/crashappsec/setup-chalk-action/tree/nettrino/expandbuildpipes/chalk-gitlab-component) |
| Jenkins | `chalk-jenkins-library/` | [`nettrino/expandbuildpipes/chalk-jenkins-library`](https://github.com/crashappsec/setup-chalk-action/tree/nettrino/expandbuildpipes/chalk-jenkins-library) |
| Buildkite | `chalk-buildkite-plugin/` | [`nettrino/expandbuildpipes/chalk-buildkite-plugin`](https://github.com/crashappsec/setup-chalk-action/tree/nettrino/expandbuildpipes/chalk-buildkite-plugin) |
| CircleCI | `chalk-circleci-orb/` | [`nettrino/expandbuildpipes/chalk-circleci-orb`](https://github.com/crashappsec/setup-chalk-action/tree/nettrino/expandbuildpipes/chalk-circleci-orb) |
| Azure DevOps | `chalk-azure-pipeline-template/` | [`nettrino/expandbuildpipes/chalk-azure-pipeline-template`](https://github.com/crashappsec/setup-chalk-action/tree/nettrino/expandbuildpipes/chalk-azure-pipeline-template) |
| Bitbucket | `bitbucket-chalk-pipe/` | [`nettrino/expandbuildpipes/bitbucket-chalk-pipe`](https://github.com/crashappsec/setup-chalk-action/tree/nettrino/expandbuildpipes/bitbucket-chalk-pipe) |
| TeamCity | `chalk-teamcity/` | [`nettrino/expandbuildpipes/chalk-teamcity`](https://github.com/crashappsec/setup-chalk-action/tree/nettrino/expandbuildpipes/chalk-teamcity) |

When each integration is validated, create a dedicated repo for it and update the
references (see the **Production** note in each platform section below).

---

## Overview

| Platform | Integration Type | Priority |
|----------|-----------------|----------|
| GitLab CI/CD | Pipeline Execution Policy (Ultimate) / inline (Free) | High |
| Jenkins | Shared Library | High |
| Buildkite | Plugin | High |
| CircleCI | Orb | Medium |
| Azure DevOps | YAML Pipeline Template | Medium |
| Bitbucket | Pipe (Docker image) | Medium |
| TeamCity | Meta-Runner + Kotlin DSL | Low |

All integrations use `setup.sh` from this repo at runtime via:
```
curl -fsSL https://raw.githubusercontent.com/crashappsec/setup-chalk-action/main/setup.sh
```

---

## 1. GitLab CI/CD

**Source:** `chalk-gitlab-component/` on the `nettrino/expandbuildpipes` branch

Two tiers:
- **Ultimate**: Pipeline Execution Policy — configure once, applies automatically to all group pipelines
- **Free / Premium**: Add the chalk setup directly to each repo's `.gitlab-ci.yml`

### Ultimate: Pipeline Execution Policy

1. **Create GitLab account** at gitlab.com (if not already done)
2. **Create a policy project** in your group, e.g. `your-group/chalk-policy` (can be private)
3. **Push the `chalk-gitlab-component/` subdirectory** as the policy project:
   ```bash
   git clone --branch nettrino/expandbuildpipes \
     https://github.com/crashappsec/setup-chalk-action.git
   cd setup-chalk-action/chalk-gitlab-component
   git init && git add . && git commit -m "initial"
   git remote add origin git@gitlab.com:your-group/chalk-policy.git
   git push -u origin main
   ```
4. **Set group CI/CD variable** `CHALK_POST_URL`:
   - Group → Settings → CI/CD → Variables → Add variable
   - Value: your report collection endpoint (CrashOverride platform sink, or any HTTP endpoint)
5. **Edit `.gitlab/security-policies/policy.yml`** — replace placeholders:
   - `your-group/chalk-policy` → your actual policy project path
   - `YOUR_GROUP_ID` → your GitLab group ID (found at Group → Settings → General)
6. **Link the policy project to your group:**
   - Group → Security → Policies → Edit policy project → select `your-group/chalk-policy`

Every pipeline in the group now gets chalk automatically.

### Free / Premium: Per-Repository

Copy `chalk-gitlab-component/examples/per-repo.yml` into your repository's
`.gitlab-ci.yml` (or merge the `before_script`/`after_script` blocks into your
existing build job), then set `CHALK_POST_URL` as a project-level CI/CD variable.

> **Production:** Create a dedicated GitLab project `chalk-security-policy` (or similar)
> and push `chalk-gitlab-component/` there. Update the policy `project:` reference.

---

## 2. Jenkins Shared Library

**Source:** `chalk-jenkins-library/` on the `nettrino/expandbuildpipes` branch

Jenkins supports pointing a shared library directly at a subdirectory of an existing
repo — no separate repo needed for PoC.

1. **Run Jenkins locally:**
   ```bash
   docker run -p 8080:8080 -p 50000:50000 \
     -v jenkins_home:/var/jenkins_home \
     -v /var/run/docker.sock:/var/run/docker.sock \
     jenkins/jenkins:lts-jdk17
   ```
2. **Complete setup wizard** at http://localhost:8080
3. **Register the shared library** (Manage Jenkins → Configure System → Global Pipeline Libraries):
   - Name: `chalk-jenkins-library`
   - Default version: `nettrino/expandbuildpipes`
   - SCM: Git
   - URL: `https://github.com/crashappsec/setup-chalk-action`
   - Library Path: `chalk-jenkins-library/`
4. **Add credential:**
   - Manage Jenkins → Manage Credentials → System → Global
   - Kind: Secret text, ID: `chalk-api-token`, Secret: your Chalk token
5. **Create Pipeline job** using the example from
   `chalk-jenkins-library/examples/Jenkinsfile`

> **Production:** Create a dedicated repo `chalk-jenkins-library`, push the subdirectory
> contents there, and update the library URL and default version to `main`.

---

## 3. Buildkite Plugin

**Source:** `chalk-buildkite-plugin/` on the `nettrino/expandbuildpipes` branch

> **Note:** Buildkite requires the plugin to be in its own public GitHub repository
> named `<org>/<name>-buildkite-plugin`. The subdirectory approach works for local
> hook testing only — a dedicated repo is required before referencing it in pipelines
> as `crashappsec/chalk#v1.0.0`.

### Local hook testing (PoC)

```bash
git clone --branch nettrino/expandbuildpipes \
  https://github.com/crashappsec/setup-chalk-action.git
cd setup-chalk-action/chalk-buildkite-plugin

# Install bats-core
brew install bats-core   # macOS
apt-get install bats     # Ubuntu

bats tests/
```

### Running with a Buildkite agent

1. **Create Buildkite account** at buildkite.com
2. **Install and configure an agent** with your Buildkite token
3. **Create a pipeline** and reference the plugin from the source directory
   until `crashappsec/chalk-buildkite-plugin` is created as a dedicated repo

> **Production:** Create a dedicated public repo `crashappsec/chalk-buildkite-plugin`,
> push `chalk-buildkite-plugin/` there, and tag `v1.0.0`.

---

## 4. CircleCI Orb

**Source:** `chalk-circleci-orb/` on the `nettrino/expandbuildpipes` branch

The orb source can be packed and published from the subdirectory directly — no
separate GitHub repo needed to publish to the CircleCI Orb Registry.

1. **Create CircleCI account** at circleci.com (connect your GitHub)
2. **Install CircleCI CLI:**
   ```bash
   brew install circleci   # macOS
   curl -fLSs https://raw.githubusercontent.com/CircleCI-Public/circleci-cli/master/install.sh | sudo bash   # Linux
   ```
3. **Authenticate:** `circleci setup`
4. **Create namespace** (one-time):
   ```bash
   circleci namespace create crashappsec github crashappsec
   ```
5. **Create the orb:**
   ```bash
   circleci orb create crashappsec/chalk
   ```
6. **Clone the branch and publish:**
   ```bash
   git clone --branch nettrino/expandbuildpipes \
     https://github.com/crashappsec/setup-chalk-action.git
   cd setup-chalk-action/chalk-circleci-orb

   circleci orb pack src/ > /tmp/chalk-orb.yml
   circleci orb validate /tmp/chalk-orb.yml
   circleci orb publish /tmp/chalk-orb.yml crashappsec/chalk@dev:first
   ```
7. **Promote to production:**
   ```bash
   circleci orb publish promote crashappsec/chalk@dev:first patch
   ```
8. **Add `CHALK_TOKEN`** to CircleCI project environment variables

> **Production:** Create a dedicated repo `chalk-circleci-orb`, push the subdirectory
> contents there, and enable CI/CD for automated publishing.

---

## 5. Azure DevOps Pipeline Template

**Source:** `chalk-azure-pipeline-template/` on the `nettrino/expandbuildpipes` branch

Azure DevOps can reference templates from a GitHub repository directly via a
[GitHub service connection](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints?view=azure-devops#github-service-connection)
— no Azure Repos mirror needed for PoC.

1. **Create Azure DevOps account** at dev.azure.com and create an organization
2. **Create a GitHub service connection** in your Azure DevOps project:
   - Project Settings → Service connections → New → GitHub
   - Name it `github-crashappsec`
3. **Create a Variable Group `chalk-secrets`:**
   - Pipelines → Library → Variable groups → Add variable `CHALK_TOKEN` (secret)
4. **Create a pipeline** using the adapted consumer example below:
   ```yaml
   resources:
     repositories:
       - repository: chalk-templates
         type: github
         name: crashappsec/setup-chalk-action
         ref: refs/heads/nettrino/expandbuildpipes
         endpoint: github-crashappsec

   variables:
     - group: chalk-secrets

   steps:
     - template: chalk-azure-pipeline-template/templates/install-chalk.yml@chalk-templates
       parameters:
         version: '0.6.5'
         connect: true
   ```
5. **Run the pipeline** to validate

> **Production:** Create a dedicated Azure DevOps project `chalk-pipeline-templates`,
> push `chalk-azure-pipeline-template/` there, and update the `resources.repositories`
> block to use `type: git` pointing at the Azure Repos project.

---

## 6. Bitbucket Pipe

**Source:** `bitbucket-chalk-pipe/` on the `nettrino/expandbuildpipes` branch

The Docker image (`crashappsec/bitbucket-chalk-pipe`) has not been published yet.
Use the direct-script approach for PoC — it works without the Docker image and
references `setup.sh` directly.

### Direct-script PoC (recommended until image is published)

Copy `bitbucket-chalk-pipe/examples/consumer-script.yml` as your
`bitbucket-pipelines.yml`. It uses `setup.sh` from this repo directly, with no
Docker image required.

### Building and publishing the pipe image

1. **Create a Docker Hub account** (hub.docker.com)
2. **Create a Bitbucket account** and repository `bitbucket-chalk-pipe` (public)
3. **Clone and push the subdirectory:**
   ```bash
   git clone --branch nettrino/expandbuildpipes \
     https://github.com/crashappsec/setup-chalk-action.git
   cd setup-chalk-action/bitbucket-chalk-pipe
   git init && git add . && git commit -m "initial"
   git remote add origin git@bitbucket.org:<your-workspace>/bitbucket-chalk-pipe.git
   git push -u origin main
   ```
4. **Add repository variables:**
   - `CHALK_TOKEN`, `DOCKER_HUB_USERNAME`, `DOCKER_HUB_PASSWORD`
5. **Build and push the image manually:**
   ```bash
   cd bitbucket-chalk-pipe
   docker build -t crashappsec/bitbucket-chalk-pipe:1.0.0 .
   docker push crashappsec/bitbucket-chalk-pipe:1.0.0
   docker tag crashappsec/bitbucket-chalk-pipe:1.0.0 crashappsec/bitbucket-chalk-pipe:latest
   docker push crashappsec/bitbucket-chalk-pipe:latest
   ```

> **Production:** Publish `crashappsec/bitbucket-chalk-pipe` to Docker Hub and update
> `consumer-pipe.yml` to reference it as `pipe: docker://crashappsec/bitbucket-chalk-pipe:1.0.0`.

---

## 7. TeamCity Meta-Runner

**Source:** `chalk-teamcity/` on the `nettrino/expandbuildpipes` branch

TeamCity meta-runners are uploaded as XML files — no separate repo needed.

1. **Start local TeamCity:**
   ```bash
   git clone --branch nettrino/expandbuildpipes \
     https://github.com/crashappsec/setup-chalk-action.git
   cd setup-chalk-action/chalk-teamcity
   docker-compose up -d
   ```
2. **Open** http://localhost:8111 and complete setup wizard
3. **Authorize the build agent:** Agents → Unauthorized → Authorize
4. **Upload the Meta-Runner:**
   - Administration → Meta-Runners → Upload Meta-Runner
   - Upload `.teamcity/chalk-meta-runner.xml`
5. **Create a build configuration** with "Setup Chalk" as step 1
6. **Add password parameter** `env.CHALK_TOKEN`

> **Production:** No dedicated repo required. Upload the meta-runner XML to your
> TeamCity instance directly.

---

## Common Notes

### Chalk Token
All platforms require a `CHALK_TOKEN` or CrashOverride OIDC connection. Obtain your
token from the [CrashOverride dashboard](https://app.crashoverride.run).

### setup.sh
All integrations use `setup.sh` from the `main` branch of this repo:
```
https://raw.githubusercontent.com/crashappsec/setup-chalk-action/main/setup.sh
```

### Moving to dedicated repos
When an integration graduates from PoC, push its subdirectory to a new repo and
update the one reference that changes per platform:

| Platform | What to update |
|----------|---------------|
| GitLab | `project:` in `.gitlab/security-policies/policy.yml` |
| Jenkins | Library SCM URL and default version in Jenkins config |
| Buildkite | Plugin reference in pipelines (`crashappsec/chalk#v1.0.0`) |
| CircleCI | Source repo for CI-triggered publishing |
| Azure DevOps | `resources.repositories` block (switch `type: github` → `type: git`) |
| Bitbucket | Docker image tag in `consumer-pipe.yml` |
| TeamCity | No change needed (XML uploaded directly) |
