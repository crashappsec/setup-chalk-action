# Chalk CI/CD Integrations — Setup Guide

This guide covers the manual steps required to deploy Chalk integrations across all supported CI/CD platforms. The code for each integration lives in its respective subdirectory.

## Overview

| Platform | Directory | Integration Type | Priority |
|----------|-----------|-----------------|----------|
| GitLab CI/CD | `chalk-gitlab-component/` | Pipeline Execution Policy (Ultimate) / inline (Free) | High |
| Jenkins | `chalk-jenkins-library/` | Shared Library | High |
| Buildkite | `chalk-buildkite-plugin/` | Plugin | High |
| CircleCI | `chalk-circleci-orb/` | Orb | Medium |
| Azure DevOps | `chalk-azure-pipeline-template/` | YAML Pipeline Template | Medium |
| Bitbucket | `bitbucket-chalk-pipe/` | Pipe (Docker image) | Medium |
| TeamCity | `chalk-teamcity/` | Meta-Runner + Kotlin DSL | Low |

Jenkins, Buildkite, CircleCI, Azure DevOps, Bitbucket, and TeamCity integrations use
`setup.sh` from this repo at runtime:
```
curl -fsSL https://raw.githubusercontent.com/crashappsec/setup-chalk-action/main/setup.sh
```
The GitLab integration uses direct binary download + explicit c4m config (see below).

---

## 1. GitLab CI/CD

**Directory:** `chalk-gitlab-component/`
**Target repo:** `gitlab.com/your-group/chalk-policy` (the policy project)

Two tiers:
- **Ultimate**: Pipeline Execution Policy — configure once, applies automatically to all group pipelines
- **Free / Premium**: Add the chalk setup directly to each repo's `.gitlab-ci.yml`

### Ultimate: Pipeline Execution Policy

1. **Create GitLab account** at gitlab.com (if not already done)
2. **Create a policy project** in your group, e.g. `your-group/chalk-policy` (can be private)
3. **Push code:**
   ```bash
   cd chalk-gitlab-component
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

Every pipeline in the group now gets chalk automatically. No changes needed to any project's `.gitlab-ci.yml`.

### Free / Premium: Per-Repository

Copy `examples/per-repo.yml` into your repository's `.gitlab-ci.yml` (or merge the
`before_script`/`after_script` blocks into your existing build job), then set
`CHALK_POST_URL` as a project-level CI/CD variable.

---

## 2. Jenkins Shared Library

**Directory:** `chalk-jenkins-library/`
**Target repo:** `github.com/crashappsec/chalk-jenkins-library`

### Steps

1. **Create GitHub repository** `chalk-jenkins-library` (public)
2. **Push code:**
   ```bash
   cd chalk-jenkins-library
   git init && git add . && git commit -m "initial"
   git remote add origin git@github.com:crashappsec/chalk-jenkins-library.git
   git push -u origin main
   ```
3. **Run Jenkins locally** (for PoC):
   ```bash
   docker run -p 8080:8080 -p 50000:50000 \
     -v jenkins_home:/var/jenkins_home \
     -v /var/run/docker.sock:/var/run/docker.sock \
     jenkins/jenkins:lts-jdk17
   ```
4. **Complete setup wizard** at http://localhost:8080
5. **Register the shared library:**
   - Manage Jenkins → Configure System → Global Pipeline Libraries
   - Name: `chalk-jenkins-library`
   - Default version: `main`
   - SCM: Git, URL: `https://github.com/crashappsec/chalk-jenkins-library`
6. **Add credential:**
   - Manage Jenkins → Manage Credentials → System → Global
   - Kind: Secret text, ID: `chalk-api-token`, Secret: your Chalk token
7. **Create Pipeline job** using the example `Jenkinsfile` from `examples/`

---

## 3. Buildkite Plugin

**Directory:** `chalk-buildkite-plugin/`
**Target repo:** `github.com/crashappsec/chalk-buildkite-plugin` (must be public)

### Steps

1. **Create Buildkite account** at buildkite.com
2. **Create GitHub repository** `chalk-buildkite-plugin` (public)
3. **Push code:**
   ```bash
   cd chalk-buildkite-plugin
   git init && git add . && git commit -m "initial"
   git remote add origin git@github.com:crashappsec/chalk-buildkite-plugin.git
   git push -u origin main
   ```
4. **Install Buildkite agent:**
   ```bash
   # macOS
   brew install buildkite/buildkite/buildkite-agent
   # Ubuntu
   curl -fsSL https://keys.openpgp.org/vks/v1/by-fingerprint/32A37959C2FA5C3C99EFBC32A79206696452D198 | gpg --dearmor -o /usr/share/keyrings/buildkite-agent-archive-keyring.gpg
   echo "deb [signed-by=/usr/share/keyrings/buildkite-agent-archive-keyring.gpg] https://apt.buildkite.com/buildkite-agent stable main" | tee /etc/apt/sources.list.d/buildkite-agent.list
   apt-get install buildkite-agent
   ```
5. **Configure agent** with your Buildkite token, start it
6. **Create Buildkite pipeline** pointing to your repo
7. **Add `CHALK_TOKEN`** to pipeline environment variables
8. **Tag a release:** `git tag v1.0.0 && git push origin v1.0.0`

### Testing Locally

```bash
# Install bats-core
brew install bats-core   # macOS
apt-get install bats     # Ubuntu

cd chalk-buildkite-plugin
bats tests/
```

---

## 4. CircleCI Orb

**Directory:** `chalk-circleci-orb/`
**Published as:** `crashappsec/chalk` on CircleCI Orb Registry

### Steps

1. **Create CircleCI account** at circleci.com (connect your GitHub)
2. **Install CircleCI CLI:**
   ```bash
   # macOS
   brew install circleci
   # Linux
   curl -fLSs https://raw.githubusercontent.com/CircleCI-Public/circleci-cli/master/install.sh | sudo bash
   ```
3. **Authenticate:**
   ```bash
   circleci setup
   # Enter your CircleCI API token
   ```
4. **Create namespace** (one-time, requires GitHub org ownership):
   ```bash
   circleci namespace create crashappsec github crashappsec
   ```
5. **Create the orb:**
   ```bash
   circleci orb create crashappsec/chalk
   ```
6. **Create GitHub repository** `chalk-circleci-orb` and push code:
   ```bash
   cd chalk-circleci-orb
   git init && git add . && git commit -m "initial"
   git remote add origin git@github.com:crashappsec/chalk-circleci-orb.git
   git push -u origin main
   ```
7. **Publish dev version:**
   ```bash
   circleci orb pack src/ > /tmp/chalk-orb.yml
   circleci orb validate /tmp/chalk-orb.yml
   circleci orb publish /tmp/chalk-orb.yml crashappsec/chalk@dev:first
   ```
8. **Test integration** using the `.circleci/config.yml`
9. **Promote to production:**
   ```bash
   circleci orb publish promote crashappsec/chalk@dev:first patch
   # Creates version 1.0.0
   ```
10. **Add `CHALK_TOKEN`** to CircleCI project environment variables

---

## 5. Azure DevOps Pipeline Template

**Directory:** `chalk-azure-pipeline-template/`
**Target:** Azure Repos project `chalk-pipeline-templates`

### Steps

1. **Create Azure DevOps account** at dev.azure.com
2. **Create organization** (e.g., `crashappsec`)
3. **Create two projects:**
   - `chalk-pipeline-templates` (hosts the templates)
   - `chalk-azure-test` (tests consuming the templates)
4. **Push code to the templates project:**
   ```bash
   cd chalk-azure-pipeline-template
   git remote add origin https://crashappsec@dev.azure.com/crashappsec/chalk-pipeline-templates/_git/chalk-pipeline-templates
   git push -u origin main
   ```
5. **Tag a release:**
   ```bash
   git tag v1.0.0 && git push origin v1.0.0
   ```
6. **Create Variable Group `chalk-secrets`:**
   - In `chalk-azure-test` project: Pipelines → Library → Variable groups
   - Add variable `CHALK_TOKEN` (mark as secret)
7. **Authorize cross-project access:**
   - In `chalk-pipeline-templates` project: Project Settings → Repositories
   - Add `chalk-azure-test` project as reader
8. **Create pipeline** in `chalk-azure-test` using the example `azure-pipelines.yml`

---

## 6. Bitbucket Pipe

**Directory:** `bitbucket-chalk-pipe/`
**Docker image:** `crashappsec/bitbucket-chalk-pipe` on Docker Hub

### Steps

1. **Create accounts:**
   - Bitbucket.org account
   - Docker Hub account (hub.docker.com)
2. **Create Bitbucket repository** `bitbucket-chalk-pipe` (public)
3. **Push code:**
   ```bash
   cd bitbucket-chalk-pipe
   git init && git add . && git commit -m "initial"
   git remote add origin git@bitbucket.org:<your-workspace>/bitbucket-chalk-pipe.git
   git push -u origin main
   ```
4. **Enable Pipelines** in the repository settings
5. **Add repository variables:**
   - `CHALK_TOKEN` — your CrashOverride API token
   - `DOCKER_HUB_USERNAME` — Docker Hub username
   - `DOCKER_HUB_PASSWORD` — Docker Hub password (mark as secret)
6. **Build and push Docker image manually** (first time):
   ```bash
   cd bitbucket-chalk-pipe
   docker build -t crashappsec/bitbucket-chalk-pipe:1.0.0 .
   docker push crashappsec/bitbucket-chalk-pipe:1.0.0
   docker tag crashappsec/bitbucket-chalk-pipe:1.0.0 crashappsec/bitbucket-chalk-pipe:latest
   docker push crashappsec/bitbucket-chalk-pipe:latest
   ```
7. **Test** by creating a consuming repo with example `consumer-pipe.yml` or `consumer-script.yml`

---

## 7. TeamCity Meta-Runner

**Directory:** `chalk-teamcity/`

### Steps

1. **Start local TeamCity** (for PoC):
   ```bash
   cd chalk-teamcity
   docker-compose up -d
   ```
2. **Open** http://localhost:8111 and complete setup wizard:
   - Choose "Internal (HSQLDB)" database
   - Accept license agreement
   - Create admin account
3. **Authorize the build agent:**
   - Agents → Unauthorized → Authorize
4. **Create a project** via Administration → Projects → Create Project
5. **Upload the Meta-Runner:**
   - Administration → Meta-Runners → Upload Meta-Runner
   - Upload `.teamcity/chalk-meta-runner.xml`
6. **Create a build configuration** with these steps:
   - Step 1: "Setup Chalk" (uses the meta-runner)
   - Step 2: Your build script
7. **Add Chalk token:**
   - In build config: Parameters → Add new parameter
   - Name: `env.CHALK_TOKEN`, Type: Password
   - Enter your Chalk token value
8. **Optional Kotlin DSL:** If using versioned settings (Kotlin DSL):
   - Enable: Project Settings → Versioned Settings → Synchronization enabled
   - Copy `.teamcity/settings.kts` to your project's `.teamcity/` directory
   - Update credential reference `credentialsJSON:chalk-token-id`

---

## Common Notes

### Chalk Token
All platforms require a `CHALK_TOKEN` environment variable or secret. Obtain your token from the [CrashOverride dashboard](https://app.crashoverride.run).

### setup.sh Reference
All integrations download `setup.sh` from:
```
https://raw.githubusercontent.com/crashappsec/setup-chalk-action/main/setup.sh
```
This script handles OS/arch detection, binary download, checksum verification, and optional command wrapping.

### Supported Platforms
- Linux x86_64 and aarch64
- macOS x86_64 (Intel) and arm64 (Apple Silicon)
