# chalk-gitlab-component

GitLab CI/CD integration for [Chalk](https://crashoverride.run). Instruments Docker
builds to produce 3 JSON reports — **build**, **push**, and **env** — with the same
fields as the GitHub Action integration.

Two deployment options:

| Tier | Mechanism | Effort |
|------|-----------|--------|
| **GitLab Ultimate** | [Pipeline Execution Policy](https://docs.gitlab.com/ee/user/application_security/policies/pipeline_execution_policies.html) — configure once, applies to every pipeline in the group automatically | One-time group setup |
| **GitLab Free / Premium** | Add chalk setup directly to each repo's `.gitlab-ci.yml` | Per-repository |

## How it works

Both approaches use the same pattern:

1. **Install** the Chalk binary directly from `dl.crashoverride.run`
2. **Configure** Chalk with an explicit c4m config (file sink + report template defining exact output fields)
3. **Wrap** Docker selectively: `docker build` and `docker push` route through chalk; all other `docker` commands (e.g. `docker login`) pass through to real Docker unchanged
4. **Emit** a completion signal via `chalk env` in `after_script`
5. **POST** all accumulated reports (build + push + env) to your `CHALK_POST_URL` endpoint

> The selective wrapper is required because directly replacing the Docker binary breaks GitLab runner internals (the runner calls `docker sh` to set up `after_script`).

## Option 1 — Group-Level Setup (GitLab Ultimate)

### Step 1: Create the policy project

Create a project in your group to hold the Chalk CI configuration, e.g. `your-group/chalk-policy`. Push this directory's contents to it:

```bash
git init && git add . && git commit -m "initial"
git remote add origin git@gitlab.com:your-group/chalk-policy.git
git push -u origin main
```

### Step 2: Set the `CHALK_POST_URL` group variable

In your GitLab group: **Settings → CI/CD → Variables → Add variable**

- Key: `CHALK_POST_URL`
- Value: your report collection endpoint (e.g. a webhook.site URL for testing, or your CrashOverride platform sink)
- Scope: All environments

### Step 3: Edit the policy file

Update `.gitlab/security-policies/policy.yml` with your actual values:

```yaml
pipeline_execution_policy:
  - name: Chalk Build Instrumentation
    enabled: true
    pipeline_config_strategy: override_project_ci
    content:
      include:
        - project: your-group/chalk-policy   # ← your policy project path
          file: /chalk-setup.yml
          ref: main
    policy_scope:
      groups:
        including:
          - id: 12345678                      # ← your GitLab group ID
```

Find your group ID at **Group → Settings → General** (shown at top of page).

### Step 4: Link the policy project to your group

In your GitLab group: **Security → Policies → Edit policy project** → select `your-group/chalk-policy`.

That's it. Every pipeline in the group now gets chalk automatically — no changes needed to any project's `.gitlab-ci.yml`.

> **Note:** `default: before_script` applies to jobs that don't define their own `before_script`. If a job overrides `before_script`, use [`!reference` tags](https://docs.gitlab.com/ee/ci/yaml/yaml_optimization.html#reference-tags) or merge the chalk setup into that job's `before_script`.

## Option 2 — Per-Repository Setup (GitLab Free / Premium)

Copy `examples/per-repo.yml` into your repository's `.gitlab-ci.yml` (or merge the `before_script` / `after_script` blocks into your existing build job).

Set `CHALK_POST_URL` as a project-level CI/CD variable.

## Report Output

Each instrumented pipeline produces 3 JSON reports:

### Report 1 — BUILD
Produced when `docker build` runs. Contains Dockerfile pinning (base images rewritten with digest), OCI labels, build metadata, and a unique `CHALK_ID`.

```json
{
  "_OPERATION": "build",
  "_DATETIME": "2026-02-26T22:06:41.277+00:00",
  "_OP_CHALK_COUNT": 1,
  "_CHALKS": [{
    "CHALK_ID": "17ASVB-FQPA-7TZJ-VE1PZA",
    "COMMIT_ID": "99f82adad3c9bf4673e9e2de26e1cf823e824594",
    "DOCKER_BASE_IMAGES": {
      "builder": { "repo": "golang", "tag": "1.22-alpine", "digest": "1699c100..." },
      "": { "repo": "alpine", "tag": "3.19", "digest": "6baf4358..." }
    },
    "_IMAGE_LABELS": {
      "run.crashoverride.commit-id": "99f82ada...",
      "run.crashoverride.origin-uri": "https://gitlab.com/your-group/your-repo.git"
    }
  }]
}
```

Key fields:
- `CHALK_ID` — unique artifact identifier, consistent across build and push reports
- `DOCKER_BASE_IMAGES` — base images with pinned digests (supply chain provenance)
- `DOCKER_FILE_CHALKED` — Dockerfile rewritten by chalk: `FROM` tags pinned to `@sha256:...` digests, OCI labels injected, `chalk.json` embedded in image

### Report 2 — PUSH
Produced when `docker push` runs. Carries the same `CHALK_ID` linking it to the build report.

```json
{
  "_OPERATION": "push",
  "_DATETIME": "2026-02-26T22:07:22.080+00:00",
  "_CHALKS": [{
    "CHALK_ID": "17ASVB-FQPA-7TZJ-VE1PZA",
    "DOCKER_TAGS": ["registry.gitlab.com/your-group/your-repo:99f82ada"],
    "_IMAGE_ID": "e00b882441a3..."
  }]
}
```

### Report 3 — ENV
Produced by `chalk env` in `after_script`. Completion signal confirming chalk ran and the pipeline finished.

```json
{
  "_OPERATION": "env",
  "_DATETIME": "2026-02-26T22:07:30.193+00:00",
  "_OP_CHALKER_VERSION": "0.6.6",
  "_OP_CHALK_COUNT": 0
}
```

## Repository Structure

```
chalk-gitlab-component/
├── chalk-setup.yml                       # Injected CI config (Ultimate: via policy)
├── .gitlab/
│   └── security-policies/
│       └── policy.yml                    # Pipeline Execution Policy definition
├── examples/
│   └── per-repo.yml                      # Free/Premium: add directly to .gitlab-ci.yml
├── .gitlab-ci.yml                        # Self-test CI for this policy project
└── README.md
```
