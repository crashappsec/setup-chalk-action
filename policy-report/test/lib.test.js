"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const lib = require("../lib");

const DOCKERFILE = `# syntax=docker/dockerfile:1
ARG PY_VERSION=3.12
FROM cgr.dev/chainguard/python:latest-dev AS deps
RUN pip install --prefix=/deps -r requirements.txt

FROM --platform=$BUILDPLATFORM busybox AS worker
COPY --from=deps /deps /usr/local
COPY --from=ghcr.io/acme/tools:1.2 \\
     /bin/tool /bin/tool
RUN --mount=type=bind,from=docker.io/library/node:22,target=/n ls /n
`;

// shaped like chalk's policy_report for the two policies of
// tests/unit/fixtures/policy_config_multi.json in chalk
function blockedReport(extra = {}) {
  return {
    _OPERATION: "build",
    _ACTION_ID: "a1",
    _OP_EXIT_CODE: 1,
    _POLICY_MODE: "enforce",
    _POLICY_RESULT: "blocked",
    _POLICY_RESULTS: [
      {
        id: "golden-images@3",
        mode: "enforce",
        on_error: "allow",
        result: "blocked",
      },
      {
        id: "chainguard-only@1",
        mode: "audit",
        on_error: "block",
        result: "violation",
      },
    ],
    _POLICY_FINDINGS: [
      {
        policy_id: "golden-images@3",
        rule: "golden_images",
        kind: "violation",
        image: "busybox",
        digest: "sha256:abc",
        stage: "worker",
        source: "from",
        reason:
          "image is not in the list of allowed golden images. Use an approved golden image",
      },
      {
        policy_id: "chainguard-only@1",
        rule: "golden_images",
        kind: "violation",
        image: "busybox",
        digest: "sha256:abc",
        stage: "worker",
        source: "from",
        reason:
          "image is not in the list of allowed golden images. Prefer Chainguard images",
      },
    ],
    _POLICY_BUILD: {
      command: "build",
      dockerfile_path: "services/worker/Dockerfile",
      context: ".",
      tags: ["ghcr.io/acme/worker:pr-142"],
      platforms: ["linux/amd64"],
    },
    ...extra,
  };
}

function workspaceWithDockerfile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "chalk-policy-"));
  fs.mkdirSync(path.join(dir, "services", "worker"), { recursive: true });
  fs.writeFileSync(
    path.join(dir, "services", "worker", "Dockerfile"),
    DOCKERFILE,
  );
  return dir;
}

test("parses pretty-printed and single-line reports appended to one file", () => {
  const pretty = JSON.stringify([blockedReport()], null, 2);
  const line = JSON.stringify([
    { _OPERATION: "push", _ACTION_ID: "a2", note: "brace } in [string]" },
  ]);
  const reports = lib.parseReports(
    `${pretty}\n${line}\n[{"_OPERATION": "trunc`,
  );
  assert.equal(reports.length, 2);
  assert.equal(reports[0]._POLICY_RESULT, "blocked");
  assert.equal(reports[1].note, "brace } in [string]");
});

test("deduplicates identical reports", () => {
  const builds = lib.toBuilds([blockedReport(), blockedReport()]);
  assert.equal(builds.length, 1);
});

test("blocked build fails the check and names the blocking policy", () => {
  const outcome = lib.summarize(lib.toBuilds([blockedReport()]));
  assert.equal(outcome.conclusion, "failure");
  assert.equal(
    outcome.title,
    "Blocked by golden-images@3: busybox is not allowed +1 non-blocking finding",
  );
  assert.equal(outcome.blocking.length, 1);
});

test("audit-only findings are neutral", () => {
  const report = blockedReport({
    _POLICY_RESULT: "violation",
    _POLICY_RESULTS: [
      {
        id: "chainguard-only@1",
        mode: "audit",
        on_error: "block",
        result: "violation",
      },
    ],
  });
  report._POLICY_FINDINGS = report._POLICY_FINDINGS.slice(1);
  const outcome = lib.summarize(lib.toBuilds([report]));
  assert.equal(outcome.conclusion, "neutral");
  assert.equal(outcome.title, "1 finding, not enforced");
});

test("passing evaluation succeeds and lists the policies", () => {
  const outcome = lib.summarize(
    lib.toBuilds([
      {
        _OPERATION: "build",
        _POLICY_RESULT: "pass",
        _POLICY_RESULTS: [
          {
            id: "golden-images@3",
            mode: "enforce",
            on_error: "allow",
            result: "pass",
          },
          {
            id: "chainguard-only@1",
            mode: "audit",
            on_error: "block",
            result: "pass",
          },
        ],
        _POLICY_FINDINGS: [],
      },
    ]),
  );
  assert.equal(outcome.conclusion, "success");
  assert.equal(
    outcome.title,
    "2 policies passed: golden-images@3, chainguard-only@1",
  );
  assert.equal(outcome.hasFindings, false);
});

test("builds without policy keys are not findings", () => {
  const outcome = lib.summarize(
    lib.toBuilds([{ _OPERATION: "build", _ACTION_ID: "x" }]),
  );
  assert.equal(outcome.conclusion, "success");
  assert.equal(outcome.title, "No build policy findings");
  assert.equal(outcome.hasFindings, false);
});

test("locates FROM, COPY --from and RUN --mount lines", () => {
  const instructions = lib.dockerfileInstructions(DOCKERFILE);
  assert.equal(
    lib.locateFinding(instructions, {
      image: "busybox",
      stage: "worker",
      source: "from",
    }),
    6,
  );
  assert.equal(
    lib.locateFinding(instructions, {
      image: "cgr.dev/chainguard/python:latest-dev",
      stage: "deps",
      source: "from",
    }),
    3,
  );
  assert.equal(
    lib.locateFinding(instructions, {
      image: "ghcr.io/acme/tools:1.2",
      stage: "worker",
      source: "copy_from",
    }),
    8,
  );
  assert.equal(
    lib.locateFinding(instructions, {
      image: "node:22",
      stage: "worker",
      source: "mount_from",
    }),
    10,
  );
  assert.equal(
    lib.locateFinding(instructions, {
      image: "alpine",
      stage: "worker",
      source: "from",
    }),
    null,
  );
});

test("falls back to the stage when FROM uses an ARG", () => {
  const instructions = lib.dockerfileInstructions(
    "ARG BASE=busybox\nFROM ${BASE} AS worker\n",
  );
  assert.equal(
    lib.locateFinding(instructions, {
      image: "busybox",
      stage: "worker",
      source: "from",
    }),
    2,
  );
});

test("prefers the line chalk reports", () => {
  const workspace = workspaceWithDockerfile();
  const report = blockedReport();
  report._POLICY_FINDINGS[0].line = "42";
  const builds = lib.toBuilds([report]);
  lib.locateFindings(builds, workspace);
  assert.equal(builds[0].findings[0].lineNumber, 42);
  assert.equal(builds[0].findings[1].lineNumber, 6);
  assert.equal(builds[0].findings[1].file, "services/worker/Dockerfile");
});

test("resolves absolute Dockerfile paths inside the workspace only", () => {
  const workspace = workspaceWithDockerfile();
  const inside = blockedReport();
  inside._POLICY_BUILD.dockerfile_path = path.join(
    workspace,
    "services",
    "worker",
    "Dockerfile",
  );
  const outside = blockedReport({ _ACTION_ID: "a2" });
  outside._POLICY_BUILD.dockerfile_path = path.join(
    workspace,
    "services",
    "worker",
    "Dockerfile",
  );
  const builds = lib.toBuilds([inside, outside]);
  lib.locateFindings(builds, workspace);
  assert.equal(builds[0].findings[0].file, "services/worker/Dockerfile");
  lib.locateFindings(builds, path.join(workspace, "services"));
  assert.equal(builds[1].findings[0].file, "worker/Dockerfile");
  lib.locateFindings(builds, path.join(workspace, "elsewhere"));
  assert.equal(builds[1].findings[0].file, null);
});

test("annotations are errors for blocking findings and warnings otherwise", () => {
  const workspace = workspaceWithDockerfile();
  const builds = lib.toBuilds([blockedReport()]);
  lib.locateFindings(builds, workspace);
  const commands = lib.annotationCommands(builds);
  assert.deepEqual(commands, [
    "::error file=services/worker/Dockerfile,line=6,title=Chalk build policy%3A golden-images@3 (enforce)::" +
      "busybox: image is not in the list of allowed golden images. Use an approved golden image",
    "::warning file=services/worker/Dockerfile,line=6,title=Chalk build policy%3A chainguard-only@1 (audit%2C not enforced)::" +
      "busybox: image is not in the list of allowed golden images. Prefer Chainguard images",
  ]);
  const annotations = lib.checkAnnotations(builds);
  assert.equal(annotations[0].annotation_level, "failure");
  assert.equal(annotations[1].annotation_level, "warning");
  assert.equal(annotations[0].start_line, 6);
});

test("escapes workflow command data", () => {
  assert.equal(lib.escapeData("a%b\nc\rd"), "a%25b%0Ac%0Dd");
  assert.equal(lib.escapeProperty("a:b,c"), "a%3Ab%2Cc");
});

test("summary has policy and finding tables with links", () => {
  const workspace = workspaceWithDockerfile();
  const builds = lib.toBuilds([blockedReport()]);
  lib.locateFindings(builds, workspace);
  const summary = lib.renderSummary(builds, lib.summarize(builds), {
    blobUrl: "https://github.com/acme/app/blob/abc123",
  });
  assert.match(summary, /^## ❌ Chalk build policy: blocked/);
  assert.match(
    summary,
    /\| `golden-images@3` \| enforce \| allow \| ❌ Blocked \|/,
  );
  assert.match(
    summary,
    /\| `chainguard-only@1` \| audit \| block \| ⚠️ Violation \(not enforced\) \|/,
  );
  assert.match(
    summary,
    /\[services\/worker\/Dockerfile:6\]\(https:\/\/github\.com\/acme\/app\/blob\/abc123\/services\/worker\/Dockerfile#L6\)/,
  );
  assert.match(summary, /nothing was built or pushed/);
});

test("summary cells cannot break the table", () => {
  const report = blockedReport();
  report._POLICY_FINDINGS[0].reason = "a | b\n<script>";
  const builds = lib.toBuilds([report]);
  const summary = lib.renderSummary(builds, lib.summarize(builds), null);
  assert.match(summary, /a \\\| b &lt;script&gt;/);
});
