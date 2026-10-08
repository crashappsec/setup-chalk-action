// Post step: runs once at the end of the job, after every chalk docker
// build/push, including when an enforced policy failed the build.
// It never fails the job: chalk already exited 1 for blocked builds.

"use strict";

const fs = require("fs");
const lib = require("./lib");

function input(name, fallback = "") {
  const value = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`];
  return value === undefined || value === "" ? fallback : value.trim();
}

function headSha() {
  try {
    const event = JSON.parse(
      fs.readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"),
    );
    // GITHUB_SHA is the merge commit for pull_request events, which the PR
    // page does not show checks for
    if (
      event.pull_request &&
      event.pull_request.head &&
      event.pull_request.head.sha
    ) {
      return event.pull_request.head.sha;
    }
  } catch {
    // no event payload, e.g. a local test
  }
  return process.env.GITHUB_SHA || "";
}

function runUrl() {
  const { GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID } = process.env;
  if (!GITHUB_SERVER_URL || !GITHUB_REPOSITORY || !GITHUB_RUN_ID) {
    return undefined;
  }
  return `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}`;
}

async function postCheckRun(builds, outcome, summary, sha) {
  const token = input("github_token");
  const repository = process.env.GITHUB_REPOSITORY;
  const api = process.env.GITHUB_API_URL || "https://api.github.com";
  if (!token || !repository || !sha) {
    console.log(
      "::warning::Chalk build policy check skipped: missing token, repository or commit",
    );
    return;
  }
  const annotations = lib.checkAnnotations(builds);
  const body = {
    name: input("check_name", "Chalk build policy"),
    head_sha: sha,
    status: "completed",
    conclusion: outcome.conclusion,
    details_url: runUrl(),
    output: {
      title: outcome.title.slice(0, 255),
      summary: summary.slice(0, 65535),
      // the API accepts at most 50 annotations per request
      annotations: annotations.slice(0, 50),
    },
  };
  const response = await fetch(`${api}/repos/${repository}/check-runs`, {
    method: "POST",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const text = await response.text();
    const hint =
      response.status === 403
        ? " Grant the job `checks: write` (pull requests from forks only get a read-only token)."
        : "";
    console.log(
      `::warning::Could not create the Chalk build policy check (HTTP ${response.status}).${hint} ${lib.escapeData(text.slice(0, 300))}`,
    );
    return;
  }
  const created = await response.json();
  console.log(`Created check run ${created.html_url || created.id}`);
}

async function main() {
  const file = input("report_file", process.env.CHALK_POLICY_REPORT_FILE || "");
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const wantCheck = input("check", "false") === "true";

  const builds = lib.toBuilds(lib.readReports(file));
  if (builds.length === 0) {
    console.log(
      "No chalk docker build or push ran in this job; nothing to report.",
    );
    return;
  }
  lib.locateFindings(builds, workspace);
  const outcome = lib.summarize(builds);
  const sha = headSha();
  const { GITHUB_SERVER_URL, GITHUB_REPOSITORY } = process.env;
  const links =
    GITHUB_SERVER_URL && GITHUB_REPOSITORY && sha
      ? { blobUrl: `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/blob/${sha}` }
      : null;
  const summary = lib.renderSummary(builds, outcome, links);

  console.log(`Chalk build policy: ${outcome.title}`);
  // stay quiet for jobs where policies are off or nothing was found, unless
  // a check run was asked for
  if (outcome.hasFindings || wantCheck) {
    if (process.env.GITHUB_STEP_SUMMARY) {
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + "\n");
    }
    for (const command of lib.annotationCommands(builds)) {
      console.log(command);
    }
  }
  if (wantCheck) {
    await postCheckRun(builds, outcome, summary, sha);
  }
}

main().catch((err) => {
  console.log(
    `::warning::Chalk build policy report failed: ${lib.escapeData(err && err.stack ? err.stack : err)}`,
  );
});
