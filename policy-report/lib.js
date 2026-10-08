// Renders chalk build policy reports for GitHub: job summary, workflow
// command annotations and an optional check run.
//
// Chalk writes one report per `chalk docker build|push` to the file named by
// CHALK_POLICY_REPORT_FILE (see setup.sh). Each report uses chalk's
// `policy_report` template, see docs/design-build-policy.md in chalk.

"use strict";

const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------- parsing

// The file sink appends whole reports, which may be pretty-printed over
// several lines, so split the stream into top-level JSON values instead of
// relying on one report per line.
function splitJsonValues(text) {
  const values = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (c === "\\") {
        escaped = true;
      } else if (c === '"') {
        inString = false;
      }
      continue;
    }
    if (c === '"') {
      inString = true;
    } else if (c === "{" || c === "[") {
      if (depth === 0) {
        start = i;
      }
      depth++;
    } else if (c === "}" || c === "]") {
      depth--;
      if (depth === 0 && start >= 0) {
        values.push(text.slice(start, i + 1));
        start = -1;
      }
    }
  }
  return values;
}

function parseReports(text) {
  const reports = [];
  for (const raw of splitJsonValues(text)) {
    let value;
    try {
      value = JSON.parse(raw);
    } catch {
      continue; // a partially written report, e.g. chalk was killed
    }
    for (const report of Array.isArray(value) ? value : [value]) {
      if (report && typeof report === "object") {
        reports.push(report);
      }
    }
  }
  return reports;
}

function readReports(file) {
  if (!file || !fs.existsSync(file)) {
    return [];
  }
  return parseReports(fs.readFileSync(file, "utf8"));
}

// ---------------------------------------------------------------- model

function asList(value) {
  return Array.isArray(value) ? value : [];
}

// One entry per chalk docker command. Commands without `_POLICY_RESULTS` ran
// no policy, or (chalk < 1.3 semantics) every policy passed.
function toBuilds(reports) {
  const seen = new Set();
  const builds = [];
  for (const report of reports) {
    const key = JSON.stringify([
      report._ACTION_ID,
      report._POLICY_BUILD,
      report._POLICY_RESULTS,
      report._POLICY_FINDINGS,
    ]);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    const results = asList(report._POLICY_RESULTS);
    builds.push({
      build: report._POLICY_BUILD || {},
      operation: report._OPERATION || "",
      exitCode: report._OP_EXIT_CODE,
      result: report._POLICY_RESULT || (results.length ? "pass" : ""),
      results,
      findings: asList(report._POLICY_FINDINGS),
    });
  }
  return builds;
}

function policyResult(build, policyId) {
  return build.results.find((r) => (r.id || "") === (policyId || ""));
}

function isBlocking(build, finding) {
  const result = policyResult(build, finding.policy_id);
  return result ? result.result === "blocked" : build.result === "blocked";
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

// Overall outcome across every build of the job, mapped to a check run
// conclusion: neutral (audit findings, errors that do not block) still lets
// a required check pass.
function summarize(builds) {
  const evaluated = builds.filter((b) => b.results.length > 0);
  const findings = builds.flatMap((b) =>
    b.findings.map((f) => ({ build: b, finding: f })),
  );
  const blocking = findings.filter((x) => isBlocking(x.build, x.finding));
  const blockedIds = [
    ...new Set(
      builds.flatMap((b) =>
        b.results
          .filter((r) => r.result === "blocked")
          .map((r) => r.id || "policy"),
      ),
    ),
  ];
  const policyIds = [
    ...new Set(
      evaluated.flatMap((b) => b.results.map((r) => r.id || "policy")),
    ),
  ];

  let conclusion;
  let title;
  if (blockedIds.length > 0) {
    conclusion = "failure";
    const first = blocking[0] && blocking[0].finding;
    title = `Blocked by ${blockedIds.join(", ")}`;
    if (blocking.length === 1 && first && first.image) {
      title += `: ${first.image} is not allowed`;
    } else {
      title += ` (${plural(blocking.length, "blocking finding", "blocking findings")})`;
    }
    const other = findings.length - blocking.length;
    if (other > 0) {
      title += ` +${plural(other, "non-blocking finding", "non-blocking findings")}`;
    }
  } else if (findings.length > 0) {
    conclusion = "neutral";
    title = `${plural(findings.length, "finding", "findings")}, not enforced`;
  } else if (evaluated.length > 0) {
    conclusion = "success";
    title = `${plural(policyIds.length, "policy", "policies")} passed`;
    if (policyIds.length && policyIds.length <= 3) {
      title += `: ${policyIds.join(", ")}`;
    }
  } else {
    conclusion = builds.length > 0 ? "success" : "skipped";
    title =
      builds.length > 0
        ? "No build policy findings"
        : "No docker build or push ran";
  }
  return {
    conclusion,
    title,
    findings,
    blocking,
    hasFindings: findings.length > 0,
  };
}

// ---------------------------------------------------------------- Dockerfile

function resolveDockerfile(build, workspace) {
  const file = build.dockerfile_path || "";
  if (!file || file === "-" || file.includes("://")) {
    return null;
  }
  const candidates = [];
  if (path.isAbsolute(file)) {
    candidates.push(file);
  } else {
    candidates.push(path.resolve(workspace, file));
    const context = build.context || "";
    if (context && !context.includes("://")) {
      candidates.push(path.resolve(workspace, context, file));
    }
  }
  for (const candidate of candidates) {
    try {
      if (fs.statSync(candidate).isFile()) {
        const relative = path.relative(workspace, candidate);
        return {
          absolute: candidate,
          // annotations can only point at files in the repository
          relative:
            relative.startsWith("..") || path.isAbsolute(relative)
              ? null
              : relative.split(path.sep).join("/"),
        };
      }
    } catch {
      // try the next candidate
    }
  }
  return null;
}

// Splits a Dockerfile into instructions with their 1-based start line,
// joining continuation lines.
function dockerfileInstructions(text) {
  const lines = text.split(/\r?\n/);
  let escape = "\\";
  const directive = /^#\s*escape\s*=\s*([\\`])\s*$/i;
  for (const line of lines) {
    const m = directive.exec(line.trim());
    if (m) {
      escape = m[1];
      break;
    }
    if (!line.trim().startsWith("#")) {
      break; // parser directives only appear before any instruction
    }
  }
  const instructions = [];
  let current = null;
  lines.forEach((raw, index) => {
    const line = raw.trim();
    if (current === null) {
      if (line === "" || line.startsWith("#")) {
        return;
      }
      current = { line: index + 1, text: "" };
    } else if (line.startsWith("#")) {
      return; // comments inside continuations are skipped by docker
    }
    if (line.endsWith(escape)) {
      current.text += line.slice(0, -1) + " ";
      return;
    }
    current.text += line;
    const [keyword, ...rest] = current.text.trim().split(/\s+/);
    instructions.push({
      line: current.line,
      keyword: keyword.toUpperCase(),
      args: rest,
    });
    current = null;
  });
  return instructions;
}

function normalizeImage(ref) {
  let image = (ref || "").trim().toLowerCase();
  image = image.split("@")[0];
  image = image.replace(
    /^(docker\.io|index\.docker\.io|registry-1\.docker\.io)\//,
    "",
  );
  image = image.replace(/^library\//, "");
  const lastSlash = image.lastIndexOf("/");
  const colon = image.lastIndexOf(":");
  if (colon <= lastSlash) {
    image += ":latest";
  }
  return image;
}

function sameImage(a, b) {
  return normalizeImage(a) === normalizeImage(b);
}

function flagValue(args, name) {
  for (const arg of args) {
    if (arg.toLowerCase().startsWith(`--${name}=`)) {
      return arg.slice(name.length + 3);
    }
  }
  return null;
}

// Best-effort line of the instruction that referenced the finding's image,
// for chalk versions that do not report `line` themselves.
function locateFinding(instructions, finding) {
  const stage = (finding.stage || "").toLowerCase();
  const source = finding.source || "from";
  let currentStage = "";
  let stageMatch = null;
  for (const ins of instructions) {
    if (ins.keyword === "FROM") {
      const args = ins.args.filter((a) => !a.startsWith("--"));
      const image = args[0] || "";
      const asIndex = args.findIndex((a) => a.toLowerCase() === "as");
      currentStage =
        asIndex >= 0 && args[asIndex + 1]
          ? args[asIndex + 1].toLowerCase()
          : "";
      if (source !== "from") {
        continue;
      }
      const stageOk = !stage || stage === currentStage;
      if (stageOk && sameImage(image, finding.image)) {
        return ins.line;
      }
      // FROM ${BASE} AS worker: match the stage when the image is an ARG
      if (
        stage &&
        stage === currentStage &&
        image.includes("$") &&
        stageMatch === null
      ) {
        stageMatch = ins.line;
      }
      continue;
    }
    if (stage && stage !== currentStage) {
      continue;
    }
    if (
      source === "copy_from" &&
      (ins.keyword === "COPY" || ins.keyword === "ADD")
    ) {
      const from = flagValue(ins.args, "from");
      if (from && sameImage(from, finding.image)) {
        return ins.line;
      }
    }
    if (source === "mount_from" && ins.keyword === "RUN") {
      for (const arg of ins.args) {
        if (!arg.toLowerCase().startsWith("--mount=")) {
          continue;
        }
        const from = arg
          .slice(8)
          .split(",")
          .map((kv) => kv.split("="))
          .find(([k]) => k.toLowerCase() === "from");
        if (from && sameImage(from[1] || "", finding.image)) {
          return ins.line;
        }
      }
    }
  }
  return stageMatch;
}

// Attaches `file` (repository-relative) and `line` to every finding.
function locateFindings(builds, workspace) {
  for (const build of builds) {
    const dockerfile = resolveDockerfile(build.build, workspace);
    let instructions = null;
    if (dockerfile) {
      try {
        instructions = dockerfileInstructions(
          fs.readFileSync(dockerfile.absolute, "utf8"),
        );
      } catch {
        instructions = null;
      }
    }
    for (const finding of build.findings) {
      finding.file = dockerfile ? dockerfile.relative : null;
      const reported = parseInt(finding.line || "", 10);
      if (reported > 0) {
        finding.lineNumber = reported;
      } else if (instructions && finding.image) {
        finding.lineNumber = locateFinding(instructions, finding);
      } else {
        finding.lineNumber = null;
      }
    }
  }
}

// ---------------------------------------------------------------- output

function escapeData(s) {
  return String(s)
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

function escapeProperty(s) {
  return escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

function findingMessage(build, finding) {
  const result = policyResult(build, finding.policy_id);
  const mode = result ? result.mode : "";
  const enforced = isBlocking(build, finding);
  const policy = finding.policy_id || finding.rule || "policy";
  const qualifier = enforced
    ? mode || "enforce"
    : `${mode || "audit"}, not enforced`;
  const subject = finding.image ? `${finding.image}: ` : "";
  return {
    level: enforced ? "error" : "warning",
    title: `Chalk build policy: ${policy} (${qualifier})`,
    message: `${subject}${finding.reason || finding.kind || "policy finding"}`,
  };
}

// `::error file=…,line=…,title=…::message` workflow commands
function annotationCommands(builds) {
  const commands = [];
  for (const build of builds) {
    for (const finding of build.findings) {
      const { level, title, message } = findingMessage(build, finding);
      const props = [];
      if (finding.file) {
        props.push(`file=${escapeProperty(finding.file)}`);
        if (finding.lineNumber) {
          props.push(`line=${finding.lineNumber}`);
        }
      }
      props.push(`title=${escapeProperty(title)}`);
      commands.push(`::${level} ${props.join(",")}::${escapeData(message)}`);
    }
  }
  return commands;
}

function checkAnnotations(builds) {
  const annotations = [];
  for (const build of builds) {
    for (const finding of build.findings) {
      if (!finding.file) {
        continue; // check run annotations require a path; the summary has it
      }
      const { level, title, message } = findingMessage(build, finding);
      const line = finding.lineNumber || 1;
      annotations.push({
        path: finding.file,
        start_line: line,
        end_line: line,
        annotation_level: level === "error" ? "failure" : "warning",
        title,
        message,
      });
    }
  }
  return annotations;
}

function cell(value) {
  return String(
    value === undefined || value === null || value === "" ? "—" : value,
  )
    .replace(/\r?\n/g, " ")
    .replace(/\|/g, "\\|")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function code(value) {
  return value ? `\`${String(value).replace(/`/g, "'")}\`` : "—";
}

const RESULT_LABELS = {
  pass: "✅ Passed",
  blocked: "❌ Blocked",
  violation: "⚠️ Violation (not enforced)",
  error: "⚠️ Evaluation error",
};

const HEADINGS = {
  failure: "❌ Chalk build policy: blocked",
  neutral: "⚠️ Chalk build policy: findings not enforced",
  success: "✅ Chalk build policy: passed",
  skipped: "Chalk build policy",
};

function sourceLabel(source) {
  return (
    { from: "FROM", copy_from: "COPY --from", mount_from: "RUN --mount" }[
      source
    ] || source
  );
}

function locationLink(finding, links) {
  if (!finding.file) {
    return "—";
  }
  const label = `${finding.file}${finding.lineNumber ? `:${finding.lineNumber}` : ""}`;
  if (!links || !links.blobUrl) {
    return cell(label);
  }
  const anchor = finding.lineNumber ? `#L${finding.lineNumber}` : "";
  return `[${cell(label)}](${links.blobUrl}/${finding.file.split("/").map(encodeURIComponent).join("/")}${anchor})`;
}

function buildHeading(build) {
  const b = build.build;
  const parts = [code(`docker ${b.command || build.operation || "build"}`)];
  if (b.dockerfile_path) {
    parts.push(
      code(
        build.findings[0] && build.findings[0].file
          ? build.findings[0].file
          : b.dockerfile_path,
      ),
    );
  }
  const tags = asList(b.tags);
  if (tags.length) {
    parts.push(tags.map(code).join(", "));
  }
  return parts.join(" · ");
}

function renderSummary(builds, outcome, links) {
  const out = [];
  out.push(`## ${HEADINGS[outcome.conclusion]}`, "", cell(outcome.title), "");
  for (const build of builds) {
    if (build.results.length === 0 && build.findings.length === 0) {
      continue;
    }
    out.push(`### ${buildHeading(build)}`, "");
    if (build.results.length) {
      out.push(
        "| Policy | Mode | On error | Result |",
        "| --- | --- | --- | --- |",
      );
      for (const r of build.results) {
        out.push(
          `| ${code(r.id)} | ${cell(r.mode)} | ${cell(r.on_error)} | ${RESULT_LABELS[r.result] || cell(r.result)} |`,
        );
      }
      out.push("");
    }
    if (build.findings.length) {
      out.push(
        "| Policy | Image | Stage | Source | Location | Reason |",
        "| --- | --- | --- | --- | --- | --- |",
      );
      for (const f of build.findings) {
        out.push(
          `| ${code(f.policy_id || f.rule)} | ${code(f.image)} | ${cell(f.stage)} | ` +
            `${cell(sourceLabel(f.source))} | ${locationLink(f, links)} | ${cell(f.reason)} |`,
        );
      }
      out.push("");
    }
    const platforms = asList(build.build.platforms);
    if (platforms.length) {
      out.push(`Platforms: ${platforms.map(code).join(", ")}`, "");
    }
    if (build.result === "blocked") {
      out.push(
        "Chalk stopped this command before docker ran: nothing was built or pushed.",
        "",
      );
    }
  }
  return out.join("\n");
}

module.exports = {
  annotationCommands,
  checkAnnotations,
  dockerfileInstructions,
  escapeData,
  escapeProperty,
  locateFinding,
  locateFindings,
  normalizeImage,
  parseReports,
  readReports,
  renderSummary,
  summarize,
  toBuilds,
};
