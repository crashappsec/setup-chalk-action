#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check required tools
for cmd in docker curl python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "FAIL: Required tool '${cmd}' is not installed"
        exit 1
    fi
done

JENKINS_URL="http://localhost:8080"
JENKINS_USER="admin"
JENKINS_PASS="admin"
JOB_NAME="chalk-e2e-test"
MAX_WAIT=300  # 5 minutes
COOKIE_JAR=$(mktemp /tmp/jenkins-cookies.XXXXXX)

cleanup() {
    echo "==> Cleaning up..."
    rm -f "$COOKIE_JAR"
    docker compose down --volumes --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# All Jenkins curl calls share the same cookie jar for session-bound crumbs
curl_jenkins() {
    curl -fsSL --user "${JENKINS_USER}:${JENKINS_PASS}" \
        --cookie "$COOKIE_JAR" --cookie-jar "$COOKIE_JAR" \
        "$@"
}

wait_for_jenkins() {
    echo "==> Waiting for Jenkins to be ready (up to ${MAX_WAIT}s)..."
    local elapsed=0
    while [ "$elapsed" -lt "$MAX_WAIT" ]; do
        if curl_jenkins "${JENKINS_URL}/api/json" >/dev/null 2>&1; then
            echo "==> Jenkins is ready (${elapsed}s)"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    echo "FAIL: Jenkins did not become ready within ${MAX_WAIT}s"
    return 1
}

wait_for_job() {
    echo "==> Waiting for job '${JOB_NAME}' to be seeded (up to ${MAX_WAIT}s)..."
    local elapsed=0
    while [ "$elapsed" -lt "$MAX_WAIT" ]; do
        if curl_jenkins "${JENKINS_URL}/job/${JOB_NAME}/api/json" >/dev/null 2>&1; then
            echo "==> Job '${JOB_NAME}' exists (${elapsed}s)"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    echo "FAIL: Job '${JOB_NAME}' was not created within ${MAX_WAIT}s"
    return 1
}

trigger_build() {
    echo "==> Triggering build for '${JOB_NAME}'..."
    local crumb
    crumb=$(curl_jenkins "${JENKINS_URL}/crumbIssuer/api/json" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['crumbRequestField'] + ':' + d['crumb'])")
    local header_name="${crumb%%:*}"
    local header_value="${crumb#*:}"
    curl_jenkins \
        -X POST \
        -H "${header_name}: ${header_value}" \
        "${JENKINS_URL}/job/${JOB_NAME}/build"
    echo "==> Build triggered"
}

wait_for_build() {
    echo "==> Waiting for build #1 to appear (up to 60s)..."
    local elapsed=0
    while [ "$elapsed" -lt 60 ]; do
        if curl_jenkins "${JENKINS_URL}/job/${JOB_NAME}/1/api/json" >/dev/null 2>&1; then
            echo "==> Build #1 exists"
            break
        fi
        sleep 3
        elapsed=$((elapsed + 3))
    done

    echo "==> Waiting for build #1 to complete (up to ${MAX_WAIT}s)..."
    elapsed=0
    while [ "$elapsed" -lt "$MAX_WAIT" ]; do
        local building
        building=$(curl_jenkins "${JENKINS_URL}/job/${JOB_NAME}/1/api/json" 2>/dev/null \
            | python3 -c "import sys,json; print(json.load(sys.stdin).get('building', True))")
        if [ "$building" = "False" ]; then
            echo "==> Build #1 completed (${elapsed}s)"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    echo "FAIL: Build #1 did not complete within ${MAX_WAIT}s"
    return 1
}

print_console_output() {
    echo ""
    echo "========== Jenkins Build Console Output =========="
    curl_jenkins "${JENKINS_URL}/job/${JOB_NAME}/1/consoleText" 2>/dev/null || \
        echo "(could not retrieve console output)"
    echo "=================================================="
    echo ""
}

check_result() {
    local result
    result=$(curl_jenkins "${JENKINS_URL}/job/${JOB_NAME}/1/api/json" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('result', 'UNKNOWN'))")
    echo "==> Build result: ${result}"
    if [ "$result" = "SUCCESS" ]; then
        return 0
    else
        return 1
    fi
}

# --- Main ---

echo "==> Building and starting Jenkins..."
docker compose build
docker compose up -d

wait_for_jenkins
wait_for_job
trigger_build
wait_for_build
print_console_output

if check_result; then
    echo "PASS: Jenkins E2E test succeeded"
    exit 0
else
    echo "FAIL: Jenkins E2E test failed"
    exit 1
fi
