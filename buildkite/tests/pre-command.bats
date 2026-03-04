#!/usr/bin/env bats

setup() {
    export BUILDKITE_BUILD_ID="test-build-001"
    export BUILDKITE_BUILD_PATH="/tmp/chalk-bats-test"
    mkdir -p "${BUILDKITE_BUILD_PATH}"
}

teardown() {
    rm -rf "${BUILDKITE_BUILD_PATH}"
}

@test "pre-command hook warns when chalk not found" {
    unset CHALK_HOME
    run bash hooks/pre-command
    [ "$status" -eq 0 ]
    [[ "$output" == *"Chalk not found"* ]]
}

@test "pre-command hook reports chalk version when CHALK_HOME set" {
    export CHALK_HOME="${BUILDKITE_BUILD_PATH}/.chalk-${BUILDKITE_BUILD_ID}"
    mkdir -p "${CHALK_HOME}/bin"
    # Create a mock chalk binary
    echo '#!/bin/sh' > "${CHALK_HOME}/bin/chalk"
    echo 'echo "chalk version 0.6.5"' >> "${CHALK_HOME}/bin/chalk"
    chmod +x "${CHALK_HOME}/bin/chalk"
    export PATH="${CHALK_HOME}/bin:${PATH}"

    run bash hooks/pre-command
    [ "$status" -eq 0 ]
    [[ "$output" == *"Chalk ready"* ]]
}
