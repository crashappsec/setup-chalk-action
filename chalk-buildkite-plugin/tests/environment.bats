#!/usr/bin/env bats

setup() {
    export BUILDKITE_PLUGIN_CHALK_VERSION="0.6.5"
    export BUILDKITE_PLUGIN_CHALK_CONNECT="false"
    export BUILDKITE_PLUGIN_CHALK_PROFILE="default"
    export BUILDKITE_PLUGIN_CHALK_NO_WRAP="false"
    export BUILDKITE_BUILD_ID="test-build-001"
    export BUILDKITE_BUILD_PATH="/tmp/chalk-bats-test"
    mkdir -p "${BUILDKITE_BUILD_PATH}"
}

teardown() {
    rm -rf "${BUILDKITE_BUILD_PATH}"
    rm -f "/tmp/chalk-setup-${BUILDKITE_BUILD_ID}.sh"
}

@test "environment hook installs chalk" {
    run bash hooks/environment
    [ "$status" -eq 0 ]
    [[ "$output" == *"Chalk installed successfully"* ]]
}

@test "chalk binary is executable after hook" {
    bash hooks/environment
    run "${BUILDKITE_BUILD_PATH}/.chalk-${BUILDKITE_BUILD_ID}/bin/chalk" --version
    [ "$status" -eq 0 ]
}
