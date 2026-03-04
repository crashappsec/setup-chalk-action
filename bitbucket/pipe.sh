#!/usr/bin/env bash
set -eu

CHALK_VERSION="${CHALK_VERSION:-}"
CHALK_LOAD="${CHALK_LOAD:-}"
CHALK_TOKEN="${CHALK_TOKEN:-}"
CHALK_CONNECT="${CHALK_CONNECT:-false}"
CHALK_PROFILE="${CHALK_PROFILE:-default}"
CHALK_NO_WRAP="${CHALK_NO_WRAP:-false}"
CHALK_COMMAND="${CHALK_COMMAND:-chalk --version}"
CHALK_PREFIX="${CHALK_PREFIX:-/usr/local}"

echo "Setting up Chalk..."

CHALK_FLAGS=""
[[ -n "${CHALK_VERSION}" ]]   && CHALK_FLAGS="$CHALK_FLAGS --version=${CHALK_VERSION}"
[[ -n "${CHALK_LOAD}" ]]      && CHALK_FLAGS="$CHALK_FLAGS --load=${CHALK_LOAD}"
[[ -n "${CHALK_PROFILE}" ]]   && CHALK_FLAGS="$CHALK_FLAGS --profile=${CHALK_PROFILE}"
[[ "${CHALK_CONNECT}" == "true" ]] && CHALK_FLAGS="$CHALK_FLAGS --connect"
[[ "${CHALK_NO_WRAP}" == "true" ]] && CHALK_FLAGS="$CHALK_FLAGS --no-wrap"

CHALK_PREFIX="${CHALK_PREFIX}" \
CHALK_TOKEN="${CHALK_TOKEN}" \
    /usr/local/bin/chalk-setup.sh $CHALK_FLAGS

echo "Chalk installed successfully: $(chalk --version)"

if [[ "${CHALK_COMMAND}" != "chalk --version" ]]; then
    echo "Running: ${CHALK_COMMAND}"
    eval "${CHALK_COMMAND}"
fi
