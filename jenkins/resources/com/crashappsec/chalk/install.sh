#!/usr/bin/env bash
set -eu

CHALK_VERSION="${CHALK_VERSION:-}"
CHALK_PREFIX="${CHALK_PREFIX:-/usr/local}"
CHALK_TOKEN="${CHALK_TOKEN:-}"

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Linux)  OS_NAME="Linux"  ;;
    Darwin) OS_NAME="Darwin" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64)        ARCH_NAME="x86_64"  ;;
    aarch64|arm64) ARCH_NAME="aarch64" ;;
    *)             echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

BASE_URL="https://dl.crashoverride.run/chalk"

if [ -z "$CHALK_VERSION" ]; then
    CHALK_VERSION=$(curl -fsSL "${BASE_URL}/current-version.txt")
fi

NAME="chalk-${CHALK_VERSION}-${OS_NAME}-${ARCH_NAME}"
URL="${BASE_URL}/${NAME}"
DEST="${CHALK_PREFIX}/bin/chalk"

mkdir -p "${CHALK_PREFIX}/bin"
curl -fsSL -o "${DEST}" "${URL}"
curl -fsSL -o "/tmp/chalk.sha256" "${URL}.sha256"
( cd "${CHALK_PREFIX}/bin" && sha256sum -c /tmp/chalk.sha256 )
chmod +x "${DEST}"
"${DEST}" --version
