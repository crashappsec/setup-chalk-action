#!/usr/bin/env bash
set -euo pipefail

# Creates a temporary git repo from the mounted shared library source files.
# Jenkins shared libraries require a git repo root with vars/ (and optionally resources/).
# Also patches the hardcoded GitHub URL in setupChalk.groovy to point at the local HTTP server.

LIBRARY_SRC=/var/jenkins_library_src
LIBRARY_REPO=/var/jenkins_library_repo

echo "==> Initializing shared library git repo at ${LIBRARY_REPO}"

# Clean contents but keep the directory (owned by jenkins from Dockerfile)
rm -rf "${LIBRARY_REPO:?}"/*
rm -rf "${LIBRARY_REPO}"/.git 2>/dev/null || true

# Copy library source files
cp -r "${LIBRARY_SRC}/vars" "${LIBRARY_REPO}/vars"
if [ -d "${LIBRARY_SRC}/resources" ]; then
    cp -r "${LIBRARY_SRC}/resources" "${LIBRARY_REPO}/resources"
fi

# Patch the hardcoded GitHub URL to point at local HTTP server
sed -i 's|https://raw.githubusercontent.com/crashappsec/setup-chalk-action/main/setup.sh|http://localhost:9999/setup.sh|g' \
    "${LIBRARY_REPO}/vars/setupChalk.groovy"

echo "==> Patched setupChalk.groovy URL to use local HTTP server"

# Initialize git repo (Jenkins SCM retriever requires it)
cd "${LIBRARY_REPO}"
git init -b main
git config user.email "test@test.local"
git config user.name "Test"
git add .
git commit -m "init shared library for testing"

echo "==> Shared library git repo ready at ${LIBRARY_REPO}"
