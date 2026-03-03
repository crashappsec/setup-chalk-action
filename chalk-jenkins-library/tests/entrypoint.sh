#!/usr/bin/env bash
set -euo pipefail

# 1. Initialize the shared library git repo
/usr/local/bin/init-library-repo.sh

# 2. Start a local HTTP file server to serve setup.sh
echo "==> Starting local HTTP server on port 9999 serving /var/chalk-setup"
python3 -m http.server 9999 --directory /var/chalk-setup &

# 3. Exec into the default Jenkins entrypoint
exec /usr/local/bin/jenkins.sh "$@"
