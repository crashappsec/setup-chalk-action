"""Run the full installer against an older API, with a harmless local Chalk."""
import http.server
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="chalk-public-policy-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # macOS filesystem sandboxes can deny opening /dev/stderr even though
        # the inherited descriptor is writable. Normalize only those logging
        # redirections in the test copy; discovery/install code runs unchanged.
        self.script = self.root / "setup-under-test.sh"
        self.script.write_text((ROOT / "setup.sh").read_text().replace(
            "> /dev/stderr", ">&2"))
        self.status = 200
        self.headers = {}
        self.delay = 0
        self.requests = []
        test = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                test.requests.append(self.path)
                path = urlsplit(self.path).path
                status, headers, body = 200, {}, b"1.3.0"
                if path == "/v0.1/routes/chalkapi":
                    headers["x-chalk-api-host"] = "https://chalk.invalid"
                elif path == "/v0.1/profile/version":
                    time.sleep(test.delay)
                    status, headers = test.status, test.headers
                elif path == "/v0.1/profile":
                    headers = {"x-chalk-component-url": "https://chalk.invalid/component",
                               "x-chalk-component-parameters-url": "https://chalk.invalid/params"}
                elif path == "/params":
                    body = b"[]"
                elif path == "/component":
                    body = b"# Old API profile fixture\n"
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            do_POST = do_GET

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        tools = self.root / "tools"
        tools.mkdir()
        # Every target is owned temporary test data; no privilege escalation is
        # needed when the installer's platform permission check requests sudo.
        sudo = tools / "sudo"
        sudo.write_text('#!/bin/sh\nexec "$@"\n')
        sudo.chmod(0o755)
        curl = tools / "curl"
        curl.write_text(
            "#!/usr/bin/env python3\nimport os,sys\nfrom urllib.parse import urlsplit\n"
            "args=[]\nfor arg in sys.argv[1:]:\n"
            " if arg.startswith(('http://','https://')):\n"
            "  u=urlsplit(arg)\n"
            f"  arg='http://127.0.0.1:{self.server.server_port}'+u.path+('?' + u.query if u.query else '')\n"
            " args.append(arg)\n"
            f"os.execv({shutil.which('curl')!r},['curl',*args])\n"
        )
        curl.chmod(0o755)
        fake = self.root / "fake-chalk"
        fake.write_text('#!/bin/sh\nfor arg; do\n'
                        ' if [ "$arg" = version ]; then echo "Chalk executable version is 1.3.0"; fi\n'
                        'done\nexit 0\n')
        fake.chmod(0o755)
        prefix = self.root / "prefix"
        (prefix / "bin").mkdir(parents=True)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("CHALK_", "__CHALK_", "GITHUB_"))}
        self.env.update(
            PATH=str(prefix / "bin") + os.pathsep + str(tools) + os.pathsep + os.environ["PATH"],
            RUNNER_TEMP=str(self.root), CHALK_TMP=str(self.root), CHALK_PREFIX=str(prefix),
            CHALK_COPY_FROM=str(fake), CHALK_TOKEN="test-token", CHALK_VERSION="1.3.0",
            CHALK_ATTEMPTS="1", GITHUB_REPOSITORY="acme/app", GITHUB_OUTPUT=str(self.root / "output"),
        )

    def install(self, args=None, **env):
        (self.root / "output").write_text("")
        # The installer opens /dev/stderr directly; use a regular log file so
        # that reopening this descriptor also works in a filesystem sandbox.
        log_path = self.root / "stderr.log"
        with log_path.open("w") as log:
            result = subprocess.run(
                ["sh", str(self.script), *(args or ["--no-wrap"])], env=self.env | env,
                cwd=ROOT, stdout=subprocess.PIPE, stderr=log, text=True, timeout=15,
            )
        result.stderr = log_path.read_text()
        output = dict(line.split("=", 1) for line in (self.root / "output").read_text().splitlines())
        return result, output

    def test_old_api_without_policy_headers_installs_with_pinned_and_profile_versions(self):
        for version in ("1.3.0", ""):
            with self.subTest(version=version):
                result, output = self.install(CHALK_VERSION=version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output, {"policy_can_block": "false", "policy_ids": ""})
                self.assertTrue((self.root / "prefix/bin/chalk").is_file())

    def test_missing_or_failed_optional_endpoint_keeps_pinned_install_working(self):
        for status in (404, 503):
            self.status = status
            result, output = self.install()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output["policy_can_block"], "false")

    def test_stalled_policy_lookup_does_not_hang_pinned_install(self):
        self.delay = 20
        start = time.monotonic()
        result, output = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output["policy_can_block"], "false")
        self.assertLess(time.monotonic() - start, 12.5)

    def test_failed_lookup_and_early_setup_failure_clear_previous_profile(self):
        self.headers = {"x-chalk-policy": "enforce", "x-chalk-policy-ids": "previous@1"}
        result, output = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output["policy_can_block"], "true")
        self.status = 503
        result, output = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, {"policy_can_block": "false", "policy_ids": ""})
        (self.root / "setup-chalk-policy.env").write_text("policy_can_block=true\npolicy_ids=stale@1\n")
        result, output = self.install(args=["--invalid-argument"])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output["policy_can_block"], "false")
        self.assertEqual((self.root / "setup-chalk-policy.env").read_text(),
                         "policy_can_block=false\npolicy_ids=\n")

    def test_a_missing_repository_never_matches_enforce_repos_star(self):
        self.headers = {"x-chalk-policy": "enforce-repos", "x-chalk-policy-enforce-repos": "*"}
        result, output = self.install(GITHUB_REPOSITORY="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output["policy_can_block"], "false")

    def test_unwritable_optional_fallback_does_not_fail_installation(self):
        (self.root / "setup-chalk-policy.env").mkdir()
        result, output = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output["policy_can_block"], "false")


if __name__ == "__main__":
    unittest.main()
