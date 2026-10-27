"""Run the full installer with and without an explicit Chalk API host.

curl is shimmed to record each requested URL and send it to a local server
standing in for every CrashOverride endpoint; Chalk itself is a harmless stub.
"""
import http.server
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
ENTITLEMENTS = "entitlements.crashoverride.run"
DISCOVERED = "chalkapi.discovered.invalid"
OVERRIDE = "chalk-sandbox.test.invalid"


class ChalkApiHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="chalkapi-host-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # macOS filesystem sandboxes can deny reopening /dev/stderr; only the
        # logging redirections differ from setup.sh.
        self.script = self.root / "setup-under-test.sh"
        self.script.write_text((ROOT / "setup.sh").read_text().replace("> /dev/stderr", ">&2"))

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                # suffix match: a Chalk API host may carry a path prefix
                path = urlsplit(self.path).path
                headers, body = {}, b""
                if "/v0.1/routes/" in path:
                    headers["x-chalk-api-host"] = f"https://{DISCOVERED}"
                elif "/v0.1/openid-connect/" in path:
                    headers["x-chalk-jwt"] = "chalk-jwt-from-oidc"
                elif path == "/oidc-token":
                    body = b'{"value": "github-oidc-jwt"}'
                elif path.endswith("/v0.1/profile/version"):
                    body = b"1.3.0"
                elif path.endswith("/v0.1/profile"):
                    headers = {"x-chalk-component-url": "https://cdn.invalid/component",
                               "x-chalk-component-parameters-url": "https://cdn.invalid/params"}
                elif path == "/params":
                    body = b"[]"
                elif path == "/component":
                    body = b"# profile fixture\n"
                self.send_response(200)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        tools = self.root / "tools"
        tools.mkdir()
        sudo = tools / "sudo"
        sudo.write_text('#!/bin/sh\nexec "$@"\n')
        sudo.chmod(0o755)
        self.url_log = self.root / "urls.log"
        curl = tools / "curl"
        curl.write_text(
            "#!/usr/bin/env python3\nimport os,sys\nfrom urllib.parse import urlsplit\n"
            "args=[]\nfor arg in sys.argv[1:]:\n"
            " if arg.startswith(('http://','https://')):\n"
            f"  open({str(self.url_log)!r},'a').write(arg+'\\n')\n"
            "  u=urlsplit(arg)\n"
            f"  arg='http://127.0.0.1:{server.server_port}'+u.path+('?'+u.query if u.query else '')\n"
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
                    if not key.startswith(("CHALK_", "__CHALK_", "GITHUB_", "GITLAB_", "ACTIONS_",
                                           "RUNNER_", "CI"))}
        self.env.update(
            PATH=str(prefix / "bin") + os.pathsep + str(tools) + os.pathsep + os.environ["PATH"],
            CHALK_TMP=str(self.root), CHALK_PREFIX=str(prefix), CHALK_COPY_FROM=str(fake),
            CHALK_ATTEMPTS="1", CHALK_TOKEN="api-key", CHALK_VERSION="",
        )

    def install(self, **env):
        self.url_log.write_text("")
        (self.root / "prefix/bin/chalk").unlink(missing_ok=True)
        log_path = self.root / "stderr.log"
        with log_path.open("w") as log:
            result = subprocess.run(
                ["sh", str(self.script), "--no-wrap"], env=self.env | env, cwd=ROOT,
                stdout=subprocess.PIPE, stderr=log, text=True, timeout=30,
            )
        result.stderr = log_path.read_text()
        result.urls = self.url_log.read_text().splitlines()
        result.hosts = [urlsplit(url).netloc for url in result.urls]
        return result

    def assert_installed_without_entitlements(self, result, host):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(ENTITLEMENTS, result.hosts)
        self.assertIn(f"https://{host}/v0.1/profile/version?", " ".join(result.urls))
        self.assertIn(f"https://{host}/v0.1/profile?", " ".join(result.urls))
        self.assertTrue((self.root / "prefix/bin/chalk").is_file())

    def test_host_set_skips_entitlements_for_token(self):
        for host in (OVERRIDE, "127.0.0.1:8443", f"{OVERRIDE}/chalk/api"):
            with self.subTest(host=host):
                result = self.install(CHALK_API_HOST=f"https://{host}")
                self.assert_installed_without_entitlements(result, host)

    def test_host_set_skips_entitlements_for_github_oidc(self):
        result = self.install(
            CHALK_API_HOST=f"https://{OVERRIDE}", CHALK_TOKEN="", CHALK_CONNECT="true",
            CI="true", GITHUB_SHA="0" * 40, ACTIONS_ID_TOKEN_REQUEST_TOKEN="request-token",
            ACTIONS_ID_TOKEN_REQUEST_URL="https://token.actions.invalid/oidc-token?id=1",
        )
        self.assert_installed_without_entitlements(result, OVERRIDE)
        self.assertIn(f"https://{OVERRIDE}/v0.1/openid-connect/github?verbose=false", result.urls)

    def test_host_set_skips_entitlements_for_gitlab_oidc(self):
        result = self.install(
            CHALK_API_HOST=f"https://{OVERRIDE}", CHALK_TOKEN="", CHALK_OIDC="gitlab-oidc-jwt",
            CI="true", GITLAB_CI="true",
        )
        self.assert_installed_without_entitlements(result, OVERRIDE)
        self.assertIn(f"https://{OVERRIDE}/v0.1/openid-connect/gitlab?verbose=false", result.urls)

    def test_host_unset_looks_it_up_via_entitlements(self):
        # the action passes an empty input through as an empty variable
        for env in ({}, {"CHALK_API_HOST": ""}):
            with self.subTest(env=env):
                result = self.install(**env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.urls[0], f"https://{ENTITLEMENTS}/v0.1/routes/chalkapi?verbose=false")
                self.assertEqual(result.hosts.count(ENTITLEMENTS), 1)
                self.assertIn(f"https://{DISCOVERED}/v0.1/profile/version?", " ".join(result.urls))

    def test_invalid_host_fails_before_any_request(self):
        for value in (
            f"http://{OVERRIDE}",
            f"https://{OVERRIDE}/",
            OVERRIDE,
            "https://",
            f"https://user:pass@{OVERRIDE}",
            f"https://{OVERRIDE}?x=1",
            f"https://{OVERRIDE}#x",
            f" https://{OVERRIDE}",
            f"https://{OVERRIDE}\n",
            f"https://{OVERRIDE}\nhttps://{OVERRIDE}",
            f"https://{OVERRIDE}//v0.1",
            f"https://-{OVERRIDE}",
        ):
            with self.subTest(value=value):
                result = self.install(CHALK_API_HOST=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Invalid Chalk API host", result.stderr)
                self.assertIn("https URL without a trailing slash", result.stderr)
                self.assertEqual(result.urls, [])
                self.assertFalse((self.root / "prefix/bin/chalk").exists())


if __name__ == "__main__":
    unittest.main()
