"""Only allowed + installed CLIs are used; login is probed and auth failures are handled like limits."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cli_gateway as gw  # noqa: E402
import server  # noqa: E402

_REAL_RUN = subprocess.run


def installed_only(*names):
    """resolve_exe stub: only `names` exist on PATH."""
    def _resolve(cmd):
        return cmd if cmd and cmd[0] in names else []
    return _resolve


class Base(unittest.TestCase):
    def setUp(self):
        gw._COOLDOWNS.clear()
        gw._RECENT_CALLS.clear()
        gw._LOGIN_STATE.clear()
        os.environ.pop("MCP_AGENTS_ALLOWED", None)
        os.environ.pop("MCP_AGENTS_DEPTH", None)
        os.environ.pop("MCP_AGENTS_CHAIN", None)
        self.tmp = tempfile.mkdtemp(prefix="sel_")

    def tearDown(self):
        os.environ.pop("MCP_AGENTS_ALLOWED", None)


class TestAllowlist(Base):
    def test_default_is_all_supported(self):
        self.assertEqual(gw.allowed_clis(), gw.DEFAULT_CHAIN)

    def test_env_restricts_and_keeps_given_order(self):
        os.environ["MCP_AGENTS_ALLOWED"] = "codex, claude ,nope"
        self.assertEqual(gw.allowed_clis(), ("codex", "claude"))

    def test_disallowed_cli_is_refused_without_running(self):
        os.environ["MCP_AGENTS_ALLOWED"] = "claude"
        with mock.patch("cli_gateway.resolve_exe", side_effect=lambda c: c), \
             mock.patch("cli_gateway.subprocess.run") as run:
            res = gw.run_cli("grok", "x", workspace=self.tmp)
        self.assertFalse(res["ok"])
        self.assertIn("not allowed", res["error"])
        run.assert_not_called()

    def test_status_lists_only_allowed(self):
        os.environ["MCP_AGENTS_ALLOWED"] = "claude,codex"
        with mock.patch("cli_gateway.resolve_exe", side_effect=installed_only("claude")):
            st = gw.list_clis()
        self.assertEqual(set(k for k in st if not k.startswith("_")), {"claude", "codex"})
        self.assertTrue(st["claude"]["available"])
        self.assertFalse(st["codex"]["available"])
        self.assertIn("grok", st["_not_allowed"])


class TestInstalledOnly(Base):
    def test_not_installed_primary_fails_fast(self):
        with mock.patch("cli_gateway.resolve_exe", side_effect=installed_only("codex")), \
             mock.patch("cli_gateway.subprocess.run") as run:
            res = gw.run_cli("claude", "x", workspace=self.tmp)
        self.assertFalse(res["ok"])
        self.assertIn("not installed", res["error"])
        run.assert_not_called()

    def test_fallback_skips_uninstalled_and_reaches_installed(self):
        # Default order: grok, codex, opencode, claude... Only grok and claude exist here.
        called = []

        def fake(cmd, **kw):
            if cmd[0] == "git":
                return _REAL_RUN(cmd, **kw)
            called.append(cmd[0])
            if cmd[0] == "grok":
                return subprocess.CompletedProcess(cmd, 1, "", "429 rate limit exceeded")
            return subprocess.CompletedProcess(cmd, 0, "feito", "")

        with mock.patch("cli_gateway.resolve_exe", side_effect=installed_only("grok", "claude")), \
             mock.patch("cli_gateway.subprocess.run", side_effect=fake):
            res = gw.run_cli("grok", "x", workspace=self.tmp)
        self.assertTrue(res["ok"])
        self.assertEqual(called, ["grok", "claude"])  # codex/opencode never attempted

    def test_fallback_respects_allowlist(self):
        os.environ["MCP_AGENTS_ALLOWED"] = "grok"
        called = []

        def fake(cmd, **kw):
            called.append(cmd[0])
            return subprocess.CompletedProcess(cmd, 1, "", "429 rate limit exceeded")

        with mock.patch("cli_gateway.resolve_exe", side_effect=lambda c: c), \
             mock.patch("cli_gateway.subprocess.run", side_effect=fake):
            res = gw.run_cli("grok", "x", workspace=self.tmp)
        self.assertFalse(res["ok"])
        self.assertEqual(called, ["grok"])


class TestLogin(Base):
    def _probe_with(self, rc, out, err="", exc=None):
        def fake(cmd, **kw):
            if exc:
                raise exc
            self.assertEqual(kw.get("cwd"), gw._probe_dir())  # fixed scratch dir, outside the project
            self.assertGreaterEqual(int(kw["env"]["MCP_AGENTS_DEPTH"]), gw.MAX_DEPTH)  # no nested agents
            return subprocess.CompletedProcess(cmd, rc, out, err)

        with mock.patch("cli_gateway.resolve_exe", side_effect=lambda c: c), \
             mock.patch("cli_gateway.subprocess.run", side_effect=fake):
            return gw.probe_login("claude")

    def test_ok(self):
        r = self._probe_with(0, json.dumps({"result": "ok", "session_id": "s"}))
        self.assertEqual(r["login"], "ok")

    def test_expired_oauth(self):
        r = self._probe_with(1, "", "Failed to authenticate: OAuth session expired and could not be refreshed")
        self.assertEqual(r["login"], "auth_error")
        self.assertEqual(gw._LOGIN_STATE["claude"]["login"], "auth_error")

    def test_is_error_json_with_rc0(self):
        r = self._probe_with(0, json.dumps({"is_error": True, "result": "Invalid API key"}))
        self.assertEqual(r["login"], "auth_error")

    def test_rate_limited(self):
        self.assertEqual(self._probe_with(1, "", "429 Too Many Requests")["login"], "rate_limited")

    def test_timeout(self):
        r = self._probe_with(0, "", exc=subprocess.TimeoutExpired("claude", 60))
        self.assertEqual(r["login"], "timeout")

    def test_status_check_login_probes_only_installed(self):
        os.environ["MCP_AGENTS_ALLOWED"] = "claude,codex"
        probed = []

        def fake(cmd, **kw):
            probed.append(cmd[0])
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"result": "ok"}), "")

        with mock.patch("cli_gateway.resolve_exe", side_effect=installed_only("claude")), \
             mock.patch("cli_gateway.subprocess.run", side_effect=fake):
            st = json.loads(server.agent_run(cli="status", check_login=True))
        self.assertEqual(probed, ["claude"])
        self.assertEqual(st["claude"]["login"], "ok")
        self.assertNotIn("login", st["codex"])

    def test_auth_error_during_run_falls_back_and_is_skipped_next_time(self):
        called = []

        def fake(cmd, **kw):
            if cmd[0] == "git":
                return _REAL_RUN(cmd, **kw)
            called.append(cmd[0])
            if cmd[0] == "claude":
                return subprocess.CompletedProcess(cmd, 1, "", "Failed to authenticate: token expired")
            return subprocess.CompletedProcess(cmd, 0, "feito", "")

        os.environ["MCP_AGENTS_ALLOWED"] = "claude,codex"
        with mock.patch("cli_gateway.resolve_exe", side_effect=lambda c: c), \
             mock.patch("cli_gateway.subprocess.run", side_effect=fake):
            res = gw.run_cli("claude", "x", workspace=self.tmp)
            self.assertTrue(res["ok"])
            self.assertEqual(res["cli"], "codex")
            # codex is primary now; claude is known logged-out and must not be a fallback candidate
            called.clear()
            gw._RECENT_CALLS.clear()
            os.environ["MCP_AGENTS_ALLOWED"] = "codex,claude"
            with mock.patch("cli_gateway.subprocess.run", side_effect=lambda cmd, **kw: (
                    _REAL_RUN(cmd, **kw) if cmd[0] == "git"
                    else (called.append(cmd[0]) or subprocess.CompletedProcess(cmd, 1, "", "429 rate limit")))):
                gw.run_cli("codex", "y", workspace=self.tmp)
        self.assertEqual(called, ["codex"])

    def test_unexpected_exception_is_reported_not_raised(self):
        r = self._probe_with(0, "", exc=PermissionError("[WinError 32] in use"))
        self.assertEqual(r["login"], "error")
        self.assertIn("PermissionError", r["detail"])

    def test_normal_failure_is_not_auth(self):
        self.assertFalse(gw._is_auth_error("", "SyntaxError: broken build", 1))
        self.assertFalse(gw._is_auth_error("all good, oauth module refactored", "", 0))


if __name__ == "__main__":
    unittest.main()
