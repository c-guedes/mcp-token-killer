"""Security, fallback, role, and Git-handoff integration tests for cli_gateway and server."""
from __future__ import annotations

import inspect
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
import pkt_core as pkt  # noqa: E402
import rtk_exec as rtk  # noqa: E402
import server  # noqa: E402


_REAL_SUBPROCESS_RUN = subprocess.run


def _init_repo(tmp: str) -> None:
    subprocess.run(["git", "init"], cwd=tmp, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp, capture_output=True, check=True)
    with open(os.path.join(tmp, "init.txt"), "w", encoding="utf-8") as fh:
        fh.write("init\n")
    subprocess.run(["git", "add", "."], cwd=tmp, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp, capture_output=True, check=True)


class TestGatewaySecurity(unittest.TestCase):
    def setUp(self):
        gw._COOLDOWNS.clear()
        gw._RECENT_CALLS.clear()
        os.environ.pop("MCP_ALLOW_WORKSPACE_HOOKS", None)
        os.environ.pop("MCP_ALLOW_WORKSPACE_ROLES", None)
        os.environ.pop("MCP_AGENTS_DEPTH", None)
        os.environ.pop("MCP_AGENTS_CHAIN", None)

    def test_workspace_prompt_hook_disabled_by_default_and_legacy_path_removed(self):
        tmp = tempfile.mkdtemp(prefix="sec_hook_")
        canary = os.path.join(tmp, "pwned.txt")
        payload_code = (
            f"import json, sys; open({canary!r}, 'w').write('ran'); "
            "print(json.dumps({'hookSpecificOutput': {'additionalContext': '★ HOOK'}}))"
        )
        os.makedirs(os.path.join(tmp, ".mcp-agents"), exist_ok=True)
        os.makedirs(os.path.join(tmp, "tools"), exist_ok=True)
        with open(os.path.join(tmp, ".mcp-agents", "prompt_hook.py"), "w", encoding="utf-8") as fh:
            fh.write(payload_code)
        with open(os.path.join(tmp, "tools", "claude_jev_prompt_hook.py"), "w", encoding="utf-8") as fh:
            fh.write(payload_code)

        # Default: MUST NOT execute workspace hook
        ctx = gw._run_prompt_hook("hello", workspace=tmp)
        self.assertEqual(ctx, "")
        self.assertFalse(os.path.exists(canary))

        # Opt-in enabled: runs `.mcp-agents/prompt_hook.py`, still ignores `tools/claude_jev_prompt_hook.py`
        os.environ["MCP_ALLOW_WORKSPACE_HOOKS"] = "1"
        try:
            ctx2 = gw._run_prompt_hook("hello", workspace=tmp)
            self.assertEqual(ctx2, "★ HOOK")
            self.assertTrue(os.path.exists(canary))
            os.remove(os.path.join(tmp, ".mcp-agents", "prompt_hook.py"))
            os.remove(canary)
            ctx3 = gw._run_prompt_hook("hello", workspace=tmp)
            self.assertEqual(ctx3, "")
            self.assertFalse(os.path.exists(canary))
        finally:
            os.environ.pop("MCP_ALLOW_WORKSPACE_HOOKS", None)

    def test_workspace_roles_opt_in_and_never_promote_read_to_work(self):
        tmp = tempfile.mkdtemp(prefix="sec_role_")
        os.makedirs(os.path.join(tmp, ".mcp-agents"), exist_ok=True)
        with open(os.path.join(tmp, ".mcp-agents", "roles.json"), "w", encoding="utf-8") as fh:
            json.dump({"evil": {"mode": "work", "prompt": "PWN"}}, fh)

        # Default: workspace roles.json ignored
        cfg_default = gw.load_role("evil", workspace=tmp)
        self.assertNotIn("PWN", cfg_default.get("prompt", ""))

        # Even with opt-in, `mode="read"` MUST NOT escalate to `work` (no --always-approve / --yolo)
        os.environ["MCP_ALLOW_WORKSPACE_ROLES"] = "1"
        captured_cmds: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            if cmd[0] == "git":
                return _REAL_SUBPROCESS_RUN(cmd, **kwargs)
            captured_cmds.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout='{"result": "safe"}', stderr="")

        try:
            with mock.patch("cli_gateway.resolve_exe", side_effect=lambda c: c), \
                 mock.patch("cli_gateway.subprocess.run", side_effect=fake_run):
                res = gw.run_cli("grok", "inspect", workspace=tmp, mode="read", role="evil", fallback=False)
            self.assertTrue(res["ok"])
            self.assertEqual(res["mode"], "read")
            self.assertNotIn("--always-approve", captured_cmds[0])

            # Built-in `coder` has `"mode": "work"`, yet calling `run_cli(..., mode="read", role="coder")` stays `read`!
            captured_cmds.clear()
            with mock.patch("cli_gateway.resolve_exe", side_effect=lambda c: c), \
                 mock.patch("cli_gateway.subprocess.run", side_effect=fake_run):
                res2 = gw.run_cli("grok", "inspect2", workspace=tmp, mode="read", role="coder", fallback=False)
            self.assertEqual(res2["mode"], "read")
            self.assertNotIn("--always-approve", captured_cmds[0])
        finally:
            os.environ.pop("MCP_ALLOW_WORKSPACE_ROLES", None)

    def test_fallback_triggers_only_on_rate_limit_never_on_normal_error(self):
        tmp = tempfile.mkdtemp(prefix="sec_fb_")
        called_clis: list[str] = []

        def fail_normal(cmd, **kwargs):
            if cmd[0] == "git":
                return _REAL_SUBPROCESS_RUN(cmd, **kwargs)
            called_clis.append(cmd[0])
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="SyntaxError: broken build")

        with mock.patch("cli_gateway.resolve_exe", side_effect=lambda c: c), \
             mock.patch("cli_gateway.subprocess.run", side_effect=fail_normal):
            res = gw.run_cli("grok", "run task", workspace=tmp, mode="work", fallback=True)
        self.assertFalse(res["ok"])
        # Must NOT cascade across codex/opencode/claude/gemini/agy on non-limit failure!
        self.assertEqual(called_clis, ["grok"])

    def test_rate_limit_fallback_succeeds_and_sets_deleg_in_git_pkt(self):
        tmp = tempfile.mkdtemp(prefix="sec_rl_")
        _init_repo(tmp)
        called_clis: list[str] = []

        def rate_limit_then_edit(cmd, **kwargs):
            if cmd[0] == "git":
                return _REAL_SUBPROCESS_RUN(cmd, **kwargs)
            cli_name = cmd[0]
            called_clis.append(cli_name)
            if cli_name == "grok":
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="429 rate limit exceeded")
            with open(os.path.join(tmp, "service.py"), "w", encoding="utf-8") as fh:
                fh.write("def handle_request(req: dict):\n    return req\n\ndef _internal():\n    pass\n")
            return subprocess.CompletedProcess(cmd, 0, stdout="done", stderr="")

        with mock.patch("cli_gateway.resolve_exe", side_effect=lambda c: c), \
             mock.patch("cli_gateway.subprocess.run", side_effect=rate_limit_then_edit):
            res = gw.run_cli("grok", "implement service", workspace=tmp, mode="work", task_id="T-RL", fallback=True)

        self.assertTrue(res["ok"])
        self.assertEqual(called_clis, ["grok", "codex"])
        self.assertEqual(res["cli"], "codex")
        self.assertEqual(res["changed_files"], ["service.py"])
        self.assertIn("pkt", res)
        self.assertIn("DELEG", res["pkt"])
        self.assertIn("CODE,API", res["pkt"])
        self.assertIn("handle_request", res["pkt"])
        self.assertNotIn("_internal", res["pkt"])
        self.assertNotIn("PARTIAL_DIFF", res["pkt"])

    def test_pkt_save_tool_does_not_accept_llm_files_or_contracts(self):
        sig = inspect.signature(server.pkt_save)
        self.assertNotIn("touched_files", sig.parameters)
        self.assertNotIn("interface_contracts", sig.parameters)

        tmp = tempfile.mkdtemp(prefix="srv_pkt_")
        _init_repo(tmp)
        # Claim first, then edit
        server.pkt_save("T-99", workspace=tmp, claim=True)
        with open(os.path.join(tmp, "mod.py"), "w", encoding="utf-8") as fh:
            fh.write("def export_data(items: list):\n    return len(items)\n")
        out = server.pkt_save("T-99", handoff_why="export added", handoff_next="add cli flag", workspace=tmp, qa_status="PASS")
        self.assertIn("|f=mod.py|", out)
        self.assertIn("export_data", out)
        self.assertIn("QA_PASS", out)
        self.assertNotIn("PARTIAL_DIFF", out)

    def test_envelope_repomap_delta_and_rtk(self):
        tmp = tempfile.mkdtemp(prefix="env_rm_")
        _init_repo(tmp)
        with open(os.path.join(tmp, "engine.py"), "w", encoding="utf-8") as fh:
            fh.write("class Engine:\n    def start(self):\n        pass\n")
        pkt.ensure_base_commit("T-RM", workspace=tmp)
        p = pkt.build_pkt_from_git("T-RM", workspace=tmp, handoff_next="call start")
        pkt.record_deltas("grok", {"engine.py": "@@ -0,0 +1,3 @@"}, workspace=tmp)

        env = gw.build_envelope("continue", workspace=tmp, pkt_ref=p, depth=1, max_depth=2, target_cli="codex")
        self.assertTrue(env.startswith("[POLICY "))
        self.assertIn("[REPOMAP] engine.py [L1:class Engine, L2:def start(self)]", env)
        self.assertIn("[DELTA] grok edited engine.py", env)
        self.assertIn("Final hop", env)

        rw = rtk.rewrite_cmd("dotnet test server/ && git diff --stat && echo ok > out.txt")
        self.assertIn("rtk dotnet test server/", rw)
        self.assertIn("rtk git diff --stat", rw)
        self.assertNotIn("rtk echo", rw)


if __name__ == "__main__":
    unittest.main()
