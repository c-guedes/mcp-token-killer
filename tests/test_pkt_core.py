"""Unit tests for standalone @PKT core and CLI gateway."""
from __future__ import annotations

import json
import os
import random
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cli_gateway as gw
import pkt_core as pkt
import rtk_exec as rtk


class TestSmartTruncate(unittest.TestCase):
    def test_short_text_untouched(self):
        self.assertEqual(pkt.smart_truncate("Texto curto", 50), "Texto curto")

    def test_head_tail_marker_exact_count(self):
        text = "INICIO_" + "x" * 100 + "_FIM"
        out = pkt.smart_truncate(text, 50)
        self.assertTrue(out.startswith("INICIO_"))
        self.assertTrue(out.endswith("_FIM"))
        head, _, rest = out.partition("...(+")
        n, _, tail = rest.partition("c)...")
        self.assertEqual(int(n), len(text) - len(head) - len(tail))

    def test_fuzz_never_exceeds_limit(self):
        rng = random.Random(1234)
        for _ in range(1000):
            n, lim = rng.randint(0, 600), rng.randint(0, 300)
            s = "".join(rng.choice("ab cd\n\t") for _ in range(n))
            self.assertLessEqual(len(pkt.smart_truncate(s, lim)), lim)


class TestPktProtocol(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mcp_pkt_")
        self.store = os.path.join(self.tmp, "pkt_refs.json")

    def test_single_line_and_validation(self):
        p = pkt.encode_packet({"id": "T-1", "status": "doing", "cli": "grok"}, workspace=self.tmp, store_path=self.store)
        self.assertNotIn("\n", p)
        self.assertTrue(p.startswith("@PKT|T-1|doing|grok|["))
        with self.assertRaises(pkt.PktValidationError):
            pkt.encode_packet({"id": "T-1", "touched_files": "not-a-list"}, store_path=self.store)

    def test_csharp_semicolons_and_idempotent_hash(self):
        c = {
            "id": "T-2",
            "touched_files": [f"f{i}.gd" for i in range(6)],
            "interface_contracts": ["public int Hp { get; set; }", "void A();", "void B();", "void C();"],
            "handoff_why": "W" * 200,
            "handoff_next": "N" * 200,
        }
        p1 = pkt.encode_packet(c, workspace=self.tmp, store_path=self.store)
        p2 = pkt.encode_packet(c, workspace=self.tmp, store_path=self.store)
        self.assertEqual(p1, p2)
        self.assertIn("(+2)", p1)
        ref = p1.split("|ref=")[1]
        loaded = pkt.load_pkt_refs(self.store)
        self.assertEqual(loaded[ref]["contracts"][0], "public int Hp { get; set; }")

    def test_spill_merge_on_load(self):
        spill = self.store + ".spill.jsonl"
        with open(spill, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"ref": "T-3#abcd1234", "payload": {"files": ["a.py"], "nxt": "go"}}) + "\n")
        loaded = pkt.load_pkt_refs(self.store)
        self.assertEqual(loaded["T-3#abcd1234"]["nxt"], "go")

    def test_resolve_pkt_ref_workspace(self):
        p = pkt.encode_packet(
            {"id": "T-4", "handoff_why": "test", "handoff_next": "next"},
            workspace=self.tmp,
            always_store=True,
        )
        ref = p.split("|ref=")[1]
        resolved = pkt.resolve_pkt_ref(ref, workspace=self.tmp)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["nxt"], "next")

    def test_file_locks_conflict_and_release(self):
        ok1, c1 = pkt.acquire_locks("grok:1", ["src/a.py", "src/b.py"], workspace=self.tmp, cli="grok")
        self.assertTrue(ok1)
        self.assertEqual(c1, [])
        ok2, c2 = pkt.acquire_locks("codex:2", ["src/b.py"], workspace=self.tmp, cli="codex")
        self.assertFalse(ok2)
        self.assertEqual(c2[0]["owner"], "grok:1")
        self.assertEqual(pkt.release_locks("grok:1", workspace=self.tmp), 2)
        ok3, _ = pkt.acquire_locks("codex:2", ["src/b.py"], workspace=self.tmp, cli="codex")
        self.assertTrue(ok3)


class TestCliGateway(unittest.TestCase):
    def test_build_cmds(self):
        self.assertIn("-p", gw.build_cmd("grok", "hi", session_id="s1"))
        self.assertIn("-r", gw.build_cmd("grok", "hi", session_id="s1"))
        self.assertIn("--always-approve", gw.build_cmd("grok", "hi", mode="work"))
        self.assertEqual(gw.build_cmd("codex", "hi", session_id="s2")[-2:], ["s2", "hi"])
        self.assertIn("--resume", gw.build_cmd("claude", "hi", session_id="s3"))
        self.assertIn("--resume", gw.build_cmd("gemini", "hi", session_id="s4"))
        self.assertIn("-s", gw.build_cmd("opencode", "hi", session_id="s5"))

    def test_envelope_injects_pkt_and_policy(self):
        tmp = tempfile.mkdtemp(prefix="mcp_env_")
        p = pkt.encode_packet(
            {"id": "T-5", "touched_files": ["server.py"], "handoff_why": "bug", "handoff_next": "fix it"},
            workspace=tmp,
            always_store=True,
        )
        pkt.record_deltas("grok", {"server.py": "@@ -10,0 +11,3 @@"}, workspace=tmp)
        env = gw.build_envelope("do work", workspace=tmp, pkt_ref=p, depth=1, max_depth=2, target_cli="codex")
        self.assertTrue(env.startswith("[POLICY "))
        self.assertIn("HANDOFF @PKT|T-5", env)
        self.assertNotIn("PKT_PAYLOAD=", env)  # lazy-loaded
        self.assertIn("[DELTA] grok edited server.py: @@ -10,0 +11,3 @@", env)
        self.assertIn("Final hop", env)
        self.assertIn("do work", env)

    def test_opencode_ndjson_and_depth_cycle_guards(self):
        raw = '{"type":"text","sessionID":"ses_123","part":{"type":"text","text":"OK"}}\n'
        txt, sid = gw._extract_json_response(raw)
        self.assertEqual(txt, "OK")
        self.assertEqual(sid, "ses_123")

        os.environ["MCP_AGENTS_DEPTH"] = "2"
        try:
            r = gw.run_cli("grok", "hi", fallback=False)
            self.assertFalse(r["ok"])
            self.assertIn("depth", r["error"].lower())
        finally:
            os.environ.pop("MCP_AGENTS_DEPTH", None)

        os.environ["MCP_AGENTS_CHAIN"] = "grok>codex"
        try:
            r = gw.run_cli("grok", "hi", fallback=False)
            self.assertFalse(r["ok"])
            self.assertIn("Cycle", r["error"])
        finally:
            os.environ.pop("MCP_AGENTS_CHAIN", None)

    def test_roles_and_per_role_sessions(self):
        tmp = tempfile.mkdtemp(prefix="mcp_role_")
        cfg = gw.load_role("architect", workspace=tmp)
        self.assertEqual(cfg.get("mode"), "read")
        self.assertIn("Architect", cfg.get("prompt", ""))

        # Fallback to .claude/agents/<role>.md
        agents_dir = os.path.join(tmp, ".claude", "agents")
        os.makedirs(agents_dir, exist_ok=True)
        with open(os.path.join(agents_dir, "qa-visual.md"), "w", encoding="utf-8") as fh:
            fh.write("---\nmodel: sonnet\n---\nInspect screenshots carefully.")
        qa_cfg = gw.load_role("qa-visual", workspace=tmp)
        self.assertIn("Inspect screenshots", qa_cfg.get("prompt", ""))

        # Separate sessions per (cli, role)
        gw.save_role_session("grok", "architect", "sid-arch-1", workspace=tmp)
        gw.save_role_session("grok", "coder", "sid-coder-2", workspace=tmp)
        self.assertEqual(gw.get_role_session("grok", "architect", workspace=tmp), "sid-arch-1")
        self.assertEqual(gw.get_role_session("grok", "coder", workspace=tmp), "sid-coder-2")

        # Same CLI with different role is NOT blocked as a cycle; same (cli, role) IS blocked
        os.environ["MCP_AGENTS_CHAIN"] = "grok:architect"
        try:
            r_same = gw.run_cli("grok", "hi", role="architect", workspace=tmp, fallback=False)
            self.assertFalse(r_same["ok"])
            self.assertIn("Cycle", r_same["error"])
        finally:
            os.environ.pop("MCP_AGENTS_CHAIN", None)

    def test_rtk_rewrite_and_prompt_hook(self):
        rw = rtk.rewrite_cmd("dotnet test server/ && git diff --stat && echo ok > out.txt")
        self.assertIn("rtk dotnet test server/", rw)
        self.assertIn("rtk git diff --stat", rw)
        self.assertIn("echo ok > out.txt", rw)
        self.assertNotIn("rtk echo", rw)

        tmp = tempfile.mkdtemp(prefix="mcp_hook_")
        hook_dir = os.path.join(tmp, ".mcp-agents")
        os.makedirs(hook_dir, exist_ok=True)
        with open(os.path.join(hook_dir, "prompt_hook.py"), "w", encoding="utf-8") as fh:
            fh.write('import json, sys; _ = sys.stdin.read(); print(json.dumps({"hookSpecificOutput": {"additionalContext": "★ JEV: use skill X"}}))')
        ctx = gw._run_prompt_hook("fix bug", workspace=tmp)
        self.assertIn("★ JEV: use skill X", ctx)


if __name__ == "__main__":
    unittest.main()
