"""Unit and Git-integration tests for standalone @PKT protocol core."""
from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pkt_core as pkt  # noqa: E402


def _git(cwd: str, *args: str) -> None:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr}")


def _init_repo(tmp: str) -> None:
    _git(tmp, "init")
    _git(tmp, "config", "user.email", "test@example.com")
    _git(tmp, "config", "user.name", "Test")


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
        for _ in range(1500):
            n, lim = rng.randint(0, 600), rng.randint(0, 300)
            s = "".join(rng.choice("ab cd\n\t") for _ in range(n))
            self.assertLessEqual(len(pkt.smart_truncate(s, lim)), lim)


class TestPktEncodingAndStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mcp_pkt_")
        self.store = os.path.join(self.tmp, "pkt_refs.json")

    def test_ref_emitted_only_when_truncated(self):
        pure = pkt.encode_packet(
            {
                "id": "T-1",
                "status": "doing",
                "cli": "grok",
                "touched_files": ["a.py", "b.py", "c.py", "d.py"],
                "interface_contracts": ["1", "2", "3"],
                "handoff_why": "w" * 90,
                "handoff_next": "n" * 140,
            },
            workspace=self.tmp,
            store_path=self.store,
        )
        self.assertNotIn("|ref=", pure)

        over = pkt.encode_packet(
            {"id": "T-1", "touched_files": ["a.py", "b.py", "c.py", "d.py", "e.py"]},
            workspace=self.tmp,
            store_path=self.store,
        )
        self.assertIn("(+1)", over)
        self.assertIn("|ref=T-1#", over)

    def test_validation_error_on_bad_types(self):
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
        ref = p1.split("|ref=")[1]
        loaded = pkt.load_pkt_refs(self.store)
        self.assertEqual(loaded[ref]["contracts"][0], "public int Hp { get; set; }")

    def test_spill_merge_on_load(self):
        spill = self.store + ".spill.jsonl"
        with open(spill, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"ref": "T-3#abcd1234", "payload": {"files": ["a.py"], "nxt": "go"}}) + "\n")
        loaded = pkt.load_pkt_refs(self.store)
        self.assertEqual(loaded["T-3#abcd1234"]["nxt"], "go")

    def test_concurrent_locks_same_actor_distinct_invocation_tokens(self):
        ok1, _ = pkt.acquire_locks("grok:coder:aaaa1111", ["src/a.py"], workspace=self.tmp, cli="grok:coder")
        self.assertTrue(ok1)
        ok2, c2 = pkt.acquire_locks("grok:coder:bbbb2222", ["src/a.py"], workspace=self.tmp, cli="grok:coder")
        self.assertFalse(ok2)
        self.assertEqual(c2[0]["cli"], "grok:coder")
        pkt.release_locks("grok:coder:aaaa1111", workspace=self.tmp)


class TestGitFactExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mcp_git_")
        _init_repo(self.tmp)
        with open(os.path.join(self.tmp, "README.md"), "w", encoding="utf-8") as fh:
            fh.write("# init\n")
        _git(self.tmp, "add", ".")
        _git(self.tmp, "commit", "-m", "c1: init")

    def test_t18_t19_base_commit_claim_and_failover_inheritance(self):
        # Commit from an earlier unrelated card BEFORE claim
        with open(os.path.join(self.tmp, "OtherCard.cs"), "w", encoding="utf-8") as fh:
            fh.write("public class OtherCard {}\n")
        _git(self.tmp, "add", ".")
        _git(self.tmp, "commit", "-m", "c2: unrelated card")

        # Claim pins HEAD at c2 (T19: excludes OtherCard.cs!)
        base1 = pkt.ensure_base_commit("KB-19", workspace=self.tmp)
        self.assertEqual(base1, pkt.git_head_rev(self.tmp))

        # Worker 1 commits partial work, then fails over to Worker 2
        with open(os.path.join(self.tmp, "Combat.cs"), "w", encoding="utf-8") as fh:
            fh.write("public class Combat {\n    public int Hp { get; set; }\n}\n")
        _git(self.tmp, "add", ".")
        _git(self.tmp, "commit", "-m", "c3: partial work by codex")

        # Failover claim MUST preserve base1 (T18)
        base2 = pkt.ensure_base_commit("KB-19", workspace=self.tmp)
        self.assertEqual(base2, base1)

        # Worker 2 adds GDScript & Python files (uncommitted)
        with open(os.path.join(self.tmp, "Player.gd"), "w", encoding="utf-8") as fh:
            fh.write("@export var speed: int = 5\nfunc _ready():\n    pass\nfunc apply_stun(d: int):\n    pass\n")

        line = pkt.build_pkt_from_git("KB-19", workspace=self.tmp, cli="claude", handoff_why="stun", handoff_next="wire hud")
        self.assertNotIn("OtherCard.cs", line)
        self.assertNotIn(".mcp-agents", line)
        self.assertIn("f=Combat.cs,Player.gd", line)
        self.assertIn("@export var speed", line)
        self.assertIn("apply_stun", line)
        self.assertNotIn("_ready", line)
        self.assertNotIn("PARTIAL_DIFF", line)
        self.assertNotIn("(?)", line)
        self.assertIn("[CODE,API,PUB]", line)
        # 4 public contracts -> 3 inline + (+1) + recoverable ref= containing `public int Hp { get; set; }`
        self.assertIn(";(+1)|", line)
        ref = line.split("|ref=")[1]
        resolved = pkt.resolve_pkt_ref(ref, workspace=self.tmp)
        self.assertTrue(any("public int Hp { get; set; }" in c for c in resolved["contracts"]))

    def test_partial_diff_flagged_without_valid_base_commit(self):
        with open(os.path.join(self.tmp, "mod.py"), "w", encoding="utf-8") as fh:
            fh.write("def compute_tax(x: float):\n    return x\n")
        # No ensure_base_commit called -> heuristic diff MUST set PARTIAL_DIFF and (?)
        line = pkt.build_pkt_from_git("UNCLAIMED-1", workspace=self.tmp, cli="grok")
        self.assertIn("PARTIAL_DIFF", line)
        self.assertIn("(?)", line)
        self.assertIn("compute_tax", line)

        # Invalid/rebased commit hash also triggers PARTIAL_DIFF
        pkt.save_task_state("REBASED-1", {"base_commit": "deadbeef" * 5}, workspace=self.tmp)
        line2 = pkt.build_pkt_from_git("REBASED-1", workspace=self.tmp, cli="grok")
        self.assertIn("PARTIAL_DIFF", line2)
        self.assertIn("(?)", line2)

    def test_already_dirty_file_reedited_is_detected(self):
        dirty_file = os.path.join(self.tmp, "dirty.py")
        untouched_dirty = os.path.join(self.tmp, "untouched.py")
        with open(dirty_file, "w", encoding="utf-8") as fh:
            fh.write("x = 1\n")
        with open(untouched_dirty, "w", encoding="utf-8") as fh:
            fh.write("y = 1\n")

        snap_before = pkt.snapshot_worktree(self.tmp)
        # Re-edit only dirty.py
        with open(dirty_file, "w", encoding="utf-8") as fh:
            fh.write("x = 2\n")
        snap_after = pkt.snapshot_worktree(self.tmp)

        changed = pkt.diff_worktree_snapshots(self.tmp, snap_before, snap_after)
        self.assertEqual(changed, ["dirty.py"])

    def test_bit_code_touched_requires_real_change_and_existing_file(self):
        # README.md exists on disk and is clean -> CODE bit must be 0
        bits_clean = pkt.compute_bits({"touched_files": ["README.md"]}, workspace=self.tmp)
        self.assertEqual(bits_clean & pkt.BIT_CODE_TOUCHED, 0)

        # Modify README.md -> CODE bit becomes 1
        with open(os.path.join(self.tmp, "README.md"), "a", encoding="utf-8") as fh:
            fh.write("more\n")
        bits_dirty = pkt.compute_bits({"touched_files": ["README.md"]}, workspace=self.tmp)
        self.assertNotEqual(bits_dirty & pkt.BIT_CODE_TOUCHED, 0)

        # Ghost file (deleted) -> CODE bit is 0 and skeleton is empty
        os.remove(os.path.join(self.tmp, "README.md"))
        bits_deleted = pkt.compute_bits({"touched_files": ["README.md"], "git_verified": True}, workspace=self.tmp)
        self.assertEqual(bits_deleted & pkt.BIT_CODE_TOUCHED, 0)
        self.assertEqual(pkt.file_skeleton("missing.py", workspace=self.tmp), "")


if __name__ == "__main__":
    unittest.main()
