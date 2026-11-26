"""Multi-language contract extraction (tree-sitter) and its flagged regex fallback."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import lang_contracts as lc  # noqa: E402
import pkt_core as pkt  # noqa: E402

try:
    import tree_sitter_language_pack  # noqa: F401
    HAS_TS = True
except ImportError:
    HAS_TS = False


def contracts(src: str, lang: str, added=None) -> list[str]:
    decls = lc.extract_public_contracts(src.encode(), lang, added)
    assert decls is not None, f"no parser for {lang}"
    return [lc.format_contract("f", d, lang) for d in decls]


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@unittest.skipUnless(HAS_TS, "tree-sitter-language-pack not installed")
class TestLanguages(unittest.TestCase):
    """The 8 cases the line regex missed or that must keep working."""

    def test_go_method_with_receiver(self):
        out = contracts("package x\nfunc (s *Svc) Run(id string) error { return nil }\nfunc run() {}\n", "go")
        self.assertIn("f: `func (s *Svc) Run(id string) error`", out)
        self.assertFalse(any("run()" in c for c in out))  # lowercase = unexported

    def test_ts_class_method_and_privates(self):
        src = "export class Svc {\n  async cancel(id: string): Promise<void> {}\n  private x(): void {}\n  #y() {}\n}\nclass Hidden { a() {} }\n"
        out = contracts(src, "typescript")
        self.assertIn("f(Svc): `async cancel(id: string): Promise<void>`", out)
        self.assertFalse(any("x()" in c or "#y" in c or "Hidden" in c for c in out))

    def test_python_multiline_def(self):
        out = contracts("class Svc:\n    def cancelar(\n        self,\n        id: str,\n    ) -> bool:\n        return True\n    def _p(self): pass\n", "python")
        self.assertIn("f(Svc): `def cancelar(self, id: str) -> bool`", out)
        self.assertFalse(any("_p" in c for c in out))

    def test_java_public_and_interface(self):
        out = contracts("public class Svc {\n  public void cancel(String id) {}\n  private void p() {}\n}\ninterface I { void m(); }\n", "java")
        self.assertIn("f(Svc): `public void cancel(String id)`", out)
        self.assertIn("f(I): `void m()`", out)
        self.assertFalse(any(" p()" in c for c in out))

    def test_kotlin_fun(self):
        out = contracts("class Svc {\n  fun cancel(id: String) {}\n  private fun p() {}\n}\n", "kotlin")
        self.assertIn("f(Svc): `fun cancel(id: String)`", out)
        self.assertFalse(any("p()" in c for c in out))

    def test_csharp_multiline_and_property(self):
        src = "public class Svc {\n  public async Task<bool> Cancel(\n    string id,\n    int x) { return true; }\n  internal void I() {}\n  public int Hp { get; set; }\n}\n"
        out = contracts(src, "csharp")
        self.assertIn("f(Svc): `public async Task<bool> Cancel(string id, int x)`", out)
        self.assertIn("f(Svc): `public int Hp { get; set; }`", out)
        self.assertFalse(any("I()" in c for c in out))

    def test_rust_pub_fn(self):
        out = contracts("pub struct S;\nimpl S {\n  pub fn run(&self) -> bool { true }\n  fn p(&self) {}\n}\n", "rust")
        self.assertIn("f(S): `pub fn run(&self) -> bool`", out)
        self.assertFalse(any("fn p" in c for c in out))

    def test_gdscript_func_and_class_name(self):
        out = contracts("class_name Calc\nstatic func dobro(n: int) -> int:\n\treturn n*2\nfunc _ready():\n\tpass\n", "gdscript")
        self.assertIn("f(class_name Calc): `static func dobro(n: int) -> int`", out)
        self.assertFalse(any("_ready" in c for c in out))

    def test_only_added_signature_lines_count(self):
        src = "def kept(a):\n    pass\n\ndef changed(\n    a,\n    b,\n):\n    pass\n"
        # Only line 6 (`b,`) was added: the multi-line signature of `changed` intersects it.
        out = contracts(src, "python", added={6})
        self.assertEqual(out, ["f: `def changed(a, b)`"])

    def test_body_only_edit_is_not_a_contract(self):
        src = "def f(a):\n    x = 1\n    return x\n"
        self.assertEqual(contracts(src, "python", added={2}), [])

    def test_members_ranked_before_types(self):
        decls = lc.extract_public_contracts(b"export class Svc {\n  run(): void {}\n}\n", "typescript", None)
        ranked = lc.rank_contracts([("f", d) for d in decls])
        self.assertEqual(lc.format_contract("f", ranked[0][1], "typescript"), "f(Svc): `run(): void`")


class TestParseAddedLines(unittest.TestCase):
    def test_hunks(self):
        diff = "+++ b/a.py\n@@ -1,0 +2,3 @@\n+x\n@@ -9 +12 @@\n+y\n+++ b/b.go\n@@ -4,2 +4,0 @@\n"
        out = lc.parse_added_lines(diff)
        self.assertEqual(out["a.py"], {2, 3, 4, 12})
        self.assertEqual(out["b.go"], set())


@unittest.skipUnless(HAS_TS, "tree-sitter-language-pack not installed")
class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pkt_lang_")
        _git(self.tmp, "init", "-q")
        _git(self.tmp, "config", "user.email", "t@t")
        _git(self.tmp, "config", "user.name", "t")
        with open(os.path.join(self.tmp, "svc.ts"), "w", encoding="utf-8") as fh:
            fh.write("export class Svc {\n  run(): void {}\n}\n")
        _git(self.tmp, "add", ".")
        _git(self.tmp, "commit", "-qm", "init")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        lc._UNAVAILABLE.clear()

    def test_ts_method_added_to_existing_class(self):
        pkt.ensure_base_commit("ML-1", workspace=self.tmp)
        with open(os.path.join(self.tmp, "svc.ts"), "w", encoding="utf-8") as fh:
            fh.write("export class Svc {\n  run(): void {}\n  cancel(\n    id: string,\n  ): boolean { return true }\n}\n")
        pkt.record_task_owned_files("ML-1", ["svc.ts"], workspace=self.tmp)
        line = pkt.build_pkt_from_git("ML-1", workspace=self.tmp, cli="t")
        self.assertIn("svc.ts(Svc): `cancel(id: string): boolean`", line)
        self.assertNotIn("run()", line)  # unchanged member
        self.assertNotIn("(?)", line)

    def test_missing_parser_falls_back_with_flag(self):
        pkt.ensure_base_commit("ML-2", workspace=self.tmp)
        with open(os.path.join(self.tmp, "Svc.java"), "w", encoding="utf-8") as fh:
            fh.write("public class Svc {\n  public void cancel(String id) {}\n}\n")
        pkt.record_task_owned_files("ML-2", ["Svc.java"], workspace=self.tmp)
        lc._UNAVAILABLE.add("java")
        lc._PARSERS.pop("java", None)
        line = pkt.build_pkt_from_git("ML-2", workspace=self.tmp, cli="t")
        self.assertIn("(?)", line)  # regex fallback is never presented as exact
        self.assertNotIn("PARTIAL_DIFF", line)  # the file list itself is still exact

    def test_skeleton_multilang(self):
        with open(os.path.join(self.tmp, "m.go"), "w", encoding="utf-8") as fh:
            fh.write("package m\n\nfunc (s *S) Run() {}\n")
        sk = pkt.file_skeleton("m.go", workspace=self.tmp)
        self.assertIn("L3:func (s *S) Run()", sk)


class TestExternalBase(unittest.TestCase):
    """pkt_save(base_commit="origin/main") for an external PR branch (e.g. Devin)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pkt_ext_")
        _git(self.tmp, "init", "-q", "-b", "main")
        _git(self.tmp, "config", "user.email", "t@t")
        _git(self.tmp, "config", "user.name", "t")
        with open(os.path.join(self.tmp, "base.py"), "w", encoding="utf-8") as fh:
            fh.write("x = 1\n")
        _git(self.tmp, "add", ".")
        _git(self.tmp, "commit", "-qm", "init")
        _git(self.tmp, "checkout", "-qb", "feat")
        with open(os.path.join(self.tmp, "feat.py"), "w", encoding="utf-8") as fh:
            fh.write("def feature():\n    pass\n")
        _git(self.tmp, "add", ".")
        _git(self.tmp, "commit", "-qm", "feat")
        _git(self.tmp, "checkout", "-q", "main")
        with open(os.path.join(self.tmp, "main_only.py"), "w", encoding="utf-8") as fh:
            fh.write("def outra_coisa():\n    pass\n")
        _git(self.tmp, "add", ".")
        _git(self.tmp, "commit", "-qm", "main moved on")
        _git(self.tmp, "checkout", "-q", "feat")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_target_commits_after_fork_are_excluded(self):
        line = pkt.build_pkt_from_git("PR-1", workspace=self.tmp, base_commit="main", cli="devin")
        self.assertIn("f=feat.py|", line)
        self.assertNotIn("main_only", line)
        self.assertNotIn("outra_coisa", line)
        self.assertNotIn("PARTIAL_DIFF", line)

    def test_stray_worktree_file_still_flags(self):
        with open(os.path.join(self.tmp, "solto.py"), "w", encoding="utf-8") as fh:
            fh.write("def solto():\n    pass\n")
        line = pkt.build_pkt_from_git("PR-2", workspace=self.tmp, base_commit="main", cli="devin")
        self.assertIn("PARTIAL_DIFF", line)


if __name__ == "__main__":
    unittest.main()
