"""Registers `mcp-agents` globally across installed CLIs (grok, codex, claude, opencode)."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(ROOT, "server.py")
PY = sys.executable

sys.path.insert(0, ROOT)
from cli_gateway import resolve_exe  # noqa: E402


def _run(cmd: list[str]) -> tuple[bool, str]:
    resolved = resolve_exe(cmd)
    if not resolved:
        return False, "not in PATH"
    r = subprocess.run(resolved, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
    msg = (r.stdout or r.stderr or "").strip().splitlines()
    return r.returncode == 0, (msg[-1] if msg else f"rc={r.returncode}")


def register_claude_json() -> tuple[bool, str]:
    p = pathlib.Path.home() / ".claude.json"
    if not p.exists():
        return False, "missing ~/.claude.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    d.setdefault("mcpServers", {})["mcp-agents"] = {"type": "stdio", "command": PY, "args": [SERVER]}
    p.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
    return True, str(p)


def register_opencode_json() -> tuple[bool, str]:
    p = pathlib.Path.home() / ".config" / "opencode" / "opencode.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    d = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    d.setdefault("mcp", {})["mcp-agents"] = {"type": "local", "command": [PY, SERVER], "enabled": True}
    p.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
    return True, str(p)


def prefetch_grammars() -> None:
    """Downloads every grammar used by `lang_contracts` into the local tree-sitter cache."""
    from lang_contracts import EXT_LANG  # noqa: E402
    from tree_sitter_language_pack import download

    langs = sorted(set(EXT_LANG.values()))
    download(langs)
    print(f"grammars  -> OK ({', '.join(langs)})")


def main() -> None:
    if "--grammars" in sys.argv[1:]:
        prefetch_grammars()
        return
    results = {
        "grok": _run(["grok", "mcp", "add", "mcp-agents", "--", PY, SERVER]),
        "codex": _run(["codex", "mcp", "add", "mcp-agents", "--", PY, SERVER]),
        "claude": register_claude_json(),
        "opencode": register_opencode_json(),
    }
    for name, (ok, info) in results.items():
        print(f"{name:10s} -> {'OK' if ok else 'SKIP'} ({info})")


if __name__ == "__main__":
    main()
