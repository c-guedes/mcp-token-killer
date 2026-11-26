"""Lean RTK command rewriter & executor for token-compact shell output."""
from __future__ import annotations

import os
import re
import shutil
import subprocess

from pkt_core import smart_truncate

_SEG_UNSAFE = re.compile(r"\$\(|`|<<|>")
_STDERR_REDIR = re.compile(r"\s*2>(?:&1|/dev/null)")
_ENV_PREFIX = re.compile(r"^((?:[A-Za-z_][A-Za-z0-9_]*=(?:\"[^\"]*\"|'[^']*'|[^\s]+)\s+)+)(.+)$")
_SIMPLE_PREFIXES = (
    "dotnet build", "dotnet test", "dotnet publish",
    "git diff", "grep -", "ls -", "wc -l", "psql ",
)


def _has_rtk() -> bool:
    return bool(shutil.which("rtk"))


def rtk_rewrite_segment(seg: str) -> str:
    """Rewrites a single shell segment through RTK rules or `rtk rewrite`."""
    stripped = seg.strip()
    if not stripped or _SEG_UNSAFE.search(_STDERR_REDIR.sub("", stripped)) or stripped.startswith("rtk "):
        return seg
    m_env = _ENV_PREFIX.match(stripped)
    if m_env:
        env_part, rest = m_env.group(1), m_env.group(2)
        rw = rtk_rewrite_segment(rest)
        return (env_part + rw) if rw != rest else seg
    low = stripped.lower()
    for prefix in _SIMPLE_PREFIXES:
        if low.startswith(prefix):
            return "rtk " + stripped
    m_head = re.match(r"^head\s+-(c|n)\s*(\d+)\s+([\"']?[^|;>\s]+[\"']?)$", stripped, re.IGNORECASE)
    if m_head:
        if m_head.group(1).lower() == "c":
            return seg
        return f"rtk read {m_head.group(3)} --head-lines {m_head.group(2)}"
    if not _has_rtk():
        return seg
    try:
        r = subprocess.run(["rtk", "rewrite", stripped], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=4)
        out = r.stdout.strip()
        return out if r.returncode in (0, 3) and out else seg
    except Exception:
        return seg


def split_top(cmd: str) -> list[str]:
    """Splits `cmd` on `&&`, `||`, `;` outside quotes and `$(...)`."""
    out, buf, i, q, depth = [], "", 0, None, 0
    while i < len(cmd):
        c = cmd[i]
        if q:
            q = None if c == q else q
        elif c in "\"'":
            q = c
        elif cmd.startswith("$(", i):
            depth += 1
        elif c == ")" and depth:
            depth -= 1
        elif not depth and cmd[i:i + 2] in ("&&", "||"):
            out += [buf, cmd[i:i + 2]]
            buf, i = "", i + 2
            continue
        elif not depth and (c == ";" or (c == "\n" and not buf.endswith("\\"))):
            out += [buf, ";"]
            buf, i = "", i + 1
            continue
        buf += c
        i += 1
    return out + [buf]


def rewrite_cmd(cmd: str) -> str:
    """Rewrites each safe segment of `cmd` to use `rtk`."""
    if not cmd or "<<" in cmd:
        return cmd
    parts = split_top(cmd)
    out = []
    for i, part in enumerate(parts):
        if i % 2 == 1:
            out.append(part)
        else:
            out.append(rtk_rewrite_segment(part))
    return "".join(out)


def run_rtk_cmd(cmd: str, workspace: str = ".", timeout: int = 60) -> dict:
    """Rewrites `cmd` with RTK and executes it in `workspace`."""
    rewritten = rewrite_cmd(cmd)
    ws = os.path.abspath(workspace or ".")
    try:
        proc = subprocess.run(
            rewritten,
            cwd=ws,
            shell=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        combined = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()
        return {
            "ok": proc.returncode == 0,
            "rc": proc.returncode,
            "cmd": rewritten,
            "output": smart_truncate(combined, 8000),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": 124, "cmd": rewritten, "error": f"timed out after {timeout}s"}
    except Exception as exc:
        return {"ok": False, "rc": 1, "cmd": rewritten, "error": str(exc)}
