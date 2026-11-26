"""mcp-token-killer: Git-backed @PKT handoffs and multi-CLI orchestration over MCP."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.mcpserver import MCPServer

from cli_gateway import list_clis, run_cli
from pkt_core import (
    PktValidationError,
    build_pkt_from_git,
    default_store_path,
    ensure_base_commit,
    load_pkt_refs,
    resolve_pkt_ref,
)
from rtk_exec import run_rtk_cmd

_INSTRUCTIONS = (
    "Use `agent_run` to delegate to another CLI or role (`pkt_ref` for context, `session_id` to resume; "
    "in `work` mode it records `base_commit` and returns a Git-extracted `pkt`). "
    "Use `pkt_save` to attach `handoff_why`/`handoff_next` (and optional `qa_status`) onto Git-extracted facts; "
    "use `pkt_get` only when a `ref=` needs expansion. Prefer `rtk_run` for builds, diffs, grep, and logs."
)

mcp = MCPServer("mcp-token-killer", instructions=_INSTRUCTIONS)


@mcp.tool()
def agent_run(
    cli: str,
    prompt: str = "",
    workspace: str = ".",
    pkt_ref: str = "",
    session_id: str = "",
    mode: str = "read",
    model: str = "",
    role: str = "",
    task_id: str = "",
    fallback: bool = True,
) -> str:
    """Run/resume a CLI agent (grok|codex|claude|gemini|opencode|agy) with optional role & @PKT, or cli='status'."""
    if cli == "status":
        return json.dumps(list_clis(), ensure_ascii=False)
    if not prompt.strip():
        return json.dumps({"ok": False, "error": "prompt is required"}, ensure_ascii=False)
    res = run_cli(
        cli=cli,
        prompt=prompt,
        workspace=workspace,
        pkt_ref=pkt_ref,
        session_id=session_id,
        mode=mode,
        model=model,
        role=role,
        task_id=task_id,
        fallback=fallback,
    )
    return json.dumps(res, ensure_ascii=False)


@mcp.tool()
def pkt_save(
    id: str,
    handoff_why: str = "",
    handoff_next: str = "",
    workspace: str = ".",
    op: str = "HND",
    status: str = "doing",
    cli: str = "-",
    qa_status: str = "",
    claim: bool = False,
) -> str:
    """Build a @PKT line from real Git diff (`f=` and `api=` extracted from Git, never LLM-invented).

    Pass `claim=True` before starting work on `id` to pin `base_commit` to current HEAD.
    """
    try:
        if claim:
            ensure_base_commit(id, workspace=workspace)
        return build_pkt_from_git(
            task_id=id,
            workspace=workspace,
            handoff_why=handoff_why,
            handoff_next=handoff_next,
            op=op,
            status=status,
            cli=cli,
            qa_status=qa_status,
        )
    except PktValidationError as exc:
        return f"@PKT|{id}|{status}|{cli}|[INVALID]|op=ERR|why={exc}"


@mcp.tool()
def pkt_get(ref: str = "", workspace: str = ".", limit: int = 15) -> str:
    """Resolve a `ref=<id>#<sha8>` payload, or list recent refs when `ref` is empty."""
    if ref.strip():
        payload = resolve_pkt_ref(ref.strip(), workspace=workspace)
        if payload is None:
            return json.dumps({"ok": False, "error": f"ref not found: {ref}"}, ensure_ascii=False)
        return json.dumps({"ok": True, "ref": ref.strip(), "payload": payload}, ensure_ascii=False)

    refs = load_pkt_refs(default_store_path(workspace))
    keys = list(refs.keys())[-max(1, min(limit, 50)):]
    summary = {k: {"files": len(refs[k].get("files") or []), "nxt": (refs[k].get("nxt") or "")[:80]} for k in keys}
    return json.dumps({"ok": True, "count": len(refs), "recent": summary}, ensure_ascii=False)


@mcp.tool()
def rtk_run(cmd: str, workspace: str = ".", timeout: int = 60) -> str:
    """Run a shell command automatically rewritten through RTK for token-compact output."""
    return json.dumps(run_rtk_cmd(cmd=cmd, workspace=workspace, timeout=timeout), ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="stdio")
