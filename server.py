"""Lean plug-and-play MCP server for @PKT handoffs and multi-CLI orchestration."""
from __future__ import annotations

import json
import os
import sys

# Ensure local imports work regardless of caller cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.mcpserver import MCPServer

from cli_gateway import list_clis, run_cli
from pkt_core import PktValidationError, default_store_path, encode_packet, load_pkt_refs, resolve_pkt_ref
from rtk_exec import run_rtk_cmd

_INSTRUCTIONS = (
    "Use `agent_run` to delegate to another CLI or role (pass `pkt_ref` for context, `session_id` to resume). "
    "Use `pkt_save` after edits to create a compact @PKT handoff, and `pkt_get` only if a `ref=` needs expansion. "
    "Prefer `rtk_run` over raw shell for builds, diffs, grep, and logs."
)

mcp = MCPServer("mcp-agents", instructions=_INSTRUCTIONS)


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
        fallback=fallback,
    )
    return json.dumps(res, ensure_ascii=False)


@mcp.tool()
def pkt_save(
    id: str,
    touched_files: list[str] | None = None,
    interface_contracts: list[str] | None = None,
    handoff_why: str = "",
    handoff_next: str = "",
    workspace: str = ".",
    op: str = "HND",
    status: str = "doing",
    cli: str = "-",
    always_store: bool = True,
) -> str:
    """Validate and encode a @PKT handoff line, storing full payload in pkt_refs.json."""
    try:
        pkt = encode_packet(
            {
                "id": id,
                "status": status,
                "cli": cli,
                "touched_files": touched_files or [],
                "interface_contracts": interface_contracts or [],
                "handoff_why": handoff_why,
                "handoff_next": handoff_next,
            },
            op=op,
            workspace=workspace,
            always_store=always_store,
        )
        return pkt
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
