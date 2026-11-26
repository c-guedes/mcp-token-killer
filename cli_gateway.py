"""Lean multi-CLI gateway with Windows wrapper resolution, session resume, security guards, and Git-backed @PKT."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

from pkt_core import (
    acquire_locks,
    build_pkt_from_git,
    diff_worktree_snapshots,
    ensure_base_commit,
    file_skeleton,
    get_recent_deltas,
    is_git_repo,
    pkt_safe_id,
    record_deltas,
    record_task_owned_files,
    release_locks,
    resolve_pkt_ref,
    smart_truncate,
    snapshot_worktree,
)

MAX_DEPTH = 2
DEFAULT_TIMEOUT = 300
DEFAULT_CHAIN = ("grok", "codex", "opencode", "claude", "gemini", "agy")

_NPM_JS_TARGETS = {
    "grok": os.path.join("node_modules", "@xai-official", "grok", "bin", "grok"),
    "codex": os.path.join("node_modules", "@openai", "codex", "bin", "codex.js"),
    "gemini": os.path.join("node_modules", "@google", "gemini-cli", "dist", "index.js"),
}

_LIMIT_PATTERNS = (
    "rate limit", "rate_limit", "quota", "too many requests", "429", "402",
    "credit balance", "balance exhausted", "usage limit", "hit your limit", "overloaded",
)

_COOLDOWNS: dict[str, float] = {}

# Signals that a CLI is unusable because of its login, not because the task failed.
_AUTH_PATTERNS = (
    "failed to authenticate", "not logged in", "not authenticated", "please log in", "please login",
    "login required", "unauthorized", "invalid api key", "invalid_api_key", "api key not",
    "session expired", "token expired", "oauth", "authentication failed", "authentication_error",
)
LOGIN_PROBE_PROMPT = "Responda apenas a palavra: ok"
LOGIN_TTL_S = 900
LOGIN_PROBE_TIMEOUT = 60
# cli -> {"login": ok|auth_error|rate_limited|timeout|error, "ts": epoch, "detail": str}
_LOGIN_STATE: dict[str, dict] = {}


def allowed_clis() -> tuple[str, ...]:
    """CLIs this gateway may run, in fallback order.

    `MCP_AGENTS_ALLOWED=claude,codex` restricts both direct calls and fallback (e.g. only the
    vendors approved in a corporate environment). Unknown names are ignored. Unset = all supported.
    """
    raw = os.environ.get("MCP_AGENTS_ALLOWED", "").strip()
    if not raw:
        return DEFAULT_CHAIN
    wanted = [c.strip().lower() for c in raw.split(",") if c.strip()]
    return tuple(c for c in wanted if c in DEFAULT_CHAIN)


def is_installed(cli: str) -> bool:
    return bool(resolve_exe([_env_bin(cli)]))


def _login_state(cli: str) -> dict | None:
    st = _LOGIN_STATE.get(cli)
    if st and time.time() - float(st.get("ts") or 0) <= LOGIN_TTL_S:
        return st
    return None


def _is_auth_error(out: str, err: str, rc: int) -> bool:
    text = (out or "") + "\n" + (err or "")
    if rc == 0 and '"is_error": true' not in text and '"is_error":true' not in text:
        return False
    low = text.lower()
    return any(p in low for p in _AUTH_PATTERNS)
_RECENT_CALLS: dict[tuple[str, str], int] = {}


def _env_bin(cli: str) -> str:
    return os.environ.get(f"MCP_CLI_{cli.upper()}", "").strip() or cli


def resolve_exe(cmd: list[str]) -> list[str]:
    """Resolves cmd[0] to a native .exe or `node <script.js>` to bypass Windows 8191-char .cmd/.ps1 limits."""
    if not cmd:
        return cmd
    exe = shutil.which(cmd[0])
    if not exe:
        return []
    low = exe.lower()
    if low.endswith((".cmd", ".bat", ".ps1")):
        dp0 = os.path.dirname(exe)
        base = os.path.splitext(os.path.basename(exe))[0].lower()
        if base == "opencode":
            native = os.path.join(dp0, "node_modules", "opencode-ai", "bin", "opencode.exe")
            if os.path.exists(native):
                return [native] + cmd[1:]
        if base in _NPM_JS_TARGETS:
            target = os.path.join(dp0, _NPM_JS_TARGETS[base])
            node = os.path.join(dp0, "node.exe")
            if not os.path.exists(node):
                node = shutil.which("node") or ""
            if node and os.path.exists(target):
                return [node, target] + cmd[1:]
    return [exe] + cmd[1:]


def build_cmd(
    cli: str,
    prompt: str,
    workspace: str = ".",
    mode: str = "read",
    model: str = "",
    session_id: str = "",
) -> list[str]:
    """Builds the headless CLI command for read/work mode with optional session resume."""
    work = str(mode).lower() == "work"
    bin_name = _env_bin(cli)
    ws = os.path.abspath(workspace or ".")

    if cli == "grok":
        sock = os.path.join(tempfile.gettempdir(), f"grok_mcp_{uuid.uuid4().hex[:10]}.sock")
        cmd = [bin_name, "--leader-socket", sock, "--cwd", ws, "--output-format", "json", "--always-approve"]
        if not work:
            cmd += ["--disallowed-tools", "Edit,Write,MultiEdit,Bash,NotebookEdit"]
        if model:
            cmd += ["-m", model]
        if session_id:
            cmd += ["-r", session_id]
        cmd += ["-p", prompt]
        return cmd

    if cli == "codex":
        cmd = [bin_name, "exec", "--skip-git-repo-check"]
        if work:
            cmd.append("--dangerously-bypass-approvals-and-sandbox")
        else:
            cmd += ["-s", "read-only"]
        if model:
            cmd += ["-m", model]
        if session_id:
            cmd += ["resume", session_id, prompt]
        else:
            cmd.append(prompt)
        return cmd

    if cli == "claude":
        cmd = [bin_name, "-p", "--exclude-dynamic-system-prompt-sections", "--output-format", "json"]
        if work:
            cmd.append("--dangerously-skip-permissions")
        else:
            cmd += ["--tools", "Read,Grep,Glob", "--allowedTools", "Read,Grep,Glob"]
        if model:
            cmd += ["--model", model]
        if session_id:
            cmd += ["--resume", session_id]
        cmd += ["--", prompt]
        return cmd

    if cli == "gemini":
        cmd = [bin_name]
        if work:
            cmd.append("--yolo")
        if model:
            cmd += ["-m", model]
        if session_id:
            cmd += ["--resume", session_id]
        cmd += ["-p", prompt]
        return cmd

    if cli == "opencode":
        cmd = [bin_name, "run", "--format", "json"]
        if work:
            cmd.append("--auto")
        if model:
            cmd += ["-m", model]
        if session_id:
            cmd += ["-s", session_id]
        cmd.append(prompt)
        return cmd

    if cli == "agy":
        cmd = [bin_name]
        if work:
            cmd.append("--dangerously-skip-permissions")
        if model:
            cmd += ["--model", model]
        cmd += ["-p", prompt]
        return cmd

    raise ValueError(f"Unsupported CLI: {cli}. Supported: {', '.join(DEFAULT_CHAIN)}")


def probe_login(cli: str, timeout: int = LOGIN_PROBE_TIMEOUT) -> dict:
    """Runs a minimal headless prompt to check that `cli` is logged in and answering.

    Runs in an empty temporary directory, in read mode, with recursion disabled, so the probe
    neither reads the project nor calls other agents. Costs one tiny request per CLI.
    """
    import tempfile

    if cli not in allowed_clis():
        return {"login": "not_allowed"}
    raw_cmd = build_cmd(cli, LOGIN_PROBE_PROMPT, workspace=".", mode="read")
    cmd = resolve_exe(raw_cmd)
    if not cmd:
        return {"login": "not_installed"}
    env = dict(os.environ)
    env["MCP_AGENTS_DEPTH"] = str(MAX_DEPTH + 10)  # nested agent_run calls refuse immediately
    env["PYTHONIOENCODING"] = "utf-8"
    t0 = time.time()
    with tempfile.TemporaryDirectory(prefix="mcp_login_") as tmp:
        try:
            proc = subprocess.run(
                cmd, cwd=tmp, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                encoding="utf-8", errors="replace", env=env, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            res = {"login": "timeout", "detail": f"no answer in {timeout}s"}
        except Exception as exc:
            res = {"login": "error", "detail": smart_truncate(str(exc), 200)}
        else:
            text, _sid, _usage = _extract_json_response(proc.stdout)
            blob = (proc.stderr or "") + "\n" + (proc.stdout or "")
            if _is_auth_error(proc.stdout, proc.stderr, proc.returncode):
                res = {"login": "auth_error", "detail": smart_truncate(blob.strip(), 200)}
            elif _is_limit_error(proc.stdout, proc.stderr, proc.returncode):
                res = {"login": "rate_limited", "detail": smart_truncate(blob.strip(), 200)}
            elif proc.returncode == 0 and (text or "").strip():
                res = {"login": "ok", "answer": smart_truncate(text.strip(), 40)}
            else:
                res = {"login": "error", "detail": smart_truncate(blob.strip() or f"rc={proc.returncode}", 200)}
    res["secs"] = round(time.time() - t0, 1)
    _LOGIN_STATE[cli] = {"login": res["login"], "ts": time.time(), "detail": res.get("detail", "")}
    return res


def list_clis(check_login: bool = False) -> dict[str, dict]:
    """Allowed CLIs with install status, cooldown and (optionally probed) login state.

    `check_login=True` runs `probe_login` on every installed allowed CLI, in parallel.
    """
    now = time.time()
    allowed = allowed_clis()
    out: dict[str, dict] = {}
    for cli in allowed:
        resolved = resolve_exe([_env_bin(cli)])
        cd_until = _COOLDOWNS.get(cli, 0.0)
        out[cli] = {
            "available": bool(resolved),
            "path": resolved[0] if resolved else None,
            "cooldown_s": max(0, int(cd_until - now)),
        }
        st = _login_state(cli)
        if st:
            out[cli]["login"] = st["login"]
    if check_login:
        from concurrent.futures import ThreadPoolExecutor

        targets = [c for c in allowed if out[c]["available"]]
        with ThreadPoolExecutor(max_workers=max(1, min(4, len(targets)))) as pool:
            for c, res in zip(targets, pool.map(probe_login, targets)):
                out[c].update(res)
    excluded = [c for c in DEFAULT_CHAIN if c not in allowed]
    if excluded:
        out["_not_allowed"] = excluded  # type: ignore[assignment]
    return out


def _is_limit_error(out: str, err: str, rc: int) -> bool:
    if rc == 0:
        return False
    low = ((out or "") + "\n" + (err or "")).lower()
    return any(p in low for p in _LIMIT_PATTERNS)


def _extract_usage(obj: dict) -> dict:
    """Extracts normalized token/cost telemetry from Claude, Grok, or OpenCode JSON."""
    u = obj.get("usage")
    out: dict = {}
    if isinstance(u, dict):
        inp = int(u.get("input_tokens") or u.get("input") or 0)
        c_read = int(u.get("cache_read_input_tokens") or (u.get("cache") or {}).get("read") or 0)
        c_create = int(u.get("cache_creation_input_tokens") or (u.get("cache") or {}).get("write") or 0)
        out_tok = int(u.get("output_tokens") or u.get("output") or 0)
        # Note: Grok `input_tokens` does not include `cache_read_input_tokens`, Claude separates all 3
        out["input_tokens"] = inp + c_read + c_create
        out["cached_tokens"] = c_read
        out["output_tokens"] = out_tok
    if obj.get("num_turns") is not None:
        out["turns"] = int(obj["num_turns"])
    cost = obj.get("total_cost_usd")
    if cost is not None:
        out["cost_usd"] = round(float(cost), 6)
    return out


def _extract_json_response(raw: str) -> tuple[str, str, dict]:
    """Extracts `(text, session_id, usage_meta)` when a CLI outputs JSON or NDJSON."""
    s = (raw or "").strip()
    if not s:
        return "", "", {}
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            meta = _extract_usage(obj)
            if obj.get("is_error"):
                return "", str(obj.get("session_id") or obj.get("sessionId") or ""), meta
            txt = obj.get("result") or obj.get("response") or obj.get("text") or obj.get("content") or ""
            sid = obj.get("session_id") or obj.get("sessionId") or obj.get("sessionID") or ""
            if isinstance(txt, str) and txt:
                return txt, str(sid), meta
    except Exception:
        pass
    sid = ""
    parts = []
    meta: dict = {}
    for line in s.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            sid = str(obj.get("session_id") or obj.get("sessionId") or obj.get("sessionID") or sid)
            if obj.get("usage"):
                meta.update(_extract_usage(obj))
            if obj.get("type") == "result" and isinstance(obj.get("result"), str):
                return obj["result"], sid, meta
            part_obj = obj.get("part")
            if isinstance(part_obj, dict):
                if part_obj.get("tokens"):
                    tok = part_obj["tokens"]
                    meta["input_tokens"] = meta.get("input_tokens", 0) + int(tok.get("input") or 0) + int((tok.get("cache") or {}).get("read") or 0)
                    meta["cached_tokens"] = meta.get("cached_tokens", 0) + int((tok.get("cache") or {}).get("read") or 0)
                    meta["output_tokens"] = meta.get("output_tokens", 0) + int(tok.get("output") or 0)
                if part_obj.get("cost") is not None:
                    meta["cost_usd"] = round(meta.get("cost_usd", 0.0) + float(part_obj["cost"]), 6)
                if obj.get("type") == "text" and isinstance(part_obj.get("text"), str):
                    parts.append(part_obj["text"])
                    continue
            part = obj.get("text") or obj.get("delta") or ""
            if isinstance(part, str) and part:
                parts.append(part)
    return ("".join(parts) if parts else s), sid, meta


def _sessions_path(workspace: str = ".") -> str:
    return os.path.join(os.path.abspath(workspace or "."), ".mcp-agents", "sessions.json")


def get_role_session(cli: str, role: str, workspace: str = ".") -> str:
    if not role:
        return ""
    try:
        with open(_sessions_path(workspace), encoding="utf-8") as fh:
            data = json.load(fh)
            if isinstance(data, dict):
                return str(data.get(f"{cli}:{role}", "") or "")
    except Exception:
        pass
    return ""


def save_role_session(cli: str, role: str, session_id: str, workspace: str = ".") -> None:
    if not role or not session_id:
        return
    sp = _sessions_path(workspace)
    os.makedirs(os.path.dirname(sp), exist_ok=True)
    try:
        with open(sp, encoding="utf-8") as fh:
            data = json.load(fh)
            if not isinstance(data, dict):
                data = {}
    except Exception:
        data = {}
    data[f"{cli}:{role}"] = session_id
    tmp = f"{sp}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, sp)


def load_role(role: str, workspace: str = ".") -> dict:
    """Loads built-in role config; workspace roles require explicit opt-in `MCP_ALLOW_WORKSPACE_ROLES=1`."""
    r = (role or "").strip()
    if not r:
        return {}
    ws = os.path.abspath(workspace or ".")
    allow_ws_roles = os.environ.get("MCP_ALLOW_WORKSPACE_ROLES", "").strip() == "1"

    search_paths = []
    if allow_ws_roles:
        search_paths.append(os.path.join(ws, ".mcp-agents", "roles.json"))
    search_paths.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "roles.json"))

    for path in search_paths:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, dict) and r in data and isinstance(data[r], dict):
                    return dict(data[r])
        except Exception:
            pass

    if allow_ws_roles:
        md_path = os.path.join(ws, ".claude", "agents", f"{r}.md")
        if os.path.isfile(md_path):
            try:
                with open(md_path, encoding="utf-8") as fh:
                    txt = fh.read()
                if txt.startswith("---"):
                    _, _, body = txt.split("---", 2)
                    txt = body.strip()
                return {"prompt": smart_truncate(txt, 1500)}
            except Exception:
                pass
    return {"prompt": f"Role: {r}. Stay strictly within this role."}


def _run_prompt_hook(prompt: str, workspace: str, session_id: str = "") -> str:
    """Executes `<workspace>/.mcp-agents/prompt_hook.py` ONLY when `MCP_ALLOW_WORKSPACE_HOOKS=1`."""
    if os.environ.get("MCP_ALLOW_WORKSPACE_HOOKS", "").strip() != "1":
        return ""
    ws = os.path.abspath(workspace or ".")
    hp = os.path.join(ws, ".mcp-agents", "prompt_hook.py")
    if not os.path.isfile(hp):
        return ""
    try:
        r = subprocess.run(
            [sys.executable, hp],
            cwd=ws,
            input=json.dumps({"prompt": prompt, "session_id": session_id or "mcp_agents"}),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=6,
        )
        data = json.loads(r.stdout or "{}")
        ctx = ((data.get("hookSpecificOutput") or {}).get("additionalContext") or "").strip()
        if not ctx:
            return ""
        star_lines = [ln for ln in ctx.splitlines() if ln.lstrip().startswith("★")]
        return smart_truncate("\n".join(star_lines) if star_lines else ctx, 600)
    except Exception:
        return ""


def _extract_pkt_files(pkt_ref: str, workspace: str) -> list[str]:
    """Extracts target file paths from a @PKT string or resolved ref payload."""
    ref = (pkt_ref or "").strip()
    if not ref:
        return []
    m_ref = re.search(r"\|ref=([^\s|]+)", ref)
    key = m_ref.group(1) if m_ref else (ref if "#" in ref else "")
    if key:
        payload = resolve_pkt_ref(key, workspace=workspace)
        if payload and isinstance(payload.get("files"), list):
            return [str(f) for f in payload["files"] if str(f).strip()]
    m_f = re.search(r"\|f=([^|]+)", ref)
    if m_f:
        raw = m_f.group(1)
        return [x.strip() for x in raw.split(",") if x.strip() and not x.strip().startswith("(+") and x.strip() != "-"]
    return []


def _extract_pkt_id(pkt_ref: str) -> str:
    ref = (pkt_ref or "").strip()
    if ref.startswith("@PKT|"):
        parts = ref.split("|")
        if len(parts) >= 2 and parts[1].strip():
            return pkt_safe_id(parts[1])
    if "#" in ref and not ref.startswith("@"):
        return pkt_safe_id(ref.split("#", 1)[0])
    return ""


def build_envelope(
    prompt: str,
    workspace: str = ".",
    pkt_ref: str = "",
    depth: int = 0,
    max_depth: int = MAX_DEPTH,
    target_cli: str = "",
    role_prompt: str = "",
    hook_context: str = "",
    extra_warnings: list[str] | None = None,
) -> str:
    """Static-prefix-first envelope (prompt-cache friendly) with role, lazy @PKT, JIT RepoMap, and [DELTA]."""
    depth_note = " Final hop: do NOT delegate via agent_run; answer directly." if depth + 1 >= max_depth else ""
    blocks = [
        f"[POLICY depth={depth + 1}/{max_depth}] Trust @PKT `f=`/`api=` and [REPOMAP] directly without re-searching; for unknown symbols use graph before grep; prefer `rtk` for heavy shell output.{depth_note}"
    ]
    if role_prompt:
        blocks.append(f"[ROLE] {role_prompt}")
    if hook_context:
        blocks.append(f"[HOOK_CTX] {hook_context}")
    if pkt_ref:
        ref = pkt_ref.strip()
        if ref.startswith("@PKT|"):
            blocks.append(f"HANDOFF {ref}")
        else:
            payload = resolve_pkt_ref(ref, workspace=workspace)
            if payload:
                blocks.append(f"PKT_REF={ref}\n" + json.dumps(payload, ensure_ascii=False))
            else:
                blocks.append(f"PKT_REF={ref}")
        target_files = _extract_pkt_files(ref, workspace)
        skeletons = [s for s in (file_skeleton(f, workspace=workspace) for f in target_files[:4]) if s]
        if skeletons:
            blocks.append("[REPOMAP] " + " | ".join(skeletons))
        deltas = get_recent_deltas(target_files, workspace=workspace, exclude_cli=target_cli)
        if deltas:
            blocks.append("\n".join(deltas))
    if extra_warnings:
        blocks.append("\n".join(extra_warnings))
    blocks.append(prompt)
    return "\n\n".join(blocks)


def _git_diff_hunks(workspace: str, files: list[str]) -> dict[str, str]:
    """Extracts compact `@@ ... @@` line ranges for changed files in a git repo."""
    if not files or not is_git_repo(workspace):
        return {}
    out: dict[str, str] = {}
    for f in files[:10]:
        try:
            r = subprocess.run(["git", "diff", "-U0", "--", f], cwd=workspace, capture_output=True, text=True, timeout=4)
            hunks = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.startswith("@@")]
            out[f] = " | ".join(hunks[:4]) if hunks else "modified"
        except Exception:
            out[f] = "modified"
    return out


def _log_metric(
    workspace: str,
    cli: str,
    mode: str,
    ok: bool,
    secs: float,
    prompt_len: int,
    pkt_len: int,
    out_len: int,
    usage: dict | None = None,
) -> None:
    try:
        path = os.path.join(os.path.abspath(workspace or "."), ".mcp-agents", "metrics.jsonl")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "cli": cli,
            "mode": mode,
            "ok": ok,
            "secs": round(secs, 2),
            "prompt_chars": prompt_len,
            "pkt_chars": pkt_len,
            "out_chars": out_len,
        }
        if usage:
            rec.update(usage)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def run_cli(
    cli: str,
    prompt: str,
    workspace: str = ".",
    pkt_ref: str = "",
    session_id: str = "",
    mode: str = "read",
    model: str = "",
    role: str = "",
    task_id: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    fallback: bool = True,
) -> dict:
    """Executes a CLI headlessly. Never escalates `mode` via role; falls back ONLY on rate-limit errors."""
    ws = os.path.abspath(workspace or ".")
    role_cfg = load_role(role, workspace=ws) if role else {}

    # Security: NEVER allow a role to promote `read` -> `work`; a role may only restrict `work` -> `read`.
    requested_work = str(mode).lower() == "work"
    if requested_work and str(role_cfg.get("mode") or "").lower() == "read":
        eff_mode = "read"
    else:
        eff_mode = "work" if requested_work else "read"

    if role_cfg.get("model") and not model:
        model = str(role_cfg["model"])

    if cli not in allowed_clis():
        return {"ok": False, "cli": cli, "rc": 2,
                "error": f"'{cli}' is not allowed here (MCP_AGENTS_ALLOWED={','.join(allowed_clis()) or '-'})."}
    if not is_installed(cli):
        return {"ok": False, "cli": cli, "rc": 2, "error": f"'{_env_bin(cli)}' is not installed (not found in PATH)."}

    max_depth = int(os.environ.get("MCP_AGENTS_MAX_DEPTH", str(MAX_DEPTH)) or MAX_DEPTH)
    depth = int(os.environ.get("MCP_AGENTS_DEPTH", "0") or "0")
    if depth >= max_depth:
        return {"ok": False, "cli": cli, "rc": 3, "error": f"Max recursion depth ({max_depth}) reached. Synthesize and answer directly."}

    actor = f"{cli}:{role}" if role else cli
    chain_env = [c for c in os.environ.get("MCP_AGENTS_CHAIN", "").split(">") if c]
    if actor in chain_env:
        return {"ok": False, "cli": cli, "rc": 3, "error": f"Cycle blocked: {' > '.join(chain_env)} -> {actor}. Answer directly."}

    call_key = (actor, prompt[:200])
    if _RECENT_CALLS.get(call_key, 0) >= 3:
        return {"ok": False, "cli": cli, "rc": 3, "error": f"Circuit breaker: repeated identical call to {actor} (3x). Try a different approach."}
    _RECENT_CALLS[call_key] = _RECENT_CALLS.get(call_key, 0) + 1

    if session_id == "new":
        eff_sid = ""
    elif session_id:
        eff_sid = session_id
    elif role:
        eff_sid = get_role_session(cli, role, workspace=ws)
    else:
        eff_sid = ""

    work = eff_mode == "work"
    eff_task_id = pkt_safe_id(task_id) if task_id else (_extract_pkt_id(pkt_ref) or f"RUN-{int(time.time())}")
    if work:
        ensure_base_commit(eff_task_id, workspace=ws)

    # Unique per-invocation token so simultaneous runs of the same actor inside one server process still conflict
    lock_owner = f"{actor}:{uuid.uuid4().hex[:8]}"
    locked_files: list[str] = []
    warnings: list[str] = []
    had_lock_conflict = False
    if work and pkt_ref:
        locked_files = _extract_pkt_files(pkt_ref, ws)
        if locked_files:
            ok_lock, conflicts = acquire_locks(lock_owner, locked_files, workspace=ws, cli=actor)
            if not ok_lock:
                had_lock_conflict = True
                warnings.append("[CONCURRENT_EDIT] " + "; ".join(f"{c.get('file')} active by {c.get('cli')}" for c in conflicts))
                locked_files = []

    hook_ctx = _run_prompt_hook(prompt, workspace=ws, session_id=eff_sid)
    full_prompt = build_envelope(
        prompt,
        workspace=ws,
        pkt_ref=pkt_ref,
        depth=depth,
        max_depth=max_depth,
        target_cli=cli,
        role_prompt=str(role_cfg.get("prompt") or ""),
        hook_context=hook_ctx,
        extra_warnings=warnings,
    )
    pkt_len = len(pkt_ref or "")

    now = time.time()
    chain = [cli]
    if fallback and not eff_sid:
        # Fallback only to CLIs that are allowed, installed, not cooling down and not known to be logged out.
        for c in allowed_clis():
            cand_actor = f"{c}:{role}" if role else c
            st = _login_state(c)
            if (
                c != cli
                and cand_actor not in chain_env
                and _COOLDOWNS.get(c, 0.0) <= now
                and not (st and st["login"] == "auth_error")
                and is_installed(c)
            ):
                chain.append(c)

    env = dict(os.environ)
    env["MCP_AGENTS_DEPTH"] = str(depth + 1)
    env["PYTHONIOENCODING"] = "utf-8"

    last_err = ""
    try:
        for cand in chain:
            if _COOLDOWNS.get(cand, 0.0) > now and cand != cli:
                continue
            cand_actor = f"{cand}:{role}" if role else cand
            env["MCP_AGENTS_CHAIN"] = ">".join(chain_env + [cand_actor])
            raw_cmd = build_cmd(
                cand,
                full_prompt,
                workspace=ws,
                mode=eff_mode,
                model=model if cand == cli else "",
                session_id=eff_sid if cand == cli else "",
            )
            cmd = resolve_exe(raw_cmd)
            if not cmd:
                last_err = f"'{_env_bin(cand)}' not found in PATH"
                if cand == cli:
                    break
                continue  # a fallback candidate vanished from PATH: skip it, keep the chain

            snap_before = snapshot_worktree(ws) if work else {}
            t0 = time.time()
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=ws,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=env,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                _log_metric(ws, cand, eff_mode, False, time.time() - t0, len(full_prompt), pkt_len, 0)
                last_err = f"{cand} timed out after {timeout}s"
                break
            except Exception as exc:
                _log_metric(ws, cand, eff_mode, False, time.time() - t0, len(full_prompt), pkt_len, 0)
                last_err = f"{cand} failed: {exc}"
                break

            dur = time.time() - t0
            if _is_limit_error(proc.stdout, proc.stderr, proc.returncode):
                _COOLDOWNS[cand] = time.time() + 180
                _log_metric(ws, cand, eff_mode, False, dur, len(full_prompt), pkt_len, 0)
                last_err = smart_truncate(proc.stderr or proc.stdout or "rate limit", 400)
                if fallback and not eff_sid:
                    continue
                break

            if _is_auth_error(proc.stdout, proc.stderr, proc.returncode):
                # The CLI is unusable (login missing/expired), not the task: same nature as a rate limit.
                _LOGIN_STATE[cand] = {"login": "auth_error", "ts": time.time(),
                                      "detail": smart_truncate(proc.stderr or proc.stdout or "", 200)}
                _log_metric(ws, cand, eff_mode, False, dur, len(full_prompt), pkt_len, 0)
                last_err = f"{cand}: login missing or expired. " + smart_truncate(proc.stderr or proc.stdout or "", 300)
                if fallback and not eff_sid:
                    continue
                break

            text, out_sid, usage_meta = _extract_json_response(proc.stdout)
            snap_after = snapshot_worktree(ws) if work else {}
            changed = diff_worktree_snapshots(ws, snap_before, snap_after) if work else []
            if work and changed:
                record_deltas(cand_actor, _git_diff_hunks(ws, changed), workspace=ws)

            if proc.returncode == 0 and (text or changed):
                _LOGIN_STATE[cand] = {"login": "ok", "ts": time.time(), "detail": ""}
                _log_metric(ws, cand, eff_mode, True, dur, len(full_prompt), pkt_len, len(text), usage=usage_meta)
                final_sid = out_sid or (eff_sid if cand == cli else "")
                if role and final_sid:
                    save_role_session(cand, role, final_sid, workspace=ws)
                res = {
                    "ok": True,
                    "cli": cand,
                    "role": role,
                    "mode": eff_mode,
                    "rc": 0,
                    "session_id": final_sid,
                    "output": smart_truncate(text or "(files modified)", 8000),
                }
                if usage_meta:
                    res["usage"] = usage_meta
                if changed:
                    res["changed_files"] = changed
                if work:
                    record_task_owned_files(eff_task_id, changed, workspace=ws, lock_conflict=had_lock_conflict)
                    res["pkt"] = build_pkt_from_git(
                        task_id=eff_task_id,
                        workspace=ws,
                        cli=cand,
                        delegated=(cand != cli),
                        explicit_files=changed,
                        lock_owner=lock_owner,
                    )
                return res

            _log_metric(ws, cand, eff_mode, False, dur, len(full_prompt), pkt_len, len(text), usage=usage_meta)
            last_err = smart_truncate(proc.stderr or proc.stdout or f"rc={proc.returncode}", 400)
            # Never fall back on non-rate-limit failures!
            break
    finally:
        if locked_files:
            release_locks(lock_owner, workspace=ws, files=locked_files)

    return {"ok": False, "cli": cli, "rc": 1, "error": last_err or "CLI execution failed."}
