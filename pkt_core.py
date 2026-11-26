"""Standalone @PKT (Micro-Packet / Zero Context Loss) protocol core.

Core invariant: facts (`touched_files`, `interface_contracts`, `diff_partial`) come
from Git, never from LLM prose; any loss or heuristic fallback is explicitly signaled.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time

from lang_contracts import (
    CODE_EXTS as _TS_CODE_EXTS,
    extract_declarations,
    extract_public_contracts,
    format_contract,
    rank_contracts,
    lang_for_path,
    parse_added_lines,
)

# 16-bit status flags (bitmask)
BIT_CODE_TOUCHED = 1 << 0
BIT_API_CHANGED = 1 << 1
BIT_QA_PASS = 1 << 4
BIT_QA_FAIL = 1 << 5
BIT_DELEGATED = 1 << 8
BIT_HAS_LOCK = 1 << 9
BIT_CONTRACT_PUB = 1 << 10
BIT_BREAKING = 1 << 11
BIT_DIFF_PARTIAL = 1 << 14  # 0x4000

_BIT_LABELS = (
    (BIT_CODE_TOUCHED, "CODE"),
    (BIT_API_CHANGED, "API"),
    (BIT_QA_PASS, "QA_PASS"),
    (BIT_QA_FAIL, "QA_FAIL"),
    (BIT_DELEGATED, "DELEG"),
    (BIT_HAS_LOCK, "LOCKED"),
    (BIT_CONTRACT_PUB, "PUB"),
    (BIT_BREAKING, "BREAK"),
    (BIT_DIFF_PARTIAL, "PARTIAL_DIFF"),
)

MICRO_OPS = ("ACK", "LCK", "PUB", "DEP", "BLK", "HND", "QAP", "QAF")

# Every extension with a tree-sitter grammar mapping; the regex below is only a flagged fallback.
_CODE_EXTS = tuple(dict.fromkeys(_TS_CODE_EXTS + (".gd", ".cs", ".py", ".ts", ".tsx", ".js", ".rs", ".go")))

# Legacy fallback: public contract signatures on `+` lines of `git diff -U0`,
# used only when no tree-sitter parser is available (result is flagged `(?)`).
# Private identifiers starting with `_` (`_ready`, `__init__`, `_helper`) are excluded.
CONTRACT_SIG_RE = re.compile(
    r"^\+\s*(?:static\s+|async\s+)*(?:"
    r"func\s+(?!_)[A-Za-z0-9_]+\s*\([^)]*\)|"
    r"signal\s+(?!_)[A-Za-z0-9_]+(?:\([^)]*\))?|"
    r"class_name\s+[A-Za-z0-9_]+|"
    r"const\s+(?!_)[A-Z0-9_]+\s*(?::\s*[A-Za-z0-9_\[\]]+\s*)?:?=|"
    r"@export(?:_[a-z_]+)?(?:\([^)]*\))?\s+var\s+(?!_)[A-Za-z0-9_]+|"
    r"def\s+(?!_)[A-Za-z0-9_]+\s*\([^)]*\)|"
    r"class\s+(?!_)[A-Za-z0-9_]+|"
    r"public\s+(?:static\s+)?(?:[A-Za-z0-9_<>,\[\]?]+|\([^)]*\))\s+(?!_)[A-Za-z0-9_]+\s*\{\s*get|"
    r"public\s+(?:static\s+|async\s+|virtual\s+|override\s+|sealed\s+|abstract\s+)*"
    r"(?:class|struct|record|enum|interface|(?:[A-Za-z0-9_<>,\[\]?]+|\([^)]*\))\s+(?!_)[A-Za-z0-9_]+\s*\()|"
    r"export\s+(?:default\s+)?(?:async\s+)?(?:function|class|interface|type|const)\s+(?!_)[A-Za-z0-9_]+|"
    r"pub\s+(?:async\s+)?(?:fn|struct|enum|trait|type)\s+(?!_)[A-Za-z0-9_]+"
    r")"
)

_SYM_DEF_RE = re.compile(
    r"^\s*(?:export\s+|pub\s+|public\s+)?(?:static\s+|async\s+|virtual\s+|override\s+)*"
    r"(?:func|def|class|class_name|signal|interface|struct|enum|trait|fn)\s+[A-Za-z0-9_]+"
)

_PKT_REFS_MAX = 2000
_LOCK_TTL_S = 1800
_PKT_REFS_LOCK = threading.Lock()
_SKELETON_CACHE: dict[tuple[str, float, int], str] = {}


class PktValidationError(ValueError):
    """Raised when handoff fields have invalid types before @PKT encoding."""


def pkt_safe_id(card_id) -> str:
    """Sanitizes an ID for @PKT and `ref=` keys (no `|`, `#`, or newlines)."""
    return re.sub(r"[\r\n|#]+", "_", str(card_id or "?")).strip() or "?"


def smart_truncate(text, limit: int) -> str:
    """Deterministic Head+Tail (55%/45%) cut with exact `...(+Nc)...` marker."""
    clean = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(clean) <= limit or limit <= 0:
        return clean[:limit] if limit > 0 else ""
    if limit <= 20:
        return clean[:limit]
    overhead_est = 12
    avail = max(4, limit - overhead_est)
    head = max(2, int(avail * 0.55))
    tail = max(2, avail - head)
    if head + tail >= len(clean):
        return clean[:limit]
    omitted = len(clean) - head - tail
    marker = f"...(+{omitted}c)..."
    total_len = head + len(marker) + tail
    if total_len > limit:
        diff = total_len - limit
        if tail >= diff + 2:
            tail -= diff
        elif head >= diff + 2:
            head -= diff
        omitted = len(clean) - head - tail
        marker = f"...(+{omitted}c)..."
    return clean[:head] + marker + (clean[-tail:] if tail > 0 else "")


def coerce_handoff(data: dict) -> dict:
    """Validates and normalizes the 4 handoff fields before encoding or storing."""
    cid = str(data.get("id") or "?")
    out = {}
    for key in ("touched_files", "interface_contracts"):
        v = data.get(key)
        if v is None or v == "":
            v = []
        if isinstance(v, (str, bytes, dict)) or not hasattr(v, "__iter__"):
            raise PktValidationError(f"{cid}: '{key}' must be a list of strings, got {type(v).__name__}")
        items = []
        for x in v:
            if isinstance(x, (list, dict, tuple, set)):
                raise PktValidationError(f"{cid}: item in '{key}' must be str, got {type(x).__name__}")
            s = str(x).strip()
            if s:
                items.append(s)
        out[key] = items
    for key in ("handoff_why", "handoff_next"):
        v = data.get(key)
        if v is None:
            v = ""
        if not isinstance(v, str):
            raise PktValidationError(f"{cid}: '{key}' must be str, got {type(v).__name__}")
        out[key] = v.strip()
    return out


# --- Git fact extraction & base_commit tracking ---

def is_git_repo(workspace: str) -> bool:
    ws = os.path.abspath(workspace or ".")
    if os.path.exists(os.path.join(ws, ".git")):
        return True
    try:
        r = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=ws, capture_output=True, text=True, timeout=4)
        return r.returncode == 0 and r.stdout.strip() == "true"
    except Exception:
        return False


def git_head_rev(workspace: str) -> str:
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=workspace, capture_output=True, text=True, timeout=4)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def git_commit_exists(workspace: str, rev: str) -> bool:
    if not rev:
        return False
    try:
        r = subprocess.run(["git", "cat-file", "-e", f"{rev}^{{commit}}"], cwd=workspace, capture_output=True, timeout=4)
        return r.returncode == 0
    except Exception:
        return False


def _tasks_path(workspace: str = ".") -> str:
    return os.path.join(os.path.abspath(workspace or "."), ".mcp-agents", "tasks.json")


def load_tasks(workspace: str = ".") -> dict:
    try:
        with open(_tasks_path(workspace), encoding="utf-8") as fh:
            d = json.load(fh)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_task_state(task_id: str, patch: dict, workspace: str = ".") -> dict:
    tid = pkt_safe_id(task_id)
    tp = _tasks_path(workspace)
    os.makedirs(os.path.dirname(tp), exist_ok=True)
    with _PKT_REFS_LOCK:
        tasks = load_tasks(workspace)
        cur = dict(tasks.get(tid) or {})
        cur.update(patch)
        tasks[tid] = cur
        tmp = f"{tp}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(tasks, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, tp)
        return cur


def ensure_base_commit(task_id: str, workspace: str = ".") -> str:
    """Records HEAD and pre-existing dirty/untracked `baseline_snap` on first claim; preserves across failovers."""
    if not task_id:
        return ""
    tid = pkt_safe_id(task_id)
    ws = os.path.abspath(workspace or ".")
    tasks = load_tasks(ws)
    cur = tasks.get(tid) or {}
    existing = str(cur.get("base_commit") or "").strip()
    if existing:
        return existing
    if not is_git_repo(ws):
        return ""
    rev = git_head_rev(ws)
    if rev:
        base_snap = snapshot_worktree(ws)
        base_snap.pop("__HEAD__", None)
        save_task_state(
            tid,
            {
                "base_commit": rev,
                "baseline_snap": base_snap,
                "owned_files": list(cur.get("owned_files") or []),
                "claimed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
            workspace=ws,
        )
    return rev


def record_task_owned_files(
    task_id: str,
    files: list[str],
    workspace: str = ".",
    lock_conflict: bool = False,
) -> None:
    """Records files proven changed during an `agent_run` window for `task_id`."""
    if not task_id:
        return
    tid = pkt_safe_id(task_id)
    ws = os.path.abspath(workspace or ".")
    tasks = load_tasks(ws)
    cur = tasks.get(tid) or {}
    owned = set(cur.get("owned_files") or [])
    for f in files or []:
        nf = str(f).replace("\\", "/").strip()
        if nf and not _is_internal_meta(nf):
            owned.add(nf)
    patch: dict = {"owned_files": sorted(owned)}
    if lock_conflict or cur.get("lock_conflict"):
        patch["lock_conflict"] = True
    save_task_state(tid, patch, workspace=ws)


def _is_internal_meta(rel_path: str) -> bool:
    norm = re.sub(r"^(?:\./)+", "", (rel_path or "").replace("\\", "/").strip())
    return norm == ".mcp-agents" or norm.startswith(".mcp-agents/")


def snapshot_worktree(workspace: str) -> dict[str, str]:
    """Captures content hashes of all dirty/untracked files + HEAD so re-edits of dirty files are caught."""
    ws = os.path.abspath(workspace or ".")
    snap: dict[str, str] = {}
    if not is_git_repo(ws):
        return snap
    snap["__HEAD__"] = git_head_rev(ws)
    try:
        r = subprocess.run(
            ["git", "status", "--porcelain", "-uall"],
            cwd=ws,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
        if r.returncode != 0:
            return snap
        for ln in r.stdout.splitlines():
            if len(ln) < 4:
                continue
            raw_path = ln[3:].strip()
            if " -> " in raw_path:
                raw_path = raw_path.split(" -> ", 1)[1].strip()
            rel = raw_path.strip('"')
            if _is_internal_meta(rel):
                continue
            full = os.path.join(ws, rel)
            if os.path.isfile(full):
                try:
                    with open(full, "rb") as fbin:
                        h = hashlib.sha256(fbin.read()).hexdigest()[:16]
                except OSError:
                    h = "unreadable"
                snap[rel] = h
            else:
                snap[rel] = "__DELETED__"
    except Exception:
        pass
    return snap


def diff_worktree_snapshots(workspace: str, before: dict[str, str], after: dict[str, str]) -> list[str]:
    """Returns files newly modified, re-modified (even if dirty before), deleted, or committed between snapshots."""
    ws = os.path.abspath(workspace or ".")
    changed: set[str] = set()
    head_b = before.get("__HEAD__", "")
    head_a = after.get("__HEAD__", "")
    if head_b and head_a and head_b != head_a and git_commit_exists(ws, head_b):
        try:
            r = subprocess.run(["git", "diff", "--name-only", head_b, head_a], cwd=ws, capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                changed.update(f.strip() for f in r.stdout.splitlines() if f.strip())
        except Exception:
            pass
    all_keys = (set(before.keys()) | set(after.keys())) - {"__HEAD__"}
    for k in all_keys:
        if before.get(k) != after.get(k):
            changed.add(k)
    return sorted(changed)


def _gd_class_name(workspace: str, rel_path: str) -> str:
    """Reads `class_name <Name>` from a GDScript file header if present on disk."""
    if not rel_path or not rel_path.lower().endswith(".gd"):
        return ""
    full = os.path.join(os.path.abspath(workspace or "."), rel_path)
    if not os.path.isfile(full):
        return ""
    try:
        with open(full, encoding="utf-8", errors="replace") as fh:
            for _ in range(30):
                ln = fh.readline()
                if not ln:
                    break
                m = re.match(r"^\s*class_name\s+([A-Za-z0-9_]+)", ln)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return ""


def extract_contracts_from_diff(diff_text: str, workspace: str = ".") -> list[str]:
    """Extracts public interface contracts from unified diff `+` lines via `CONTRACT_SIG_RE`."""
    contracts: list[str] = []
    cur_file = ""
    gd_cls_cache: dict[str, str] = {}
    for line in (diff_text or "").splitlines():
        if line.startswith("+++ b/"):
            cur_file = line[6:].strip()
            continue
        if line.startswith("+") and not line.startswith("+++") and CONTRACT_SIG_RE.search(line):
            clean = re.sub(r"\s+", " ", line[1:].strip()).rstrip("{:").strip()
            if clean.startswith("class_name "):
                continue  # Captured as file qualifier `file.gd(class_name X)` instead of consuming a contract slot
            if cur_file:
                base = os.path.basename(cur_file)
                if cur_file not in gd_cls_cache:
                    gd_cls_cache[cur_file] = _gd_class_name(workspace, cur_file)
                cls_name = gd_cls_cache[cur_file]
                qual = f"(class_name {cls_name})" if cls_name else ""
                prefix = f"{base}{qual}: "
            else:
                prefix = ""
            entry = f"{prefix}`{clean[:90]}`"
            if entry not in contracts:
                contracts.append(entry)
    return contracts


def _split_diff_by_file(diff_text: str) -> dict[str, str]:
    """Splits a (possibly synthesized) unified diff into per-file chunks keyed by `b/` path."""
    out: dict[str, list[str]] = {}
    cur = ""
    for line in (diff_text or "").splitlines():
        if line.startswith("+++ "):
            p = line[4:].strip()
            cur = p[2:] if p.startswith("b/") else p
            out.setdefault(cur, [])
        if cur:
            out[cur].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def _contracts_for_files(ws: str, code_files: list[str], added_by_file: dict, diff_text: str) -> tuple[list[str], bool]:
    """Public contracts per changed file via tree-sitter; regex fallback is flagged as partial.

    Returns (contracts, partial). `partial` is True when any file had to use the regex
    fallback (no grammar/parser), so the packet shows `(?)` instead of silently missing
    multi-line signatures, class methods or Go receivers.
    """
    found: list[tuple[str, dict, str]] = []
    fallback: list[str] = []
    partial = False
    chunks = None
    for cf in code_files:
        full = os.path.join(ws, cf)
        if not os.path.isfile(full) or cf not in added_by_file:
            continue
        lang = lang_for_path(cf)
        decls = None
        if lang:
            try:
                with open(full, "rb") as fh:
                    src = fh.read()
                decls = extract_public_contracts(src, lang, added_by_file[cf])
            except OSError:
                decls = None
        if decls is not None:
            found.extend((cf, d, lang) for d in decls)
            continue
        partial = True
        if chunks is None:
            chunks = _split_diff_by_file(diff_text)
        fallback.extend(extract_contracts_from_diff(chunks.get(cf, ""), workspace=ws))
    ranked = rank_contracts([(cf, d) for cf, d, _ in found])
    lang_of = {id(d): lang for _, d, lang in found}
    contracts: list[str] = []
    for cf, d in ranked:
        entry = format_contract(cf, d, lang_of[id(d)])
        if entry not in contracts:
            contracts.append(entry)
    for entry in fallback:
        if entry not in contracts:
            contracts.append(entry)
    return contracts, partial


def _active_foreign_locked_files(workspace: str, exclude_owner: str = "") -> set[str]:
    locks = _load_locks(_locks_path(workspace))
    out: set[str] = set()
    for f_norm, info in locks.items():
        owner = str(info.get("owner") or "")
        if not exclude_owner or owner != exclude_owner:
            out.add(f_norm)
    return out


def extract_git_facts(
    workspace: str = ".",
    task_id: str = "",
    base_commit: str = "",
    explicit_files: list[str] | None = None,
    lock_owner: str = "",
) -> dict:
    """Extracts `(touched_files, interface_contracts, diff_partial, git_verified)` from Git without silent over-inclusion.

    Invariants:
    1. Files already dirty/untracked at claim (`baseline_snap`) with unchanged hash are subtracted.
    2. When `explicit_files` or task `owned_files` (measured by `agent_run` snapshots) exist, `f=` comes from
       that exact set rather than sweeping unrelated working-tree files.
    3. Unmonitored uncommitted worktree files (e.g. standalone `pkt_save` where another process may have written
       to the shared worktree), pre-claim dirty files re-edited, or intersections with active foreign locks
       always set `diff_partial=True` (`PARTIAL_DIFF` + `(?)`).
    """
    ws = os.path.abspath(workspace or ".")
    if not is_git_repo(ws):
        return {"touched_files": [], "interface_contracts": [], "diff_partial": True, "git_verified": False}

    tasks = load_tasks(ws)
    tid = pkt_safe_id(task_id) if task_id else ""
    task_rec = (tasks.get(tid) or {}) if tid else {}

    raw_base = (base_commit or "").strip() or str(task_rec.get("base_commit") or "").strip()
    valid_base = raw_base if git_commit_exists(ws, raw_base) else ""
    if valid_base:
        # An external ref (`origin/main`, a PR target) may have moved on after the branch was cut.
        # Diffing against its tip would pull the target's newer commits into this task, marked as exact.
        # `merge-base` returns the fork point; for a base recorded at claim (an ancestor of HEAD) it is a no-op.
        try:
            r_mb = subprocess.run(["git", "merge-base", valid_base, "HEAD"], cwd=ws, capture_output=True, text=True, timeout=5)
            mb = (r_mb.stdout or "").strip()
            valid_base = mb if r_mb.returncode == 0 and mb else ""
        except Exception:
            valid_base = ""
    has_baseline = "baseline_snap" in task_rec
    baseline_snap: dict[str, str] = dict(task_rec.get("baseline_snap") or {})
    owned_files: set[str] = {str(f).replace("\\", "/") for f in (task_rec.get("owned_files") or []) if f}

    external_base = bool((base_commit or "").strip())
    # Without a claim, a task's scope is unknown -> partial. An explicit external base (PR branch) is the
    # exception: committed changes since the fork point are exact; stray worktree files still flag below.
    diff_partial = (not bool(valid_base)) or (bool(tid) and not has_baseline and explicit_files is None and not external_base)

    snap_now = snapshot_worktree(ws)
    snap_now.pop("__HEAD__", None)

    # Subtract pre-claim dirty/untracked files whose content hash has NOT changed since claim
    post_claim_worktree: set[str] = {
        f.replace("\\", "/") for f, h in snap_now.items() if baseline_snap.get(f) != h
    }

    # Files owned by OTHER tasks in `.mcp-agents/tasks.json`
    other_task_owned: set[str] = set()
    for other_id, other_rec in tasks.items():
        if other_id != tid and isinstance(other_rec, dict):
            for f in other_rec.get("owned_files") or []:
                other_task_owned.add(_norm_path(f))

    has_observed_scope = explicit_files is not None or bool(owned_files)
    if has_observed_scope:
        # `agent_run` path (or `pkt_save` after `agent_run`): use exact observed file set, never sweep worktree!
        touched: set[str] = set(owned_files)
        for f in explicit_files or []:
            nf = str(f).replace("\\", "/").strip()
            if nf and not _is_internal_meta(nf):
                touched.add(nf)
    elif valid_base:
        # Standalone `pkt_save` path (no `agent_run` observed the execution):
        committed_since_base: set[str] = set()
        try:
            r_comm = subprocess.run(
                ["git", "diff", "--name-only", valid_base, "HEAD"],
                cwd=ws,
                capture_output=True,
                text=True,
                timeout=8,
            )
            if r_comm.returncode == 0:
                committed_since_base.update(f.strip().replace("\\", "/") for f in r_comm.stdout.splitlines() if f.strip())
            else:
                diff_partial = True
        except Exception:
            diff_partial = True

        unowned_wt = {f for f in post_claim_worktree if _norm_path(f) not in other_task_owned}
        touched = committed_since_base | unowned_wt
        # Uncommitted files in a shared worktree without `agent_run` snapshots cannot be proven exclusive!
        if unowned_wt:
            diff_partial = True
    else:
        # Unclaimed heuristic fallback (always `diff_partial=True`)
        diff_partial = True
        touched = set(post_claim_worktree)
        if not touched:
            r_last = subprocess.run(["git", "diff", "--name-only", "HEAD~1", "HEAD"], cwd=ws, capture_output=True, text=True, timeout=5)
            if r_last.returncode == 0:
                touched.update(f.strip().replace("\\", "/") for f in r_last.stdout.splitlines() if f.strip())

    ordered_files = sorted(f.replace("\\", "/") for f in touched if f and not _is_internal_meta(f))

    # Pre-claim dirty overlap or active foreign lock intersection -> must flag PARTIAL_DIFF / (?)
    baseline_norms = {_norm_path(k) for k in baseline_snap}
    if any(_norm_path(f) in baseline_norms for f in ordered_files):
        diff_partial = True

    foreign_locks = _active_foreign_locked_files(ws, exclude_owner=lock_owner)
    if task_rec.get("lock_conflict") or any(_norm_path(f) in foreign_locks for f in ordered_files):
        diff_partial = True

    code_files = [f for f in ordered_files if f.lower().endswith(_CODE_EXTS)][:12]
    contracts: list[str] = []
    contracts_partial = False

    if code_files:
        diff_chunks: list[str] = []
        tracked_code = []
        for cf in code_files:
            full_cf = os.path.join(ws, cf)
            r_ls = subprocess.run(["git", "ls-files", "--error-unmatch", "--", cf], cwd=ws, capture_output=True, timeout=3)
            if r_ls.returncode != 0 and os.path.isfile(full_cf):
                try:
                    with open(full_cf, encoding="utf-8", errors="replace") as ftxt:
                        lines = ftxt.read().splitlines()
                    diff_chunks.append(f"+++ b/{cf}\n" + "\n".join(f"+{ln}" for ln in lines))
                except OSError:
                    pass
            else:
                tracked_code.append(cf)

        added_by_file: dict[str, set[int] | None] = {}
        for chunk in diff_chunks:  # untracked files: every line is new
            m_f = re.match(r"\+\+\+ b/(.+)", chunk)
            if m_f:
                added_by_file[m_f.group(1).strip()] = None
        if tracked_code:
            diff_cmd = ["git", "diff", "-U0", valid_base, "--"] + tracked_code if valid_base else ["git", "diff", "-U0", "HEAD~1", "--"] + tracked_code
            r_diff = subprocess.run(diff_cmd, cwd=ws, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
            if r_diff.returncode != 0 or (not valid_base and not r_diff.stdout.strip()):
                r_diff = subprocess.run(["git", "diff", "-U0", "--"] + tracked_code, cwd=ws, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
                diff_partial = True
            if r_diff.stdout:
                diff_chunks.append(r_diff.stdout)
                for f_path, lines in parse_added_lines(r_diff.stdout).items():
                    added_by_file[f_path] = lines

        contracts, contracts_partial = _contracts_for_files(ws, code_files, added_by_file, "\n".join(diff_chunks))

    return {
        "touched_files": ordered_files,
        "interface_contracts": contracts,
        "diff_partial": diff_partial,
        "contracts_partial": contracts_partial,
        "git_verified": True,
    }


def file_skeleton(rel_path: str, workspace: str = ".", max_syms: int = 8) -> str:
    """Just-in-Time RepoMap skeleton (`L<n>:def/class/func`) cached by mtime; skips Ghost Files."""
    ws = os.path.abspath(workspace or ".")
    full = os.path.join(ws, rel_path)
    if not os.path.isfile(full) or not rel_path.lower().endswith(_CODE_EXTS):
        return ""
    try:
        mtime = os.path.getmtime(full)
        ck = (full, mtime, max_syms)
        if ck in _SKELETON_CACHE:
            return _SKELETON_CACHE[ck]
        syms: list[str] = []
        lang = lang_for_path(rel_path)
        decls = None
        if lang:
            with open(full, "rb") as fbin:
                decls = extract_declarations(fbin.read(), lang)
        if decls is not None:
            for d in decls:
                if not d["public"] and d["name"].startswith(("_", "#")):
                    continue
                syms.append(f"L{d['line']}:{d['signature'][:55]}")
                if len(syms) >= max_syms:
                    break
            res = f"{rel_path} [{', '.join(syms)}]" if syms else ""
            if len(_SKELETON_CACHE) > 512:
                _SKELETON_CACHE.clear()
            _SKELETON_CACHE[ck] = res
            return res
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                if _SYM_DEF_RE.match(line):
                    clean = re.sub(r"\s+", " ", line.strip()).rstrip("{:").strip()
                    clean = re.sub(r"\b(?:public|static|virtual|override|async|partial|export)\s+", "", clean)
                    syms.append(f"L{lineno}:{clean[:55]}")
                    if len(syms) >= max_syms:
                        break
        res = f"{rel_path} [{', '.join(syms)}]" if syms else ""
        if len(_SKELETON_CACHE) > 512:
            _SKELETON_CACHE.clear()
        _SKELETON_CACHE[ck] = res
        return res
    except Exception:
        return ""


def compute_bits(data: dict, workspace: str = ".") -> int:
    """Computes 16-bit status flags. `BIT_CODE_TOUCHED` requires actual change AND existing file (no Ghost Files)."""
    bits = int(data.get("signal_bits") or 0)
    ws = os.path.abspath(workspace or ".")
    tf = data.get("touched_files") or []
    ic = data.get("interface_contracts") or []
    if isinstance(tf, str):
        tf = []

    existing_tf = [str(f) for f in tf if os.path.isfile(os.path.join(ws, str(f)))]
    if existing_tf:
        if data.get("git_verified"):
            changed_ok = True
        elif is_git_repo(ws):
            snap = snapshot_worktree(ws)
            norm_dirty = {_norm_path(k) for k in snap if k != "__HEAD__"}
            changed_ok = any(_norm_path(f) in norm_dirty for f in existing_tf)
        else:
            changed_ok = False
    else:
        changed_ok = False

    if changed_ok:
        bits |= BIT_CODE_TOUCHED
    else:
        bits &= ~BIT_CODE_TOUCHED

    if ic:
        bits |= BIT_API_CHANGED | BIT_CONTRACT_PUB
    if data.get("diff_partial"):
        bits |= BIT_DIFF_PARTIAL
    else:
        bits &= ~BIT_DIFF_PARTIAL
    if data.get("delegated"):
        bits |= BIT_DELEGATED
    if data.get("locked"):
        bits |= BIT_HAS_LOCK
    if data.get("breaking"):
        bits |= BIT_BREAKING
    qa = str(data.get("qa_status") or "").upper()
    if qa == "PASS":
        bits = (bits | BIT_QA_PASS) & ~BIT_QA_FAIL
    elif qa == "FAIL":
        bits = (bits | BIT_QA_FAIL) & ~BIT_QA_PASS
    return bits


def decode_bits(bits: int) -> list[str]:
    return [name for mask, name in _BIT_LABELS if bits & mask]


def default_store_path(workspace: str = ".") -> str:
    env_path = os.environ.get("MCP_PKT_REFS", "").strip()
    if env_path:
        return env_path
    ws = os.path.abspath(workspace or ".")
    return os.path.join(ws, ".mcp-agents", "pkt_refs.json")


def _spill_merging_files(store_path: str) -> list[str]:
    spill = store_path + ".spill.jsonl"
    folder = os.path.dirname(spill) or "."
    base = os.path.basename(spill)
    try:
        return [os.path.join(folder, n) for n in os.listdir(folder) if n.startswith(base + ".") and n.endswith(".merging")]
    except OSError:
        return []


def _merge_spill_file(path: str, into: dict) -> None:
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as sf:
            for line in sf:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    if isinstance(entry, dict) and "ref" in entry and "payload" in entry:
                        into[entry["ref"]] = entry["payload"]
    except Exception:
        pass


def load_pkt_refs(store_path: str) -> dict:
    d: dict = {}
    try:
        with open(store_path, encoding="utf-8") as fh:
            loaded = json.load(fh)
            if isinstance(loaded, dict):
                d.update(loaded)
    except Exception:
        pass
    spill = store_path + ".spill.jsonl"
    for path in [spill] + sorted(_spill_merging_files(store_path)):
        _merge_spill_file(path, d)
    return d


def _finish_spill_merge(merging: str, refs_written: dict) -> None:
    pending: dict = {}
    _merge_spill_file(merging, pending)
    if all(k in refs_written for k in pending):
        try:
            os.remove(merging)
        except OSError:
            pass


def store_pkt_ref(card_id: str, payload: dict, store_path: str) -> str:
    """Atomically stores full payload in `store_path` and returns `<id>#<sha8>`."""
    cid = pkt_safe_id(card_id)
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    ref = f"{cid}#{hashlib.sha256(blob.encode('utf-8')).hexdigest()[:8]}"
    os.makedirs(os.path.dirname(os.path.abspath(store_path)), exist_ok=True)
    lock = store_path + ".lock"
    with _PKT_REFS_LOCK:
        fd = None
        for attempt in range(40):
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(lock) > 15:
                        os.remove(lock)
                except OSError:
                    pass
                time.sleep(0.02 + 0.005 * attempt)
        if fd is None:
            spill = store_path + ".spill.jsonl"
            line = json.dumps({"ref": ref, "payload": payload}, ensure_ascii=False) + "\n"
            with open(spill, "a", encoding="utf-8") as sf:
                sf.write(line)
                sf.flush()
            return ref
        try:
            spill_path = store_path + ".spill.jsonl"
            merging = None
            if os.path.isfile(spill_path):
                merging = f"{spill_path}.{os.getpid()}.merging"
                try:
                    os.replace(spill_path, merging)
                except OSError:
                    merging = None
            refs = load_pkt_refs(store_path)
            refs[ref] = payload
            if len(refs) > _PKT_REFS_MAX:
                excess = len(refs) - _PKT_REFS_MAX
                for k in list(refs.keys())[:excess]:
                    refs.pop(k, None)
            tmp = f"{store_path}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(refs, fh, ensure_ascii=False)
            os.replace(tmp, store_path)
            if merging and os.path.isfile(merging):
                _finish_spill_merge(merging, refs)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.remove(lock)
            except OSError:
                pass
    return ref


def encode_packet(
    data: dict,
    op: str = "HND",
    workspace: str = ".",
    store_path: str | None = None,
    always_store: bool = False,
) -> str:
    """Encodes a handoff dict into a 1-line @PKT micro-packet (`ref=` emitted ONLY on truncation unless forced)."""
    hand = coerce_handoff(data)
    bits = compute_bits(data, workspace=workspace)
    flags = ",".join(decode_bits(bits)) or "NONE"
    raw_tf = [re.sub(r"[\r\n|]+", "/", f) for f in hand["touched_files"]]
    tf = ",".join(raw_tf[:4]) + f",(+{len(raw_tf) - 4})" if len(raw_tf) > 4 else (",".join(raw_tf) or "-")
    raw_ic = [re.sub(r"[\r\n|]+", " ", c) for c in hand["interface_contracts"]]
    linearized_ic = [re.sub(r";\s*", ", ", c_item.rstrip(";").strip()) for c_item in raw_ic]
    lossy_mark = ",(?)" if (data.get("diff_partial") or data.get("contracts_partial")) else ""
    if len(linearized_ic) > 3:
        ic = ";".join(linearized_ic[:3]) + f";(+{len(linearized_ic) - 3})" + lossy_mark
    else:
        ic = (";".join(linearized_ic) or "-") + lossy_mark
    why_full = re.sub(r"\s+", " ", hand["handoff_why"]).replace("|", "/").strip()
    nxt_full = re.sub(r"\s+", " ", hand["handoff_next"]).replace("|", "/").strip()
    why = smart_truncate(why_full, 90)
    nxt = smart_truncate(nxt_full, 140)
    truncated = len(raw_tf) > 4 or len(raw_ic) > 3 or len(why) < len(why_full) or len(nxt) < len(nxt_full)
    cid = pkt_safe_id(data.get("id", "?"))
    ref_part = ""
    if (truncated or always_store) and data.get("id"):
        sp = store_path or default_store_path(workspace)
        ref = store_pkt_ref(cid, {"files": raw_tf, "contracts": raw_ic, "why": why_full, "nxt": nxt_full}, sp)
        ref_part = f"|ref={ref}"
    why_part = f"|why={why}" if why else ""
    st = str(data.get("status") or "doing").replace("|", "_").replace("\n", "")
    cli_str = str(data.get("cli") or "-").replace("|", "_").replace("\n", "")
    op_str = str(op or "HND").replace("|", "_").replace("\n", "")
    return f"@PKT|{cid}|{st}|{cli_str}|[{flags}]|op={op_str}|f={tf}|api={ic}{why_part}|nxt={nxt or '-'}{ref_part}"


def build_pkt_from_git(
    task_id: str,
    workspace: str = ".",
    handoff_why: str = "",
    handoff_next: str = "",
    op: str = "HND",
    status: str = "doing",
    cli: str = "-",
    qa_status: str = "",
    delegated: bool = False,
    base_commit: str = "",
    explicit_files: list[str] | None = None,
    lock_owner: str = "",
    store_path: str | None = None,
) -> str:
    """Builds a truthful @PKT extracting `touched_files` & `interface_contracts` from Git; LLM supplies only `why`/`nxt`."""
    facts = extract_git_facts(
        workspace=workspace,
        task_id=task_id,
        base_commit=base_commit,
        explicit_files=explicit_files,
        lock_owner=lock_owner,
    )
    data = {
        "id": task_id,
        "status": status,
        "cli": cli,
        "touched_files": facts["touched_files"],
        "interface_contracts": facts["interface_contracts"],
        "diff_partial": facts["diff_partial"],
        "contracts_partial": facts.get("contracts_partial", False),
        "git_verified": facts["git_verified"],
        "handoff_why": handoff_why,
        "handoff_next": handoff_next,
        "qa_status": qa_status,
        "delegated": delegated,
    }
    return encode_packet(data, op=op, workspace=workspace, store_path=store_path, always_store=False)


def resolve_pkt_ref(ref: str, workspace: str = ".", store_path: str | None = None) -> dict | None:
    """Resolves `<id>#<sha8>` from the MCP store, with fallback to legacy `out/pkt_refs.json`."""
    candidates = [store_path] if store_path else [
        default_store_path(workspace),
        os.path.join(os.path.abspath(workspace or "."), "out", "pkt_refs.json"),
    ]
    for path in candidates:
        data = load_pkt_refs(path)
        if ref in data:
            return data[ref]
    return None


def _norm_path(p: str) -> str:
    return re.sub(r"^(?:\./)+", "", str(p or "").replace("\\", "/").strip()).lower()


def _locks_path(workspace: str = ".") -> str:
    return os.path.join(os.path.abspath(workspace or "."), ".mcp-agents", "locks.json")


def _load_locks(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
            if not isinstance(d, dict):
                d = {}
    except Exception:
        d = {}
    now = time.time()
    return {k: v for k, v in d.items() if isinstance(v, dict) and now - float(v.get("ts") or 0) <= _LOCK_TTL_S}


def acquire_locks(owner_id: str, files: list[str], workspace: str = ".", cli: str = "-") -> tuple[bool, list[dict]]:
    """Acquires advisory file locks (30m TTL). `owner_id` should be unique per invocation."""
    norm_files = [_norm_path(f) for f in (files or []) if _norm_path(f) and _norm_path(f) != "-"]
    if not norm_files:
        return True, []
    lp = _locks_path(workspace)
    os.makedirs(os.path.dirname(lp), exist_ok=True)
    lock_file = lp + ".lock"
    with _PKT_REFS_LOCK:
        fd = None
        for attempt in range(40):
            try:
                fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(lock_file) > 15:
                        os.remove(lock_file)
                except OSError:
                    pass
                time.sleep(0.02 + 0.005 * attempt)
        if fd is None:
            return False, [{"file": norm_files[0], "reason": "lock contention"}]
        try:
            locks = _load_locks(lp)
            conflicts = []
            for f in norm_files:
                cur = locks.get(f)
                if cur and cur.get("owner") != owner_id:
                    conflicts.append({"file": f, "owner": cur.get("owner"), "cli": cur.get("cli")})
            if conflicts:
                return False, conflicts
            now = time.time()
            for f in norm_files:
                locks[f] = {"owner": owner_id, "cli": cli, "ts": now}
            tmp = f"{lp}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(locks, fh, ensure_ascii=False)
            os.replace(tmp, lp)
            return True, []
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.remove(lock_file)
            except OSError:
                pass


def release_locks(owner_id: str, workspace: str = ".", files: list[str] | None = None) -> int:
    """Releases locks held by `owner_id`. Returns count released."""
    lp = _locks_path(workspace)
    if not os.path.isfile(lp):
        return 0
    targets = {_norm_path(f) for f in files} if files else None
    lock_file = lp + ".lock"
    with _PKT_REFS_LOCK:
        fd = None
        for attempt in range(40):
            try:
                fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                time.sleep(0.02 + 0.005 * attempt)
        if fd is None:
            return 0
        try:
            locks = _load_locks(lp)
            removed = 0
            for k in list(locks.keys()):
                if locks[k].get("owner") == owner_id and (targets is None or k in targets):
                    locks.pop(k, None)
                    removed += 1
            tmp = f"{lp}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(locks, fh, ensure_ascii=False)
            os.replace(tmp, lp)
            return removed
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.remove(lock_file)
            except OSError:
                pass


def _deltas_path(workspace: str = ".") -> str:
    return os.path.join(os.path.abspath(workspace or "."), ".mcp-agents", "deltas.json")


def record_deltas(cli: str, file_hunks: dict[str, str], workspace: str = ".") -> None:
    """Records compact per-file edit hunks (`file -> '@@ ... @@'`) for collaborative handoffs."""
    if not file_hunks:
        return
    dp = _deltas_path(workspace)
    os.makedirs(os.path.dirname(dp), exist_ok=True)
    try:
        with open(dp, encoding="utf-8") as fh:
            data = json.load(fh)
            if not isinstance(data, dict):
                data = {}
    except Exception:
        data = {}
    now = time.time()
    data = {k: v for k, v in data.items() if isinstance(v, dict) and now - float(v.get("ts") or 0) <= 7200}
    for f, hunks in file_hunks.items():
        nf = _norm_path(f)
        if nf:
            data[nf] = {"cli": cli, "ts": now, "hunks": smart_truncate(hunks, 180)}
    tmp = f"{dp}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)
    os.replace(tmp, dp)


def get_recent_deltas(files: list[str], workspace: str = ".", exclude_cli: str = "") -> list[str]:
    """Returns compact `[DELTA]` lines for files recently edited by other CLIs."""
    dp = _deltas_path(workspace)
    try:
        with open(dp, encoding="utf-8") as fh:
            data = json.load(fh)
            if not isinstance(data, dict):
                return []
    except Exception:
        return []
    now = time.time()
    lines = []
    for f in files or []:
        nf = _norm_path(f)
        entry = data.get(nf)
        if not isinstance(entry, dict):
            continue
        if now - float(entry.get("ts") or 0) > 7200:
            continue
        if exclude_cli and entry.get("cli") == exclude_cli:
            continue
        hunks = entry.get("hunks") or "modified"
        lines.append(f"[DELTA] {entry.get('cli', '?')} edited {f}: {hunks}")
    return lines
