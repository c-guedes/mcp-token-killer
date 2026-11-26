"""Telemetry & token-savings report for `<workspace>/.mcp-agents/metrics.jsonl`."""
from __future__ import annotations

import argparse
import collections
import json
import os


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize @PKT and API token metrics per CLI.")
    ap.add_argument("workspace", nargs="?", default=".", help="Target workspace directory")
    args = ap.parse_args()

    path = os.path.join(os.path.abspath(args.workspace), ".mcp-agents", "metrics.jsonl")
    if not os.path.isfile(path):
        raise SystemExit(f"No metrics file at: {path}")

    rows = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            if ln.strip():
                rows.append(json.loads(ln))

    by_cli: dict[str, list[dict]] = collections.defaultdict(list)
    for r in rows:
        by_cli[f"{r.get('cli','?')}:{r.get('mode','?')}"].append(r)

    print(f"=== mcp-token-killer metrics ({len(rows)} calls) ===")
    print(f"{'cli:mode':16} {'n':>4} {'ok%':>5} {'prompt_c':>9} {'pkt%':>6} {'in_tok':>10} {'cache%':>7} {'out_tok':>8} {'cost$':>8} {'avg_s':>7}")
    for key, rs in sorted(by_cli.items()):
        n = len(rs)
        ok_pct = 100.0 * sum(1 for r in rs if r.get("ok")) / n
        p_sum = sum(int(r.get("prompt_chars") or 0) for r in rs)
        pkt_sum = sum(int(r.get("pkt_chars") or 0) for r in rs)
        pkt_pct = (100.0 * pkt_sum / p_sum) if p_sum else 0.0
        in_tok = sum(int(r.get("input_tokens") or 0) for r in rs)
        c_tok = sum(int(r.get("cached_tokens") or 0) for r in rs)
        cache_pct = (100.0 * c_tok / in_tok) if in_tok else 0.0
        out_tok = sum(int(r.get("output_tokens") or 0) for r in rs)
        cost = sum(float(r.get("cost_usd") or 0.0) for r in rs)
        avg_s = sum(float(r.get("secs") or 0.0) for r in rs) / n
        print(
            f"{key:16} {n:>4} {ok_pct:>4.0f}% {p_sum // n:>9} {pkt_pct:>5.1f}% "
            f"{in_tok:>10} {cache_pct:>6.1f}% {out_tok:>8} {cost:>8.4f} {avg_s:>6.1f}s"
        )


if __name__ == "__main__":
    main()
