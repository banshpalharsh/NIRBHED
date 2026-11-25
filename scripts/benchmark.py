#!/usr/bin/env python3
"""Measured benchmarks for Nirbhed's token-frugality claims. No network needed.

Run:  python scripts/benchmark.py
Prints a markdown table of real numbers (distillation compression + cache speedup
+ parallel speedup). Nothing here is hard-coded — it measures the live code.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from nirbhed.config import Config
from nirbhed.core.distill import distill
from nirbhed.tools.base import ParamSpec, ToolSpec
from nirbhed.tools.registry import Registry

APPROX_CHARS_PER_TOKEN = 4  # rough industry heuristic for English/ASCII tool output


def _synthetic_scan_output(lines: int = 4000) -> str:
    """Imitate a noisy nuclei/nmap run: mostly progress/banner noise, few hits."""
    out = ["\x1b[32m[INF] nuclei engine started\x1b[0m", "   __     _"]
    for i in range(lines):
        if i % 500 == 0:
            out.append(f"[{i}/{lines}] [INF] scanning templates... {i / lines:.0%}")
        elif i % 777 == 0:
            out.append(f"[CVE-2024-{1000 + i}] [critical] https://t.test/path{i} matched")
        elif i % 333 == 0:
            out.append(f"80/tcp open http syn-ack ttl 64 node-{i}")
        else:
            out.append(f"[DBG] probe {i} no-match ................................")
    return "\n".join(out)


def bench_distill() -> dict:
    raw = _synthetic_scan_output()
    condensed = distill(raw, max_chars=2000)
    raw_tok = len(raw) // APPROX_CHARS_PER_TOKEN
    con_tok = len(condensed) // APPROX_CHARS_PER_TOKEN
    return {
        "raw_chars": len(raw),
        "distilled_chars": len(condensed),
        "raw_tokens_est": raw_tok,
        "distilled_tokens_est": con_tok,
        "reduction_pct": 100 * (1 - len(condensed) / len(raw)),
        "kept_cve": "CVE-" in condensed,
        "kept_ports": "80/tcp open" in condensed,
    }


def bench_cache(tmp: Path) -> dict:
    cfg = Config.from_env()
    cfg.state_dir = tmp
    cfg.scope = []
    reg = Registry(cfg)
    reg.specs["bench_sleep"] = ToolSpec(
        name="bench_sleep", category="misc", tier="recon", binary="sh",
        desc="work", cmd=["sh", "-c", "sleep 0.4; echo 44/tcp open done"],
        params={"target": ParamSpec(default="x")},
    )
    t0 = time.perf_counter()
    reg.run("bench_sleep", {"target": "x"})
    cold = time.perf_counter() - t0
    t1 = time.perf_counter()
    r = reg.run("bench_sleep", {"target": "x"})
    warm = time.perf_counter() - t1
    return {"cold_s": cold, "warm_s": warm,
            "speedup_x": (cold / warm) if warm else float("inf"),
            "was_cached": r.cached}


def bench_parallel(tmp: Path) -> dict:
    cfg = Config.from_env()
    cfg.state_dir = tmp / "p"
    cfg.scope = []
    cfg.cache = False  # measure raw execution, not cache
    reg = Registry(cfg)
    reg.specs["bench_unit"] = ToolSpec(
        name="bench_unit", category="misc", tier="recon", binary="sh",
        desc="work", cmd=["sh", "-c", "sleep 0.4; echo {target} open"],
        params={"target": ParamSpec(required=True)},
    )
    calls = [{"tool": "bench_unit", "params": {"target": f"t{i}"}} for i in range(5)]
    t0 = time.perf_counter()
    for c in calls:
        reg.run(c["tool"], c["params"])
    seq = time.perf_counter() - t0
    reg.cache = reg.cache
    t1 = time.perf_counter()
    reg.run_many(calls, max_workers=5)
    par = time.perf_counter() - t1
    return {"sequential_s": seq, "parallel_s": par,
            "speedup_x": (seq / par) if par else float("inf")}


def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        dis = bench_distill()
        cac = bench_cache(tmp)
        par = bench_parallel(tmp)

    print("## Measured benchmarks\n")
    print("### Output distillation (synthetic 4,000-line scan)")
    print(f"- raw: {dis['raw_chars']:,} chars (~{dis['raw_tokens_est']:,} tokens)")
    print(f"- distilled: {dis['distilled_chars']:,} chars (~{dis['distilled_tokens_est']:,} tokens)")
    print(f"- **reduction: {dis['reduction_pct']:.1f}%** "
          f"(CVE kept: {dis['kept_cve']}, open ports kept: {dis['kept_ports']})\n")
    print("### Cache replay (0.4s tool)")
    print(f"- cold: {cac['cold_s']*1000:.0f} ms | warm (cached): {cac['warm_s']*1000:.1f} ms")
    print(f"- **speedup: {cac['speedup_x']:.0f}x**, cached={cac['was_cached']}\n")
    print("### Parallel fan-out (5 x 0.4s tools)")
    print(f"- sequential: {par['sequential_s']*1000:.0f} ms | parallel: {par['parallel_s']*1000:.0f} ms")
    print(f"- **speedup: {par['speedup_x']:.1f}x**")


if __name__ == "__main__":
    main()
