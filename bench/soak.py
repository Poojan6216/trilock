"""Soak test: 100 concurrent sessions, sustained calls, memory over time (BUILD_SPEC 7.3).

    uv run python bench/soak.py [--sessions 100] [--seconds 60]

Writes bench/results/soak.json with RSS sampled every second, call throughput,
error count, and whether the per-session ledger cap actually bound. Sessions are
in-process clients over one proxy whose upstreams are the fixture servers; each
session is given its own identity through a principal so that 100 sessions are
100 ledgers, which is the memory shape that has to stay flat.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import resource
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import anyio
from mcp import Client

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from tests.integration.conftest import stdio_upstream  # noqa: E402

from trilock.config import DetectorConfig, LedgerConfig, TrilockConfig  # noqa: E402
from trilock.proxy.server import build_proxy  # noqa: E402
from trilock.taint.store import SessionKey  # noqa: E402

POLICY = REPO / "policies" / "dataflow.yaml"
COMMIT = subprocess.run(
    ["git", "rev-parse", "--short", "HEAD"], cwd=REPO, capture_output=True, text=True
).stdout.strip()


def rss_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return usage / (1024 * 1024) if sys.platform == "darwin" else usage / 1024


async def main_async(sessions: int, seconds: int, cap: int) -> dict[str, Any]:
    tmp = REPO / ".trilock" / "soak-workspace"
    tmp.mkdir(parents=True, exist_ok=True)
    cfg = TrilockConfig(
        servers={
            "mail": stdio_upstream("mail_server.py"),
            "notes": stdio_upstream("notes_server.py", TRILOCK_FIXTURE_NOTES_DIR=str(tmp)),
        },
        policy=POLICY,
        ledger=LedgerConfig(max_sources=cap),
        detectors=DetectorConfig(enabled=True),
        source_path=REPO / "trilock.yaml",
    )
    samples: list[dict[str, float]] = []
    calls = errors = 0
    latencies: list[float] = []
    started = time.time()

    async with build_proxy(cfg) as (server, _router, guard):
        # Give each session its own identity through the connection state hook.
        guard.resolver.transport = "http"

        async def session(i: int) -> None:
            nonlocal calls, errors
            async with Client(server) as client:
                # The in-process dispatcher builds a fresh session object per
                # request, so the principal is bound per call via the resolver's
                # lookup order: mark the *guard* to map this task to a principal.
                key = SessionKey(kind="principal", value=f"soak-{i}")
                guard.resolver._pinned = key  # type: ignore[attr-defined]
                while time.time() - started < seconds:
                    t0 = time.perf_counter()
                    try:
                        # alternate ingest (untrusted+sensitive) and an allowed read
                        r = await client.call_tool("mail.search", {"query": f"q{calls % 7}"})
                        errors += r.is_error
                        r = await client.call_tool("notes.list_notes", {})
                        errors += r.is_error
                    except Exception:
                        errors += 2
                    latencies.append((time.perf_counter() - t0) * 1000)
                    calls += 2

        async def sampler() -> None:
            while time.time() - started < seconds + 1:
                samples.append(
                    {
                        "t": round(time.time() - started, 1),
                        "rss_mb": round(rss_mb(), 1),
                        "sessions": len(guard.sessions),
                        "ledgers": len(guard.ledgers),
                    }
                )
                await anyio.sleep(1)

        async with anyio.create_task_group() as tg:
            tg.start_soon(sampler)
            for i in range(sessions):
                tg.start_soon(session, i)

        ledger_sizes = [len(s.ledger) for s in guard.sessions._states.values()]
        approvals = len(guard.approvals.pending)
    return {
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "commit": COMMIT,
        "command": "uv run python bench/soak.py " + " ".join(sys.argv[1:]),
        "machine": platform.platform(),
        "sessions": sessions,
        "seconds": seconds,
        "ledger_cap": cap,
        "calls": calls,
        "errors": errors,
        "calls_per_second": round(calls / max(1.0, time.time() - started), 1),
        "call_latency_ms": {
            "p50": round(statistics.median(latencies), 2) if latencies else None,
            "p95": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 2)
            if latencies
            else None,
            "p99": round(sorted(latencies)[int(0.99 * (len(latencies) - 1))], 2)
            if latencies
            else None,
        },
        "rss_mb": {
            "start": samples[0]["rss_mb"] if samples else None,
            "end": samples[-1]["rss_mb"] if samples else None,
            "max": max(s["rss_mb"] for s in samples) if samples else None,
            "samples": samples,
        },
        "ledgers": {
            "count": len(ledger_sizes),
            "max_sources": max(ledger_sizes) if ledger_sizes else 0,
            "cap_bound": bool(ledger_sizes) and max(ledger_sizes) <= cap and calls / 2 > cap,
        },
        "pending_approvals": approvals,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=100)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--ledger-cap", type=int, default=50)
    args = parser.parse_args()
    result = asyncio.run(main_async(args.sessions, args.seconds, args.ledger_cap))
    out = REPO / "bench" / "results" / "soak.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    r = result
    print(
        f"sessions={r['sessions']} calls={r['calls']} errors={r['errors']} rate={r['calls_per_second']}/s "
        f"p50={r['call_latency_ms']['p50']}ms p99={r['call_latency_ms']['p99']}ms"
    )
    print(
        f"rss start={r['rss_mb']['start']}MB end={r['rss_mb']['end']}MB max={r['rss_mb']['max']}MB"
    )
    print(
        f"ledgers={r['ledgers']['count']} max_sources={r['ledgers']['max_sources']} cap={r['ledger_cap']} cap_bound={r['ledgers']['cap_bound']}"
    )
    print(f"wrote {out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
