"""Reproducible synthetic benchmark, not a throughput or memory guarantee."""
from __future__ import annotations

import argparse
import json
import platform
import resource
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from sigma_probe.config import Settings
from sigma_probe.main import AnalysisPipeline


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events', type=int, default=50_000)
    parser.add_argument('--actors', type=int, default=1000)
    args = parser.parse_args()
    if not 1 <= args.events <= 100_000 or not 1 <= args.actors <= min(args.events, 10_000):
        parser.error('events: 1..100000; actors: 1..min(events,10000)')
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'synthetic.log'
        base = datetime(2026, 9, 8, tzinfo=timezone.utc)
        with path.open('w', encoding='utf-8') as handle:
            for index in range(args.events):
                stamp = (base + timedelta(seconds=index)).strftime('%d/%b/%Y:%H:%M:%S %z')
                handle.write(f'2001:db8::{index % args.actors + 1:x} - - [{stamp}] "GET /health HTTP/1.1" 200 128 "-" "curl/8.0"\n')
        started = time.perf_counter()
        result = AnalysisPipeline(Settings()).run(str(path), write_reports=False)
        elapsed = time.perf_counter() - started
        if result.ingestion.total('accepted') != args.events or len(result.actors) != args.actors:
            raise RuntimeError('Benchmark count reconciliation failed')
        if any(a.threat_score for a in result.actors):
            raise RuntimeError('Synthetic health checks were misclassified')
        memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == 'darwin':
            memory /= 1024
        print(json.dumps({'scenario': 'synthetic periodic health checks', 'events': args.events, 'actors': args.actors, 'input_bytes': path.stat().st_size, 'elapsed_seconds': round(elapsed, 4), 'events_per_second': round(args.events / elapsed, 1), 'peak_rss_mib': round(memory / 1024, 2), 'python': platform.python_version(), 'platform': platform.system(), 'includes': 'parse, enrich, profile, detect, score, in-memory report projection', 'excludes': 'input generation and report file rendering/writes', 'production_capacity_claim': False}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
