"""Run all unittest regressions and optionally save a machine-readable result."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json-output', type=Path)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), top_level_dir=str(ROOT))
    started = time.perf_counter()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    digest = hashlib.sha256()
    code = sorted([*ROOT.joinpath('src').rglob('*.py'), *ROOT.joinpath('tests').rglob('*.py'), *ROOT.joinpath('scripts').rglob('*.py'), ROOT / 'build_backend.py'])
    for path in code:
        digest.update(path.relative_to(ROOT).as_posix().encode() + b'\0' + path.read_bytes() + b'\0')
    payload = {'generated_at': datetime.now(timezone.utc).isoformat(), 'python': platform.python_version(), 'platform': platform.system(), 'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped), 'expected_failures': len(result.expectedFailures), 'unexpected_successes': len(result.unexpectedSuccesses), 'successful': result.wasSuccessful(), 'elapsed_seconds': round(time.perf_counter() - started, 4), 'python_sources_sha256': digest.hexdigest()}
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(payload, indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
