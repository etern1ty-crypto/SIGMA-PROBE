"""Score actor-level detection against independently labeled local log snapshots."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from sigma_probe.config import load_config
from sigma_probe.main import AnalysisPipeline
from sigma_probe.validation import SigmaProbeError, canonical_ip


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def evaluate(manifest_path: Path, config_path: str | None = None, threshold: int | None = None) -> dict:
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(manifest, dict) or manifest.get('schema_version') != 1:
        raise ValueError('manifest schema_version must be 1')
    cases = manifest.get('cases')
    if not isinstance(cases, list) or not cases:
        raise ValueError('manifest cases must be a nonempty list')
    if manifest.get('dataset_kind') not in ('synthetic', 'testbed', 'production'):
        raise ValueError('dataset_kind must be synthetic, testbed, or production')
    settings = load_config(config_path, environ={})
    cutoff = settings.scoring.medium_threshold if threshold is None else threshold
    if type(cutoff) is not int or not 0 <= cutoff <= 100:
        raise ValueError('threshold must be an integer from 0 to 100')

    counts: Counter[str] = Counter()
    sources = []
    seen_hashes = set()
    tool_version = None
    for index, case in enumerate(cases, 1):
        if not isinstance(case, dict) or not isinstance(case.get('log'), str) or not isinstance(case.get('labels'), dict):
            raise ValueError(f'case {index}: expected log path and actor labels')
        path = Path(case['log'])
        if not path.is_absolute():
            path = manifest_path.parent / path
        labels = {}
        for ip, label in case['labels'].items():
            address = canonical_ip(ip)
            if address in labels or label not in ('attack', 'benign', 'unknown'):
                raise ValueError(f'case {index}: duplicate IP or invalid label')
            labels[address] = label
        result = AnalysisPipeline(settings).run(str(path), write_reports=False)
        tool_version = result.report['metadata']['version']
        if result.ingestion.partial:
            raise ValueError(f'case {index}: partial ingestion cannot be evaluated')
        actors = {actor.ip_address: actor for actor in result.actors}
        if set(labels) != set(actors):
            raise ValueError(f'case {index}: labels must cover every observed actor exactly once')
        source_hash = result.report['inputs'][0]['sha256']
        if source_hash in seen_hashes:
            raise ValueError(f'case {index}: duplicate log content')
        seen_hashes.add(source_hash)
        sources.append({'case': index, 'input_sha256': source_hash,
                        'config_sha256': result.report['metadata']['config_sha256'],
                        'accepted_events': result.ingestion.total('accepted')})
        for ip, actor in actors.items():
            label = labels[ip]
            if label == 'unknown':
                counts['unknown'] += 1
                continue
            predicted = not actor.suppressed and actor.threat_score >= cutoff
            counts[('tp' if predicted else 'fn') if label == 'attack' else ('fp' if predicted else 'tn')] += 1

    tp, fp, tn, fn = (counts[key] for key in ('tp', 'fp', 'tn', 'fn'))
    return {
        'schema_version': 1, 'tool_version': tool_version, 'unit': 'actor per finite log snapshot',
        'dataset_kind': manifest['dataset_kind'], 'threshold': cutoff,
        'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'cases': sources,
        'counts': {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn, 'unknown': counts['unknown']},
        'precision': _rate(tp, tp + fp), 'recall': _rate(tp, tp + fn),
        'false_positive_rate': _rate(fp, fp + tn),
        'coverage': _rate(tp + fp + tn + fn, tp + fp + tn + fn + counts['unknown']),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--config', help='SIGMA-PROBE TOML settings; defaults otherwise')
    parser.add_argument('--threshold', type=int, help='0–100 score cutoff; defaults to configured medium threshold')
    args = parser.parse_args()
    try:
        outcome = evaluate(args.manifest, args.config, args.threshold)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, SigmaProbeError) as exc:
        parser.exit(2, f'evaluation error: {exc}\n')
    print(json.dumps(outcome, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
