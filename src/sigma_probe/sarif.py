"""SARIF export only when report input hashes match explicit repository files."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .pipeline.reporting import verify_bundle
from .validation import SigmaProbeError


def _source_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def export_sarif(bundle: str | Path, source_root: str | Path, source_specs: list[str],
                 *, report_key: str | None = None) -> dict[str, Any]:
    """Map report evidence to verified repository-relative source locations."""
    root = Path(source_root).resolve()
    if not root.is_dir():
        raise SigmaProbeError('source-root must be a directory')
    mappings: dict[str, str] = {}
    for spec in source_specs:
        input_id, separator, relative = spec.partition('=')
        path = Path(relative)
        if not separator or not input_id.startswith('input-') or not relative or path.is_absolute() or '..' in path.parts:
            raise SigmaProbeError('Use --source input-N=repository-relative/path')
        if input_id in mappings:
            raise SigmaProbeError(f'Duplicate source mapping: {input_id}')
        mappings[input_id] = relative
    bundle = Path(bundle)
    verified = verify_bundle(bundle, report_key)
    if 'report.json' not in verified['artifacts']:
        raise SigmaProbeError('SARIF export requires report.json')
    report_path = bundle / 'report.json'
    if report_path.stat().st_size > 64 * 1024 * 1024:
        raise SigmaProbeError('Report is too large for SARIF export')
    try:
        report = json.loads(report_path.read_text(encoding='utf-8'))
        inputs = {item['input_id']: item for item in report['inputs']}
        actors = report['actors']
        key_mode = report['metadata']['privacy']['key_mode']
    except (ValueError, UnicodeError, KeyError, TypeError) as exc:
        raise SigmaProbeError('Invalid JSON report') from exc
    if not isinstance(actors, list) or not mappings or set(mappings) != set(inputs):
        raise SigmaProbeError('Map every report input exactly once to a repository file')
    if key_mode == 'ephemeral_per_run':
        raise SigmaProbeError('SARIF requires raw IPs or stable operator-key pseudonyms for fingerprints')
    uris: dict[str, str] = {}
    for input_id, relative in mappings.items():
        path = root / relative
        if path.suffix.lower() == '.gz' or path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            raise SigmaProbeError(f'Invalid source path: {relative}')
        if _source_hash(path) != inputs[input_id]['sha256']:
            raise SigmaProbeError(f'Source hash differs from report: {input_id}')
        uris[input_id] = quote(Path(relative).as_posix(), safe='/')
    results: list[dict[str, Any]] = []
    rules: set[str] = set()
    seen: set[tuple[str, str, str, int]] = set()
    levels = {'high': 'error', 'medium': 'warning', 'low': 'note', 'info': 'note'}
    for actor in actors:
        if actor['suppressed']:
            continue
        for evidence in actor['evidence']:
            rule = evidence['kind']
            for reference in evidence['references']:
                input_id, line = reference['input_id'], reference['line']
                if input_id not in uris or type(line) is not int or line < 1:
                    raise SigmaProbeError('Invalid evidence source reference')
                identity = (actor['ip_address'], rule, input_id, line)
                if identity in seen:
                    continue
                seen.add(identity)
                if len(seen) > 25_000:
                    raise SigmaProbeError('SARIF exceeds GitHub 25,000-result limit; narrow the input window')
                rules.add(rule)
                fingerprint = hashlib.sha256('\0'.join(map(str, (report['metadata']['site'], *identity))).encode()).hexdigest()
                results.append({
                    'ruleId': rule, 'level': levels.get(actor['severity'], 'note'),
                    'message': {'text': f'{rule}: heuristic access-log signal; review the incident report before action.'},
                    'locations': [{'physicalLocation': {'artifactLocation': {'uri': uris[input_id], 'uriBaseId': '%SRCROOT%'},
                                                        'region': {'startLine': line}}}],
                    'partialFingerprints': {'sigmaProbe/v1': fingerprint},
                    'properties': {'actor': actor['ip_address'], 'score': actor['score'], 'status': 'context_only'},
                })
    return {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0',
        'runs': [{'tool': {'driver': {'name': 'SIGMA-PROBE', 'rules': [
            {'id': rule, 'shortDescription': {'text': rule}} for rule in sorted(rules)]}},
            'originalUriBaseIds': {'%SRCROOT%': {'uri': root.as_uri().rstrip('/') + '/'}}, 'results': results}],
    }
