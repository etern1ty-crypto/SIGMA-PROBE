"""Review-only web defense snippets; never modify the host firewall or server."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from .pipeline.reporting import verify_bundle
from .validation import SigmaProbeError, canonical_ip, choice, integer, text, utc_datetime


def propose_block(bundle: str | Path, selected_ips: list[str], backend: str, expires_at: str,
                  reason: str, *, port: int = 443, report_key: str | None = None) -> dict[str, Any]:
    """Return an operator-review draft for exact IPs present in a verified report."""
    backend = choice(backend, 'backend', ('nginx', 'iptables'))
    expiry = utc_datetime(expires_at, 'expires_at')
    if expiry <= datetime.now(timezone.utc):
        raise SigmaProbeError('expires_at must be in the future')
    reason = text(reason, 'reason', 200)
    port = integer(port, 'port', 1, 65535)
    if not selected_ips or len(selected_ips) > 100:
        raise SigmaProbeError('Select between 1 and 100 exact IP addresses')
    ips = sorted({canonical_ip(value) for value in selected_ips}, key=lambda value: (ip_address(value).version, int(ip_address(value))))
    root = Path(bundle)
    verified = verify_bundle(root, report_key)
    if 'report.json' not in verified['artifacts']:
        raise SigmaProbeError('A JSON report is required for a defense proposal')
    report_path = root / 'report.json'
    if report_path.stat().st_size > 64 * 1024 * 1024:
        raise SigmaProbeError('Report is too large for defense proposal generation')
    try:
        report = json.loads(report_path.read_text(encoding='utf-8'))
        actors = report['actors']
        site = text(report['metadata']['site'], 'report site', 120)
        if not isinstance(actors, list) or any(not isinstance(actor, dict) or not isinstance(actor.get('ip_address'), str) for actor in actors):
            raise TypeError('Invalid actor list')
        known = {actor['ip_address']: actor for actor in actors}
    except (ValueError, UnicodeError, KeyError, TypeError) as exc:
        raise SigmaProbeError('Invalid JSON report') from exc
    if any(ip not in known or known[ip].get('suppressed') is not False for ip in ips):
        raise SigmaProbeError('Every selected IP must be a non-suppressed report actor with a raw address')
    if backend == 'nginx':
        add = [f'deny {ip};' for ip in ips]
        remove = [f'Remove the exact line: deny {ip};' for ip in ips]
    else:
        add, remove = [], []
        for ip in ips:
            command = 'ip6tables' if ip_address(ip).version == 6 else 'iptables'
            rule = f'INPUT -p tcp -s {ip} --dport {port} -j DROP'
            add.append(f'{command} -I {rule}')
            remove.append(f'{command} -D {rule}')
    return {
        'site': site, 'backend': backend, 'selected_ips': ips, 'expires_at': expiry.isoformat(),
        'reason': reason, 'proposal': add, 'rollback': remove,
        'review_required': True,
        'limitations': 'Check proxies, NAT, allowlists and topology. These rules do not expire automatically. No change was applied.',
    }
