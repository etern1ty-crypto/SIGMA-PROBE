"""Local, bounded IoC snapshots. This module never opens a network socket."""
from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

from ..config import IoCConfig
from ..models.core import LogEvent
from ..validation import LimitExceeded, SigmaProbeError, text
from ..pipeline.enrichment import normalized_path


@dataclass(slots=True)
class _Feed:
    name: str
    type: str
    sha256: str
    entries: int
    expires_at: str | None
    networks: dict[tuple[int, int], set[int]] = field(default_factory=dict)
    paths: set[str] = field(default_factory=set)
    agents: tuple[str, ...] = ()

    def matches(self, event: LogEvent) -> bool:
        if self.type == 'ip':
            address = ip_address(event.source_ip)
            bits = address.max_prefixlen
            value = int(address)
            for (version, prefix), networks in self.networks.items():
                if version == address.version and (value >> (bits - prefix)) in networks:
                    return True
            return False
        if self.type == 'url_path':
            return event.path in self.paths
        agent = event.user_agent.casefold()
        return any(pattern in agent for pattern in self.agents)


class IoCManager:
    def __init__(self, config: IoCConfig, now: datetime | None = None) -> None:
        self.config = config
        self.feeds: list[_Feed] = []
        self.matched_events = 0
        self.feed_matches: Counter[str] = Counter()
        if not config.enabled:
            return
        current = now or datetime.now(timezone.utc)
        for item in config.files:
            if item.expires_at is not None and current >= item.expires_at:
                raise SigmaProbeError(f'IoC feed {item.name} has expired; provide a reviewed fresh snapshot')
            path = Path(item.path)
            if not path.is_file():
                raise SigmaProbeError(f'IoC feed {item.name} must be a regular file')
            with path.open('rb') as handle:
                raw = handle.read(config.max_file_bytes + 1)
            if len(raw) > config.max_file_bytes:
                raise LimitExceeded(f'IoC feed {item.name}: max_file_bytes exceeded')
            try:
                lines = raw.decode('utf-8-sig').splitlines()
            except UnicodeError as exc:
                raise SigmaProbeError(f'IoC feed {item.name} is not valid UTF-8') from exc
            values = {line.strip() for line in lines if line.strip() and not line.lstrip().startswith('#')}
            if not values:
                raise SigmaProbeError(f'IoC feed {item.name} contains no indicators')
            if len(values) > config.max_entries:
                raise LimitExceeded(f'IoC feed {item.name}: max_entries exceeded')
            feed = _Feed(item.name, item.type, hashlib.sha256(raw).hexdigest(), len(values), item.expires_at.isoformat() if item.expires_at else None)
            for value in sorted(values):
                text(value, f'IoC {item.name} indicator', 2048)
                if item.type == 'ip':
                    try:
                        if '%' in value:
                            raise ValueError('Scope is not supported')
                        network = ip_network(value, strict=False)
                    except ValueError as exc:
                        raise SigmaProbeError(f'IoC feed {item.name}: invalid IP/CIDR') from exc
                    key = (network.version, network.prefixlen)
                    network_value = int(network.network_address) >> (network.max_prefixlen - network.prefixlen)
                    feed.networks.setdefault(key, set()).add(network_value)
                elif item.type == 'url_path':
                    if not value.startswith('/') or '?' in value or '#' in value:
                        raise SigmaProbeError(f'IoC feed {item.name}: expected an absolute path without query/fragment')
                    feed.paths.add(normalized_path(value))
            if item.type == 'user_agent':
                if len(values) > 128 or any(not 6 <= len(value) <= 256 for value in values):
                    raise SigmaProbeError(f'IoC feed {item.name}: maximum 128 literal UA patterns, each 6..256 characters')
                feed.agents = tuple(sorted(value.casefold() for value in values))
            self.feeds.append(feed)

    def enrich_event(self, event: LogEvent) -> LogEvent:
        matches = [feed.name for feed in self.feeds if feed.matches(event)]
        if matches:
            event.heuristic_flags.add('IOC_MATCH')
            event.ioc_feeds.update(matches)
            self.matched_events += 1
            self.feed_matches.update(matches)
        return event

    def get_stats(self) -> dict[str, Any]:
        return {
            'enabled': self.config.enabled, 'matched_events': self.matched_events,
            'feeds': [
                {'name': feed.name, 'type': feed.type, 'entries': feed.entries,
                 'sha256': feed.sha256, 'expires_at': feed.expires_at,
                 'matched_events': self.feed_matches[feed.name]}
                for feed in self.feeds
            ],
        }
