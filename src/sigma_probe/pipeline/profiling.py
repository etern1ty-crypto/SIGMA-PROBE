"""Incremental IP profiles with explicit, evidence-preserving suppressions."""
from __future__ import annotations

from collections.abc import Iterable
from ipaddress import ip_address, ip_network

from ..config import Settings
from ..models.core import ActorProfile, Evidence, LogEvent
from ..validation import LimitExceeded


class ActorProfilingStage:
    def __init__(self, config: Settings) -> None:
        self.config = config
        self._allowlist = tuple(ip_network(value) for value in config.allowlist_cidrs)

    def process(self, events: Iterable[LogEvent]) -> list[ActorProfile]:
        actors: dict[str, ActorProfile] = {}
        for event in events:
            if event.source_ip not in actors:
                if len(actors) >= self.config.limits.max_actors:
                    raise LimitExceeded('max_actors exceeded')
                actors[event.source_ip] = ActorProfile(ip_address=event.source_ip)
            actors[event.source_ip].add_event(event)
        result = [actors[ip] for ip in sorted(actors)]
        for actor in result:
            actor.events.sort(key=lambda e: (e.timestamp, e.input_id, e.line_number))
            actor.suppressed = any(ip_address(actor.ip_address) in network for network in self._allowlist)
            # One pass over events, not one unbounded evidence entry per hit.
            references: dict[str, list[dict]] = {tag: [] for tag in actor.tags}
            for event in actor.events:
                for tag in sorted(event.heuristic_flags):
                    if len(references[tag]) < self.config.reporting.sample_events:
                        references[tag].append(event.reference())
            for tag in sorted(actor.tag_counts):
                actor.add_evidence(Evidence(
                    source='RequestSignatures' if tag != 'IOC_MATCH' else 'LocalIoC',
                    kind=tag, details=f'{tag}: request-level signal observed; success is not established.',
                    confidence=0.5 if tag == 'SCANNER_UA' else 0.75,
                    metrics={'matched_requests': actor.tag_counts[tag]}, references=references[tag],
                ))
            if actor.suppressed:
                actor.add_evidence(Evidence(
                    source='Allowlist', kind='suppressed',
                    details='An operator-configured IP/CIDR suppression applies; evidence remains visible.',
                    confidence=1.0,
                ))
        return result
