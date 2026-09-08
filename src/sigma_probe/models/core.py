"""Domain objects. Runtime validation uses only the Python standard library."""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from ..validation import SigmaProbeError, canonical_ip, integer, number, text, utc_datetime

PAYLOAD_TAGS = frozenset({'LFI_RFI', 'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION'})
PROBE_TAGS = PAYLOAD_TAGS | {'SENSITIVE_PATH'}
BEHAVIOR_TAGS = frozenset({'ENUMERATION', 'AUTOMATED_SCAN', 'AUTH_FAILURE_BURST', 'ERROR_BURST'})


@dataclass(slots=True)
class LogEvent:
    timestamp: datetime
    source_ip: str
    url: str
    method: str
    status_code: int
    user_agent: str = ''
    host: str | None = None
    response_size: int = 0
    input_id: str = 'input-1'
    line_number: int = 1
    path: str = ''
    entropy: float = 0.0
    heuristic_flags: set[str] = field(default_factory=set)
    ioc_feeds: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.timestamp = utc_datetime(self.timestamp)
        self.source_ip = canonical_ip(self.source_ip)
        self.url = text(self.url, 'url', 16_384)
        if not (self.url.startswith('/') or self.url.startswith(('http://', 'https://')) or self.url == '*'):
            raise SigmaProbeError('url: expected origin-form, absolute HTTP(S) URL, or *')
        if self.url.startswith(('http://', 'https://')):
            try:
                if not urlsplit(self.url).hostname:
                    raise ValueError('Missing hostname')
            except ValueError as exc:
                raise SigmaProbeError('url: malformed absolute URL') from exc
        if self.host is not None:
            self.host = text(self.host, 'host', 255).casefold().rstrip('.')
        self.method = text(self.method, 'method', 32).upper()
        if not re.fullmatch(r"[A-Z!#$%&'*+.^_`|~-]+", self.method):
            raise SigmaProbeError('method: invalid HTTP method token')
        integer(self.status_code, 'status_code', 100, 599)
        integer(self.response_size, 'response_size', 0, 2**63 - 1)
        text(self.user_agent, 'user_agent', 4096, empty=True)
        if not re.fullmatch(r'input-[1-9][0-9]*', self.input_id):
            raise SigmaProbeError('input_id must be input-N')
        integer(self.line_number, 'line_number', 1, 2**63 - 1)

    def reference(self) -> dict[str, Any]:
        return {
            'input_id': self.input_id, 'line': self.line_number,
            'timestamp': self.timestamp.isoformat(), 'method': self.method,
            'url': self.url, 'status_code': self.status_code,
            'ioc_feeds': sorted(self.ioc_feeds),
        }


@dataclass(slots=True)
class Evidence:
    source: str
    kind: str
    details: str
    confidence: float = 0.7
    metrics: dict[str, int | float | str] = field(default_factory=dict)
    references: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        text(self.source, 'evidence.source', 64)
        text(self.kind, 'evidence.kind', 64)
        text(self.details, 'evidence.details', 1024)
        number(self.confidence, 'evidence.confidence', 0, 1)
        for value in self.metrics.values():
            if isinstance(value, float) and not math.isfinite(value):
                raise SigmaProbeError('Evidence metrics must be finite')


@dataclass(slots=True)
class ActorProfile:
    ip_address: str
    events: list[LogEvent] = field(default_factory=list)
    total_requests: int = 0
    total_response_bytes: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    path_counts: Counter[str] = field(default_factory=Counter)
    status_counts: Counter[int] = field(default_factory=Counter)
    tag_counts: Counter[str] = field(default_factory=Counter)
    tags: set[str] = field(default_factory=set)
    evidence_trail: list[Evidence] = field(default_factory=list)
    threat_score: int = 0
    severity: str = 'info'
    score_breakdown: dict[str, int] = field(default_factory=dict)
    suppressed: bool = False
    mitre_techniques: list[dict[str, str]] = field(default_factory=list)
    behavioral_signatures: dict[str, Any] = field(default_factory=dict)
    _entropy_sum: float = 0.0
    _max_entropy: float = 0.0

    def __post_init__(self) -> None:
        self.ip_address = canonical_ip(self.ip_address)
        initial = list(self.events)
        self.events = []
        for event in initial:
            self.add_event(event)

    @property
    def unique_urls(self) -> int:
        return len(self.path_counts)

    @property
    def avg_entropy(self) -> float:
        return self._entropy_sum / self.total_requests if self.total_requests else 0.0

    @property
    def max_entropy(self) -> float:
        return self._max_entropy

    @property
    def url_diversity_ratio(self) -> float:
        return self.unique_urls / self.total_requests if self.total_requests else 0.0

    @property
    def error_ratio(self) -> float:
        return sum(n for status, n in self.status_counts.items() if status >= 400) / max(1, self.total_requests)

    def add_event(self, event: LogEvent) -> None:
        """O(1) aggregate update; feature extraction must precede ingestion here."""
        if event.source_ip != self.ip_address:
            raise SigmaProbeError('Cannot add an event belonging to a different IP')
        if not event.path:
            raise SigmaProbeError('Event must be enriched before profiling')
        self.events.append(event)
        self.total_requests += 1
        self.total_response_bytes += event.response_size
        self.path_counts[event.path] += 1
        self.status_counts[event.status_code] += 1
        self.tag_counts.update(event.heuristic_flags)
        self.tags.update(event.heuristic_flags)
        self._entropy_sum += event.entropy
        self._max_entropy = max(self._max_entropy, event.entropy)
        self.first_seen = min(self.first_seen, event.timestamp) if self.first_seen else event.timestamp
        self.last_seen = max(self.last_seen, event.timestamp) if self.last_seen else event.timestamp

    def add_evidence(self, evidence: Evidence) -> None:
        # Idempotent per source/kind: repeated scoring/detection must not grow
        # evidence forever or change the report's meaning.
        for index, existing in enumerate(self.evidence_trail):
            if (existing.source, existing.kind) == (evidence.source, evidence.kind):
                self.evidence_trail[index] = evidence
                return
        self.evidence_trail.append(evidence)

    def get_behavioral_vector(self) -> dict[str, float]:
        """Sparse coordinates retain path identity; no unrelated top-N ranks."""
        denominator = max(self.total_requests, 1)
        return {path: count / denominator for path, count in sorted(self.path_counts.items())}


@dataclass(slots=True)
class ThreatCampaign:
    campaign_id: str
    actors: list[ActorProfile]
    threat_score: float = 0.0
    primary_tags: list[str] = field(default_factory=list)
    campaign_type: str = 'correlated_activity'
    mitre_techniques: list[dict[str, str]] = field(default_factory=list)

    def update_metrics(self) -> None:
        self.threat_score = round(sum(a.threat_score for a in self.actors) / len(self.actors), 2) if self.actors else 0.0
        self.primary_tags = sorted({tag for actor in self.actors for tag in actor.tags})


@dataclass(slots=True)
class InputFileStats:
    input_id: str
    name: str
    sha256: str = ''
    bytes_read: int = 0
    lines: int = 0
    blank: int = 0
    invalid: int = 0
    filtered: int = 0
    accepted: int = 0


@dataclass(slots=True)
class IngestionStats:
    sources: list[InputFileStats] = field(default_factory=list)
    errors: list[dict[str, int | str]] = field(default_factory=list)

    def total(self, name: str) -> int:
        return sum(getattr(source, name) for source in self.sources)

    @property
    def partial(self) -> bool:
        return self.total('invalid') > 0


@dataclass(slots=True)
class Recommendation:
    id: str
    priority: str
    title: str
    actor_ids: list[str]
    action_items: list[str]
    rationale: str


@dataclass(slots=True)
class AnalysisResult:
    site: str
    actors: list[ActorProfile]
    campaigns: list[ThreatCampaign]
    recommendations: list[Recommendation]
    ingestion: IngestionStats
    detector_summary: dict[str, Any]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    elapsed_seconds: float = 0.0
    report_paths: dict[str, str] = field(default_factory=dict)
    report: dict[str, Any] = field(default_factory=dict)
