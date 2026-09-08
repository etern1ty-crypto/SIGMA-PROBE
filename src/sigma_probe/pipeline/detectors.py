"""Explainable temporal, behavioral and bounded correlation detectors."""
from __future__ import annotations

import hashlib
import math
import statistics
from collections import defaultdict, deque
from itertools import combinations, islice

from ..config import DetectionConfig, LimitsConfig
from ..models.core import ActorProfile, Evidence, LogEvent, PROBE_TAGS, ThreatCampaign
from ..validation import LimitExceeded
from .base import AnalysisContext


def _peak_window(events: list[LogEvent], seconds: int) -> tuple[int, list[LogEvent]]:
    """Exact maximum count in a closed time window, O(n) after sorting."""
    window: deque[LogEvent] = deque()
    peak = 0
    samples: list[LogEvent] = []
    for event in events:
        window.append(event)
        while (event.timestamp - window[0].timestamp).total_seconds() > seconds:
            window.popleft()
        if len(window) > peak:
            peak = len(window)
            samples = list(islice(window, 3))
    return peak, samples


class BehaviorDetector:
    def __init__(self, config: DetectionConfig) -> None:
        self.config = config

    def process(self, context: AnalysisContext) -> None:
        counts = {'enumeration': 0, 'auth_failure_bursts': 0, 'error_bursts': 0}
        for actor in context.actors:
            if actor.suppressed:
                continue
            error_events = [e for e in actor.events if e.status_code >= 400]
            error_paths = {e.path for e in error_events}
            if len(error_paths) >= self.config.enumeration_min_paths and actor.error_ratio >= self.config.enumeration_error_ratio:
                actor.tags.add('ENUMERATION')
                actor.add_evidence(Evidence(
                    source='BehaviorDetector', kind='ENUMERATION',
                    details='Many distinct paths returned errors; investigate automated enumeration.',
                    metrics={'distinct_error_paths': len(error_paths), 'error_ratio': round(actor.error_ratio, 4)},
                    references=[e.reference() for e in error_events[:3]],
                ))
                counts['enumeration'] += 1
            auth_events = [e for e in actor.events if e.path in self.config.login_paths and e.status_code in (401, 403)]
            for tag, candidates, threshold, counter, details in (
                ('AUTH_FAILURE_BURST', auth_events, self.config.auth_failure_threshold, 'auth_failure_bursts', 'Repeated HTTP 401/403 on configured login paths; not proof of credential stuffing.'),
                ('ERROR_BURST', error_events, self.config.error_burst_threshold, 'error_bursts', 'Burst of HTTP errors; an application fault is also possible.'),
            ):
                peak, sample = _peak_window(candidates, self.config.burst_window_seconds)
                if peak >= threshold:
                    actor.tags.add(tag)
                    actor.add_evidence(Evidence(
                        source='BehaviorDetector', kind=tag, details=details,
                        confidence=0.6, metrics={'peak_count': peak, 'window_seconds': self.config.burst_window_seconds},
                        references=[e.reference() for e in sample],
                    ))
                    counts[counter] += 1
        context.summary['behavior'] = counts


class TemporalDetector:
    """Cadence analysis, explicitly NOT FFT and NOT botnet attribution."""
    def __init__(self, config: DetectionConfig) -> None:
        self.config = config

    def process(self, context: AnalysisContext) -> None:
        rhythmic = 0
        automated_probes = 0
        for actor in context.actors:
            if actor.suppressed or len(actor.events) < self.config.temporal_min_events:
                continue
            intervals = [(b.timestamp - a.timestamp).total_seconds() for a, b in zip(actor.events, actor.events[1:])]
            mean = statistics.fmean(intervals)
            if mean <= 0:
                # Logs with only second-resolution or identical timestamps do
                # not contain enough information for a cadence claim.
                continue
            cv = statistics.pstdev(intervals) / mean
            actor.behavioral_signatures['interval_cv'] = round(cv, 6)
            actor.behavioral_signatures['mean_interval_seconds'] = round(mean, 6)
            if cv <= self.config.temporal_cv:
                rhythmic += 1
                actor.behavioral_signatures['rhythmic'] = True
                if not (actor.tags & PROBE_TAGS or 'ENUMERATION' in actor.tags or 'AUTH_FAILURE_BURST' in actor.tags):
                    continue
                actor.tags.add('AUTOMATED_SCAN')
                actor.add_evidence(Evidence(
                    source='TemporalDetector', kind='AUTOMATED_SCAN',
                    details='Low-variance request cadence coincides with probing or repeated login failures.',
                    confidence=0.65, metrics={'interval_cv': round(cv, 6), 'mean_interval_seconds': round(mean, 6)},
                    references=[e.reference() for e in actor.events[:3]],
                ))
                automated_probes += 1
        context.summary['temporal'] = {'rhythmic_actors': rhythmic, 'automated_probe_actors': automated_probes}


def cosine_similarity(left: dict[str, float], right: dict[str, float]) -> float:
    denominator = math.sqrt(sum(v * v for v in left.values()) * sum(v * v for v in right.values()))
    if not denominator:
        return 0.0
    dot = sum(value * right.get(path, 0.0) for path, value in left.items())
    return min(1.0, max(0.0, dot / denominator))


def _time_gap(a: ActorProfile, b: ActorProfile) -> float:
    if a.first_seen is None or a.last_seen is None or b.first_seen is None or b.last_seen is None:
        return math.inf
    return max(0.0, (a.first_seen - b.last_seen).total_seconds(), (b.first_seen - a.last_seen).total_seconds())


class GraphDetector:
    """Deterministic complete-link groups, not proof of a common operator.

    Only actors sharing suspicious path identities, signal families and a
    time window are eligible. Benign pages or equal-length vectors do not
    create edges. Budgets fail explicitly rather than silently sampling.
    """
    def __init__(self, config: DetectionConfig, limits: LimitsConfig) -> None:
        self.config = config
        self.limits = limits

    def process(self, context: AnalysisContext) -> None:
        summary = {'enabled': self.config.correlation_enabled, 'candidate_pairs': 0, 'pair_evaluations': 0, 'edges': 0, 'groups': 0}
        context.summary['correlation'] = summary
        if not self.config.correlation_enabled:
            return
        eligible = [a for a in context.actors if not a.suppressed and a.tags & (PROBE_TAGS | {'IOC_MATCH', 'ENUMERATION'})]
        eligible.sort(key=lambda a: a.ip_address)
        vectors: list[dict[str, float]] = []
        path_times: list[dict[str, list[float]]] = []
        index: dict[str, list[int]] = defaultdict(list)
        for position, actor in enumerate(eligible):
            counts: dict[str, float] = defaultdict(float)
            times: dict[str, list[float]] = defaultdict(list)
            for event in actor.events:
                if event.heuristic_flags & (PROBE_TAGS | {'IOC_MATCH'}) or ('ENUMERATION' in actor.tags and event.status_code >= 400):
                    counts[event.path] += 1.0
                    times[event.path].append(event.timestamp.timestamp())
            vector = dict(counts)
            vectors.append(vector)
            path_times.append(dict(times))
            for path in sorted(vector):
                index[path].append(position)
        candidates: set[tuple[int, int]] = set()
        evaluations = 0
        for path in sorted(index):
            for pair in combinations(index[path], 2):
                evaluations += 1
                if evaluations > self.limits.max_pair_evaluations:
                    raise LimitExceeded('max_pair_evaluations exceeded')
                candidates.add(pair)
                if len(candidates) > self.limits.max_candidate_pairs:
                    raise LimitExceeded('max_candidate_pairs exceeded')
        edges: set[tuple[int, int]] = set()
        signal_tags = PROBE_TAGS | {'IOC_MATCH', 'ENUMERATION'}
        for left, right in sorted(candidates):
            a, b = eligible[left], eligible[right]
            if not (a.tags & b.tags & signal_tags):
                continue
            if _time_gap(a, b) > self.config.correlation_window_seconds:
                continue
            shared_paths = vectors[left].keys() & vectors[right].keys()
            if len(shared_paths) < self.config.correlation_min_paths:
                continue
            nearby_paths = 0
            for path in sorted(shared_paths):
                times_a, times_b = path_times[left][path], path_times[right][path]
                i = j = 0
                while i < len(times_a) and j < len(times_b):
                    evaluations += 1
                    if evaluations > self.limits.max_pair_evaluations:
                        raise LimitExceeded('max_pair_evaluations exceeded during time matching')
                    delta = times_a[i] - times_b[j]
                    if abs(delta) <= self.config.correlation_window_seconds:
                        nearby_paths += 1
                        break
                    if delta < 0:
                        i += 1
                    else:
                        j += 1
                if nearby_paths >= self.config.correlation_min_paths:
                    break
            if nearby_paths < self.config.correlation_min_paths:
                continue
            # Charge sparse-vector work to the same finite evaluation budget.
            evaluations += 2 * len(vectors[left]) + len(vectors[right])
            if evaluations > self.limits.max_pair_evaluations:
                raise LimitExceeded('max_pair_evaluations exceeded during similarity evaluation')
            if cosine_similarity(vectors[left], vectors[right]) >= self.config.correlation_similarity:
                edges.add((left, right))
        # Sorted first-fit clique partition prevents connected-component
        # chaining (A~B, B~C does not imply A~C). It is deliberately not an
        # optimal maximum-clique solver, which would have unbounded cost.
        groups: list[list[int]] = []
        for node in range(len(eligible)):
            placed = False
            for group in groups:
                if len(group) >= self.config.correlation_max_cluster_size:
                    continue
                linked = True
                for member in group:
                    evaluations += 1
                    if evaluations > self.limits.max_pair_evaluations:
                        raise LimitExceeded('max_pair_evaluations exceeded during grouping')
                    if (min(member, node), max(member, node)) not in edges:
                        linked = False
                        break
                if linked:
                    group.append(node)
                    placed = True
                    break
            if not placed:
                groups.append([node])
        context.campaigns = []
        for group in groups:
            if len(group) < 2:
                continue
            actors = [eligible[node] for node in group]
            identity = '\n'.join(a.ip_address for a in actors)
            campaign_id = 'group-' + hashlib.sha256(identity.encode()).hexdigest()[:16]
            for actor in actors:
                actor.tags.add('CORRELATED_ACTIVITY')
                actor.add_evidence(Evidence(
                    source='GraphDetector', kind='CORRELATED_ACTIVITY',
                    details='Similar suspicious paths and time windows; shared ownership is not established.',
                    confidence=0.6, metrics={'group_size': len(actors), 'group_id': campaign_id},
                ))
            context.campaigns.append(ThreatCampaign(campaign_id=campaign_id, actors=actors))
        summary.update({'candidate_pairs': len(candidates), 'pair_evaluations': evaluations, 'edges': len(edges), 'groups': len(context.campaigns)})
