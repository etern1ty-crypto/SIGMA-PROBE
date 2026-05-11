"""
SIGMA-PROBE Detection Engine
Архитектура v2.0 — 'Helios'.

Each detector inspects a collection of :class:`ActorProfile` instances and
returns a ``context_update`` dict that summarises what it found. Detectors
mutate the actors in place (adding tags / evidence) and never return the
actors themselves — the caller already has them.

The accepted ``actors`` argument is intentionally permissive: it can be a
mapping keyed by IP (legacy pipeline call site) or any iterable of actors
(unit tests, ad-hoc callers).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Union

import networkx as nx
import numpy as np

from sigma_probe.models.core import ActorProfile
from sigma_probe.pipeline.base import Detector

logger = logging.getLogger(__name__)

ActorInput = Union[Dict[str, ActorProfile], Iterable[ActorProfile]]


def _normalize_actors(actors: ActorInput) -> List[ActorProfile]:
    """Accept either a dict-by-IP or any iterable and return a flat list."""
    if isinstance(actors, dict):
        return list(actors.values())
    return list(actors)


# URLs commonly probed by humans poking at a target before launching a real
# attack. Used by FFTDetector for the "manual scanning" path where the actor
# has too few events for spectral analysis but their URL pattern is itself
# suspicious.
MANUAL_SCAN_URLS = (
    "/admin",
    "/login",
    "/wp-admin",
    "/phpmyadmin",
    "/config",
    "/.env",
    "/.git",
)


class BaseDetector(Detector):
    """Common helpers for all detectors."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.config = config
        self.name = self.__class__.__name__

    def detect(
        self,
        actors: ActorInput,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Default: do nothing, return empty context update."""
        return {}

    def add_evidence(
        self,
        actor: ActorProfile,
        evidence_type: str,
        details: str,
        confidence: float = 1.0,
    ) -> None:
        actor.add_evidence(self.name, evidence_type, details, confidence)


class FFTDetector(BaseDetector):
    """Detect rhythmic (automated) and manual scanning patterns.

    The rhythmic path uses interval-of-arrival variance: actors with at
    least ``min_events_for_fft`` events whose request intervals cluster
    tightly around a single value are flagged as ``AUTOMATED_SCAN``. The
    manual path catches smaller actors whose URL set overlaps a known list
    of admin / probe paths and tags them ``MANUAL_SCAN``.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.min_events_for_fft = int(config.get("min_events_for_fft", 10))
        # Coefficient-of-variation threshold below which intervals are
        # considered rhythmic. Low CV ⇒ near-constant cadence ⇒ bot.
        self.rhythmic_cv_threshold = float(config.get("rhythmic_cv_threshold", 0.15))
        # Minimum number of suspicious URLs an actor must hit to count
        # as a manual scan.
        self.manual_scan_min_hits = int(config.get("manual_scan_min_hits", 3))

    def detect(
        self,
        actors: ActorInput,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        actor_list = _normalize_actors(actors)
        rhythmic = 0
        manual = 0

        for actor in actor_list:
            event_count = len(actor.events)

            if event_count >= self.min_events_for_fft:
                timestamps = sorted(e.timestamp.timestamp() for e in actor.events)
                intervals = np.diff(np.asarray(timestamps, dtype=float))
                if intervals.size and intervals.mean() > 0:
                    cv = float(intervals.std() / intervals.mean())
                    if cv < self.rhythmic_cv_threshold:
                        actor.add_tag("AUTOMATED_SCAN", self.name)
                        self.add_evidence(
                            actor,
                            "rhythmic_pattern",
                            f"Near-constant request interval (cv={cv:.3f})",
                            confidence=0.9,
                        )
                        rhythmic += 1
                        continue

            # Manual scanning path: small number of events targeting known
            # admin paths.
            hits = sum(
                1
                for event in actor.events
                if any(path in event.url.lower() for path in MANUAL_SCAN_URLS)
            )
            if hits >= self.manual_scan_min_hits:
                actor.add_tag("MANUAL_SCAN", self.name)
                self.add_evidence(
                    actor,
                    "manual_scan",
                    f"Probed {hits} known admin/config paths",
                    confidence=0.7,
                )
                manual += 1

        return {
            "fft_summary": {
                "total_actors": len(actor_list),
                "total_rhythmic_actors": rhythmic,
                "total_manual_actors": manual,
            }
        }


class GraphDetector(BaseDetector):
    """Coordination-via-similarity detector.

    Builds an undirected actor graph weighted by behavioural similarity
    (URL overlap + timing + user agent), then tags actors using standard
    centrality / clustering metrics.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.similarity_threshold = float(config.get("similarity_threshold", 0.3))
        self.centrality_threshold = float(config.get("centrality_threshold", 0.3))
        self.clustering_threshold = float(config.get("clustering_threshold", 0.5))

    def detect(
        self,
        actors: ActorInput,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        actor_list = _normalize_actors(actors)
        if len(actor_list) < 2:
            return {}

        graph = self._build_actor_graph(actor_list)
        centrality_scores = nx.betweenness_centrality(graph) if graph.number_of_nodes() else {}
        clustering_coeffs = nx.clustering(graph) if graph.number_of_nodes() else {}

        coordinators = 0
        cluster_members = 0
        centralities: List[float] = []

        for actor in actor_list:
            ip = actor.ip_address
            centrality = float(centrality_scores.get(ip, 0.0))
            clustering = float(clustering_coeffs.get(ip, 0.0))
            actor.centrality = centrality
            centralities.append(centrality)

            if centrality > self.centrality_threshold and clustering < self.clustering_threshold:
                coordinators += 1
                actor.add_tag("COORDINATOR", self.name)
                self.add_evidence(
                    actor,
                    "coordinator_detected",
                    f"High centrality ({centrality:.3f}), low clustering ({clustering:.3f})",
                    confidence=0.7,
                )
            elif clustering > self.clustering_threshold:
                cluster_members += 1
                actor.add_tag("CLUSTER_MEMBER", self.name)
                self.add_evidence(
                    actor,
                    "cluster_member_detected",
                    f"High clustering coefficient ({clustering:.3f})",
                    confidence=0.6,
                )

        return {
            "graph_summary": {
                "total_actors": len(actor_list),
                "coordinators": coordinators,
                "cluster_members": cluster_members,
                "avg_centrality": float(np.mean(centralities)) if centralities else 0.0,
            }
        }

    def _build_actor_graph(self, actors: List[ActorProfile]) -> nx.Graph:
        graph = nx.Graph()
        for actor in actors:
            graph.add_node(actor.ip_address)

        for i, actor1 in enumerate(actors):
            for actor2 in actors[i + 1:]:
                similarity = self._behavioural_similarity(actor1, actor2)
                if similarity > self.similarity_threshold:
                    graph.add_edge(
                        actor1.ip_address, actor2.ip_address, weight=similarity
                    )
        return graph

    @staticmethod
    def _behavioural_similarity(a: ActorProfile, b: ActorProfile) -> float:
        urls_a = {event.url for event in a.events}
        urls_b = {event.url for event in b.events}
        if not urls_a or not urls_b:
            return 0.0
        url_jaccard = len(urls_a & urls_b) / len(urls_a | urls_b)

        ua_a = {event.user_agent for event in a.events if event.user_agent}
        ua_b = {event.user_agent for event in b.events if event.user_agent}
        if ua_a and ua_b:
            ua_jaccard = len(ua_a & ua_b) / len(ua_a | ua_b)
        else:
            ua_jaccard = 0.0

        return 0.7 * url_jaccard + 0.3 * ua_jaccard


class AnomalyDetector(BaseDetector):
    """Flag actors whose behaviour stands out from the population.

    For each actor we combine two signals:

    1. Any pre-existing ``actor.anomaly_ratio`` (set by an upstream stage).
    2. A z-score blend across entropy / URL diversity / request count /
       centrality computed against the rest of the population.

    The final value is used to drive the ``ANOMALOUS`` / ``SUSPICIOUS``
    tags via configured thresholds.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.anomaly_threshold = float(config.get("anomaly_threshold", 0.7))
        self.suspicious_threshold = float(config.get("suspicious_threshold", 0.4))

    def detect(
        self,
        actors: ActorInput,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        actor_list = _normalize_actors(actors)
        if len(actor_list) < 2:
            return {}

        baseline = self._calculate_baseline(actor_list)
        anomalies = 0
        suspicious = 0

        for actor in actor_list:
            computed_score = self._z_score_blend(actor, baseline)
            score = max(actor.anomaly_ratio, computed_score)
            actor.anomaly_ratio = score

            if score >= self.anomaly_threshold:
                anomalies += 1
                actor.add_tag("ANOMALOUS", self.name)
                self.add_evidence(
                    actor,
                    "anomaly_detected",
                    f"Anomaly score {score:.3f}",
                    confidence=0.8,
                )
            elif score >= self.suspicious_threshold:
                suspicious += 1
                actor.add_tag("SUSPICIOUS", self.name)
                self.add_evidence(
                    actor,
                    "suspicious_behavior",
                    f"Anomaly score {score:.3f}",
                    confidence=0.6,
                )

        return {
            "anomaly_summary": {
                "total_actors": len(actor_list),
                "anomalies": anomalies,
                "suspicious": suspicious,
                "anomaly_rate": anomalies / len(actor_list) if actor_list else 0.0,
            }
        }

    @staticmethod
    def _calculate_baseline(actors: List[ActorProfile]) -> Dict[str, float]:
        baseline: Dict[str, float] = {}
        for attr in ("avg_entropy", "url_diversity_ratio", "total_requests", "centrality"):
            values = np.asarray([getattr(actor, attr) for actor in actors], dtype=float)
            baseline[f"{attr}_mean"] = float(values.mean())
            baseline[f"{attr}_std"] = float(values.std())
        return baseline

    @staticmethod
    def _z_score_blend(actor: ActorProfile, baseline: Dict[str, float]) -> float:
        scores: List[float] = []
        for attr in ("avg_entropy", "url_diversity_ratio", "total_requests", "centrality"):
            std = baseline[f"{attr}_std"]
            if std <= 0:
                continue
            mean = baseline[f"{attr}_mean"]
            z = abs(getattr(actor, attr) - mean) / std
            scores.append(min(z / 3.0, 1.0))
        return float(np.mean(scores)) if scores else 0.0


class BehavioralClusteringDetector(BaseDetector):
    """Cluster actors by their behavioural vector (URL frequency profile).

    Uses cosine similarity via 1 - cosine distance over normalised URL
    frequency vectors and produces a simple ``clustering_summary``.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.similarity_threshold = float(config.get("similarity_threshold", 0.6))

    def detect(
        self,
        actors: ActorInput,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        actor_list = _normalize_actors(actors)
        if len(actor_list) < 2:
            return {}

        vectors = []
        owners = []
        for actor in actor_list:
            vec = actor.get_behavioral_vector()
            if vec and sum(vec) > 0:
                vectors.append(np.asarray(vec, dtype=float))
                owners.append(actor)

        if len(vectors) < 2:
            return {}

        clusters: List[List[ActorProfile]] = []
        assigned = [False] * len(vectors)
        for i in range(len(vectors)):
            if assigned[i]:
                continue
            cluster = [owners[i]]
            assigned[i] = True
            for j in range(i + 1, len(vectors)):
                if assigned[j]:
                    continue
                if self._cosine_similarity(vectors[i], vectors[j]) >= self.similarity_threshold:
                    cluster.append(owners[j])
                    assigned[j] = True
            clusters.append(cluster)

        largest = max((len(c) for c in clusters), default=0)
        for cluster in clusters:
            if len(cluster) >= 2:
                for actor in cluster:
                    actor.add_tag("CLUSTER_MEMBER", self.name)

        return {
            "clustering_summary": {
                "total_clusters": len(clusters),
                "largest_cluster": largest,
            }
        }

    @staticmethod
    def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
        denom = float(np.linalg.norm(a) * np.linalg.norm(b))
        if denom == 0:
            return 0.0
        return float(np.dot(a, b) / denom)
