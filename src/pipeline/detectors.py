"""
SIGMA-PROBE Detection Engine
Архитектура v2.0 - 'Helios'

Принцип 2: Детекторы — это не просто анализаторы, это "глаза" системы.
"""

import numpy as np
from scipy.fft import fft
from scipy.spatial.distance import cosine
import networkx as nx
from typing import Dict, List, Any, Optional
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import logging
from scipy import signal
from scipy.stats import entropy

from ..models.core import ActorProfile, LogEvent
from ..pipeline.base import BaseDetector

logger = logging.getLogger(__name__)

class BaseDetector:
    """Base class for all detectors"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
    
    def detect(self, actors: List[ActorProfile], context: Dict[str, Any]) -> Dict[str, Any]:
        """Detect patterns and return context updates"""
        raise NotImplementedError
    
    def add_evidence(self, actor: ActorProfile, evidence_type: str, details: str, confidence: float = 1.0) -> None:
        """Add evidence to actor's trail"""
        actor.add_evidence(self.name, evidence_type, details, confidence)

class FFTDetector(BaseDetector):
    """Enhanced FFT detector with adaptive temporal analysis for sophisticated bots."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.min_peaks = config.get('min_peaks', 3)
        self.peak_threshold = config.get('peak_threshold', 0.1)
        self.autocorr_threshold = config.get('autocorr_threshold', 0.3)
        self.window_size = config.get('window_size', 600)  # 10 minutes in seconds
        self.change_threshold = config.get('change_threshold', 5.0)  # 5x change in frequency
        
    def detect(self, actors: List[ActorProfile], context: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced detection with multiple temporal analysis methods."""
        for actor in actors:
            if len(actor.events) < 10:  # Need sufficient data
                continue
                
            # Extract timestamps and calculate intervals
            timestamps = [event.timestamp.timestamp() for event in actor.events]
            intervals = np.diff(sorted(timestamps))
            
            if len(intervals) < 5:
                continue
                
            # Method 1: Traditional FFT analysis
            fft_score, fft_evidence = self._analyze_fft(intervals)
            
            # Method 2: Autocorrelation analysis
            autocorr_score, autocorr_evidence = self._analyze_autocorrelation(intervals)
            
            # Method 3: Windowed change analysis
            window_score, window_evidence = self._analyze_windowed_changes(timestamps)
            
            # Combine evidence and determine final score
            total_score = max(fft_score, autocorr_score, window_score)
            combined_evidence = fft_evidence + autocorr_evidence + window_evidence
            
            if total_score > 0.5:
                actor.tags.add('BOT_ACTIVITY')
                actor.evidence_trail.extend(combined_evidence)
                logger.info(f"FFTDetector: Actor {actor.ip} flagged as bot (score: {total_score:.2f})")
                
        return {}
    
    def _analyze_fft(self, intervals: np.ndarray) -> tuple[float, List[Dict]]:
        """Traditional FFT analysis for periodic patterns."""
        try:
            # Apply FFT
            fft_result = np.fft.fft(intervals)
            fft_magnitude = np.abs(fft_result)
            
            # Find peaks in frequency domain
            peaks, _ = signal.find_peaks(fft_magnitude[:len(fft_magnitude)//2])
            
            if len(peaks) >= self.min_peaks:
                max_peak = np.max(fft_magnitude[peaks])
                if max_peak > self.peak_threshold * np.max(fft_magnitude):
                    return 0.8, [{
                        'source': 'FFTDetector',
                        'confidence': 0.8,
                        'description': f'Detected {len(peaks)} periodic patterns in request intervals'
                    }]
            
            return 0.0, []
        except Exception as e:
            logger.error(f"FFT analysis error: {e}")
            return 0.0, []
    
    def _analyze_autocorrelation(self, intervals: np.ndarray) -> tuple[float, List[Dict]]:
        """Autocorrelation analysis for non-strict periodic patterns."""
        try:
            # Calculate autocorrelation
            autocorr = np.correlate(intervals, intervals, mode='full')
            autocorr = autocorr[len(autocorr)//2:]
            
            # Normalize
            autocorr = autocorr / autocorr[0]
            
            # Look for significant correlations beyond lag 1
            significant_lags = np.where(autocorr[1:20] > self.autocorr_threshold)[0]
            
            if len(significant_lags) > 0:
                return 0.7, [{
                    'source': 'FFTDetector',
                    'confidence': 0.7,
                    'description': f'Detected autocorrelation at lags {significant_lags[:3].tolist()}'
                }]
            
            return 0.0, []
        except Exception as e:
            logger.error(f"Autocorrelation analysis error: {e}")
            return 0.0, []
    
    def _analyze_windowed_changes(self, timestamps: List[float]) -> tuple[float, List[Dict]]:
        """Analyze frequency changes across time windows."""
        try:
            if len(timestamps) < self.window_size * 2:
                return 0.0, []
            
            # Create time windows
            start_time = min(timestamps)
            end_time = max(timestamps)
            window_count = int((end_time - start_time) / self.window_size)
            
            if window_count < 2:
                return 0.0, []
            
            window_frequencies = []
            for i in range(window_count):
                window_start = start_time + i * self.window_size
                window_end = window_start + self.window_size
                
                # Count events in window
                events_in_window = sum(1 for ts in timestamps if window_start <= ts < window_end)
                frequency = events_in_window / self.window_size
                window_frequencies.append(frequency)
            
            # Calculate frequency changes between consecutive windows
            frequency_changes = np.diff(window_frequencies)
            max_change = np.max(np.abs(frequency_changes))
            
            if max_change > self.change_threshold:
                return 0.9, [{
                    'source': 'FFTDetector',
                    'confidence': 0.9,
                    'description': f'Detected dramatic frequency change: {max_change:.2f}x between windows'
                }]
            
            return 0.0, []
        except Exception as e:
            logger.error(f"Windowed analysis error: {e}")
            return 0.0, []

class GraphDetector(BaseDetector):
    """Graph-based detector for coordinated attacks"""
    
    def detect(self, actors: List[ActorProfile], context: Dict[str, Any]) -> Dict[str, Any]:
        """Detect coordinated patterns using graph analysis"""
        logger.info(f"Running graph detection on {len(actors)} actors")
        
        if len(actors) < 2:
            return {}
        
        # Build actor graph
        G = self._build_actor_graph(actors)
        
        # Calculate centrality metrics
        centrality_scores = nx.betweenness_centrality(G)
        clustering_coeffs = nx.clustering(G)
        
        # Detect coordinators and clusters
        coordinators = 0
        clusters = 0
        
        for actor in actors:
            ip = actor.ip_address
            centrality = centrality_scores.get(ip, 0.0)
            clustering = clustering_coeffs.get(ip, 0.0)
            
            actor.centrality = centrality
            
            # Detect coordinators (high centrality, low clustering)
            if centrality > 0.3 and clustering < 0.3:
                coordinators += 1
                actor.add_tag('COORDINATOR', self.name)
                self.add_evidence(
                    actor,
                    "coordinator_detected",
                    f"High centrality ({centrality:.3f}), low clustering ({clustering:.3f})",
                    0.7
                )
            
            # Detect cluster members (high clustering)
            elif clustering > 0.5:
                clusters += 1
                actor.add_tag('CLUSTER_MEMBER', self.name)
                self.add_evidence(
                    actor,
                    "cluster_member_detected",
                    f"High clustering coefficient ({clustering:.3f})",
                    0.6
                )
        
        # Detect community structure
        communities = list(nx.community.greedy_modularity_communities(G))
        
        context_update = {
            'graph_summary': {
                'total_actors': len(actors),
                'coordinators': coordinators,
                'cluster_members': clusters,
                'communities': len(communities),
                'avg_centrality': np.mean(list(centrality_scores.values())),
                'detector': self.name
            }
        }
        
        logger.info(f"Graph detection complete: {coordinators} coordinators, {clusters} cluster members")
        return context_update
    
    def _build_actor_graph(self, actors: List[ActorProfile]) -> nx.Graph:
        """Build graph of actors based on behavioral similarity"""
        G = nx.Graph()
        
        # Add nodes
        for actor in actors:
            G.add_node(actor.ip_address)
        
        # Add edges based on behavioral similarity
        for i, actor1 in enumerate(actors):
            for j, actor2 in enumerate(actors[i+1:], i+1):
                similarity = self._calculate_behavioral_similarity(actor1, actor2)
                
                if similarity > 0.3:  # Threshold for edge creation
                    G.add_edge(actor1.ip_address, actor2.ip_address, weight=similarity)
        
        return G
    
    def _calculate_behavioral_similarity(self, actor1: ActorProfile, actor2: ActorProfile) -> float:
        """Calculate behavioral similarity between two actors"""
        # URL overlap
        urls1 = set(event.url for event in actor1.events)
        urls2 = set(event.url for event in actor2.events)
        
        if not urls1 or not urls2:
            return 0.0
        
        url_overlap = len(urls1.intersection(urls2)) / len(urls1.union(urls2))
        
        # Timing similarity
        timing_similarity = self._calculate_timing_similarity(actor1, actor2)
        
        # User agent similarity
        ua_similarity = self._calculate_ua_similarity(actor1, actor2)
        
        # Weighted combination
        similarity = 0.5 * url_overlap + 0.3 * timing_similarity + 0.2 * ua_similarity
        
        return similarity
    
    def _calculate_timing_similarity(self, actor1: ActorProfile, actor2: ActorProfile) -> float:
        """Calculate timing similarity between actors"""
        if not actor1.events or not actor2.events:
            return 0.0
        
        # Compare request intervals
        intervals1 = self._get_request_intervals(actor1.events)
        intervals2 = self._get_request_intervals(actor2.events)
        
        if not intervals1 or not intervals2:
            return 0.0
        
        # Compare average intervals
        avg1 = np.mean(intervals1)
        avg2 = np.mean(intervals2)
        
        if avg1 == 0 or avg2 == 0:
            return 0.0
        
        # Normalized difference
        diff = abs(avg1 - avg2) / max(avg1, avg2)
        return 1.0 - min(diff, 1.0)
    
    def _get_request_intervals(self, events: List[LogEvent]) -> List[float]:
        """Get intervals between consecutive requests"""
        timestamps = [event.timestamp.timestamp() for event in events]
        timestamps.sort()
        
        intervals = []
        for i in range(len(timestamps) - 1):
            interval = timestamps[i+1] - timestamps[i]
            if interval > 0:
                intervals.append(interval)
        
        return intervals
    
    def _calculate_ua_similarity(self, actor1: ActorProfile, actor2: ActorProfile) -> float:
        """Calculate user agent similarity"""
        ua1 = set(event.user_agent for event in actor1.events if event.user_agent)
        ua2 = set(event.user_agent for event in actor2.events if event.user_agent)
        
        if not ua1 or not ua2:
            return 0.0
        
        intersection = len(ua1.intersection(ua2))
        union = len(ua1.union(ua2))
        
        return intersection / union if union > 0 else 0.0

class AnomalyDetector(BaseDetector):
    """Anomaly detector for unusual behavior patterns"""
    
    def detect(self, actors: List[ActorProfile], context: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalous behavior patterns"""
        logger.info(f"Running anomaly detection on {len(actors)} actors")
        
        if len(actors) < 3:  # Need multiple actors for comparison
            return {}
        
        # Calculate baseline metrics
        baseline_metrics = self._calculate_baseline_metrics(actors)
        
        anomalies = 0
        for actor in actors:
            anomaly_score = self._calculate_anomaly_score(actor, baseline_metrics)
            actor.anomaly_ratio = anomaly_score
            
            if anomaly_score > 0.7:  # High anomaly threshold
                anomalies += 1
                actor.add_tag('ANOMALOUS', self.name)
                self.add_evidence(
                    actor,
                    "anomaly_detected",
                    f"High anomaly score: {anomaly_score:.3f}",
                    0.8
                )
            elif anomaly_score > 0.4:  # Medium anomaly
                actor.add_tag('SUSPICIOUS', self.name)
                self.add_evidence(
                    actor,
                    "suspicious_behavior",
                    f"Medium anomaly score: {anomaly_score:.3f}",
                    0.6
                )
        
        context_update = {
            'anomaly_summary': {
                'total_actors': len(actors),
                'anomalies': anomalies,
                'anomaly_rate': anomalies / len(actors) if actors else 0.0,
                'detector': self.name
            }
        }
        
        logger.info(f"Anomaly detection complete: {anomalies} anomalous actors")
        return context_update
    
    def _calculate_baseline_metrics(self, actors: List[ActorProfile]) -> Dict[str, float]:
        """Calculate baseline metrics from all actors"""
        metrics = {
            'avg_entropy': [],
            'url_diversity': [],
            'request_count': [],
            'avg_centrality': []
        }
        
        for actor in actors:
            metrics['avg_entropy'].append(actor.avg_entropy)
            metrics['url_diversity'].append(actor.url_diversity_ratio)
            metrics['request_count'].append(actor.total_requests)
            metrics['avg_centrality'].append(actor.centrality)
        
        baseline = {}
        for key, values in metrics.items():
            if values:
                baseline[f'{key}_mean'] = np.mean(values)
                baseline[f'{key}_std'] = np.std(values)
        
        return baseline
    
    def _calculate_anomaly_score(self, actor: ActorProfile, baseline: Dict[str, float]) -> float:
        """Calculate anomaly score for an actor"""
        scores = []
        
        # Entropy anomaly
        if 'avg_entropy_mean' in baseline and 'avg_entropy_std' in baseline:
            entropy_z = abs(actor.avg_entropy - baseline['avg_entropy_mean']) / baseline['avg_entropy_std']
            scores.append(min(entropy_z / 3.0, 1.0))  # Cap at 1.0
        
        # URL diversity anomaly
        if 'url_diversity_mean' in baseline and 'url_diversity_std' in baseline:
            diversity_z = abs(actor.url_diversity_ratio - baseline['url_diversity_mean']) / baseline['url_diversity_std']
            scores.append(min(diversity_z / 3.0, 1.0))
        
        # Request count anomaly
        if 'request_count_mean' in baseline and 'request_count_std' in baseline:
            count_z = abs(actor.total_requests - baseline['request_count_mean']) / baseline['request_count_std']
            scores.append(min(count_z / 3.0, 1.0))
        
        # Centrality anomaly
        if 'avg_centrality_mean' in baseline and 'avg_centrality_std' in baseline:
            centrality_z = abs(actor.centrality - baseline['avg_centrality_mean']) / baseline['avg_centrality_std']
            scores.append(min(centrality_z / 3.0, 1.0))
        
        return np.mean(scores) if scores else 0.0

class BehavioralClusteringDetector(BaseDetector):
    """Detector for clustering actors based on behavioral vectors"""
    
    def detect(self, actors: List[ActorProfile], context: Dict[str, Any]) -> Dict[str, Any]:
        """Cluster actors based on behavioral similarity"""
        logger.info(f"Running behavioral clustering on {len(actors)} actors")
        
        if len(actors) < 2:
            return {}
        
        # Extract behavioral vectors
        behavioral_vectors = []
        valid_actors = []
        
        for actor in actors:
            vector = actor.get_behavioral_vector()
            if vector and sum(vector) > 0:  # Only include actors with meaningful behavior
                behavioral_vectors.append(vector)
                valid_actors.append(actor)
        
        if len(behavioral_vectors) < 2:
            return {}
        
        # Normalize vectors
        vectors_array = np.array(behavioral_vectors)
        scaler = StandardScaler()
        normalized_vectors = scaler.fit_transform(vectors_array)
        
        # Perform clustering
        clustering = DBSCAN(eps=0.5, min_samples=2)
        cluster_labels = clustering.fit_predict(normalized_vectors)
        
        # Process clusters
        clusters = {}
        for i, (actor, label) in enumerate(zip(valid_actors, cluster_labels)):
            if label >= 0:  # Valid cluster
                if label not in clusters:
                    clusters[label] = []
                clusters[label].append(actor)
        
        # Tag actors based on cluster characteristics
        for cluster_id, cluster_actors in clusters.items():
            if len(cluster_actors) >= 3:
                # Large coordinated cluster
                for actor in cluster_actors:
                    actor.add_tag('COORDINATED_ATTACK', self.name)
                    self.add_evidence(
                        actor,
                        "coordinated_attack_detected",
                        f"Part of coordinated cluster {cluster_id} with {len(cluster_actors)} actors",
                        0.8
                    )
            elif len(cluster_actors) == 2:
                # Small coordinated pair
                for actor in cluster_actors:
                    actor.add_tag('PAIRED_ATTACK', self.name)
                    self.add_evidence(
                        actor,
                        "paired_attack_detected",
                        f"Part of attack pair in cluster {cluster_id}",
                        0.6
                    )
        
        # Detect isolated actors (noise in DBSCAN)
        isolated_actors = [actor for actor in valid_actors if actor.ip_address not in 
                          [a.ip_address for cluster in clusters.values() for a in cluster]]
        
        for actor in isolated_actors:
            actor.add_tag('ISOLATED_ATTACKER', self.name)
            self.add_evidence(
                actor,
                "isolated_attacker_detected",
                "Actor shows unique behavioral pattern",
                0.5
            )
        
        context_update = {
            'clustering_summary': {
                'total_actors': len(actors),
                'clusters': len(clusters),
                'isolated_actors': len(isolated_actors),
                'largest_cluster': max(len(cluster) for cluster in clusters.values()) if clusters else 0,
                'detector': self.name
            }
        }
        
        logger.info(f"Behavioral clustering complete: {len(clusters)} clusters, {len(isolated_actors)} isolated")
        return context_update 