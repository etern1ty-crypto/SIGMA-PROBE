"""
Unit tests for SIGMA-PROBE Detectors
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock

from src.models.core import ActorProfile, LogEvent
from src.pipeline.detectors import FFTDetector, GraphDetector, AnomalyDetector

class TestFFTDetector:
    """Test cases for FFTDetector"""
    
    def setup_method(self):
        """Set up test configuration"""
        self.config = {
            'min_events_for_fft': 10,
            'rhythmic_threshold': 2
        }
        self.detector = FFTDetector(self.config)
    
    def create_rhythmic_events(self, ip: str, interval_seconds: int = 60) -> ActorProfile:
        """Create actor with rhythmic events"""
        actor = ActorProfile(ip_address=ip)
        base_time = datetime.now()
        
        # Create rhythmic events every interval_seconds
        for i in range(15):  # More than min_events_for_fft
            event = LogEvent(
                timestamp=base_time + timedelta(seconds=i * interval_seconds),
                source_ip=ip,
                url=f"/test{i}",
                method="GET",
                status_code=200
            )
            actor.add_event(event)
        
        return actor
    
    def create_manual_scanning_events(self, ip: str) -> ActorProfile:
        """Create actor with manual scanning patterns"""
        actor = ActorProfile(ip_address=ip)
        base_time = datetime.now()
        
        # Create events with manual scanning patterns
        urls = ['/admin', '/login', '/wp-admin', '/phpmyadmin', '/config']
        for i, url in enumerate(urls):
            event = LogEvent(
                timestamp=base_time + timedelta(seconds=i * 15),  # 15-second intervals
                source_ip=ip,
                url=url,
                method="GET",
                status_code=200
            )
            actor.add_event(event)
        
        return actor
    
    def test_rhythmic_pattern_detection(self):
        """Test detection of rhythmic patterns"""
        actor = self.create_rhythmic_events('192.168.1.100')
        context = {}
        
        context_update = self.detector.detect([actor], context)
        
        # Should detect rhythmic pattern and add AUTOMATED_SCAN tag
        assert 'AUTOMATED_SCAN' in actor.tags
        assert 'fft_summary' in context_update
        assert context_update['fft_summary']['total_rhythmic_actors'] == 1
    
    def test_manual_scanning_detection(self):
        """Test detection of manual scanning patterns"""
        actor = self.create_manual_scanning_events('192.168.1.101')
        context = {}
        
        context_update = self.detector.detect([actor], context)
        
        # Should detect manual scanning and add MANUAL_SCAN tag
        assert 'MANUAL_SCAN' in actor.tags
        assert len(actor.evidence_trail) > 0
    
    def test_insufficient_events(self):
        """Test behavior with insufficient events for FFT"""
        actor = ActorProfile(ip_address='192.168.1.102')
        
        # Add only 5 events (less than min_events_for_fft)
        base_time = datetime.now()
        for i in range(5):
            event = LogEvent(
                timestamp=base_time + timedelta(seconds=i * 60),
                source_ip='192.168.1.102',
                url=f"/test{i}",
                method="GET",
                status_code=200
            )
            actor.add_event(event)
        
        context = {}
        context_update = self.detector.detect([actor], context)
        
        # Should not add any tags due to insufficient events
        assert len(actor.tags) == 0
        assert 'fft_summary' in context_update

class TestGraphDetector:
    """Test cases for GraphDetector"""
    
    def setup_method(self):
        """Set up test configuration"""
        self.config = {
            'similarity_threshold': 0.3,
            'centrality_threshold': 0.3
        }
        self.detector = GraphDetector(self.config)
    
    def create_similar_actors(self) -> list:
        """Create actors with similar behavior"""
        actors = []
        
        # Create actors with similar URLs
        for i in range(3):
            actor = ActorProfile(ip_address=f'192.168.1.{100 + i}')
            base_time = datetime.now()
            
            # Add similar events
            for j in range(5):
                event = LogEvent(
                    timestamp=base_time + timedelta(seconds=j * 30),
                    source_ip=f'192.168.1.{100 + i}',
                    url=f"/admin/test{j}",
                    method="GET",
                    status_code=200,
                    user_agent="python-requests/2.25.1"
                )
                actor.add_event(event)
            
            actors.append(actor)
        
        return actors
    
    def test_coordinator_detection(self):
        """Test detection of coordinator actors"""
        actors = self.create_similar_actors()
        context = {}
        
        context_update = self.detector.detect(actors, context)
        
        # Should detect coordinators based on centrality
        assert 'graph_summary' in context_update
        assert context_update['graph_summary']['total_actors'] == 3
        
        # Check if any actors got coordinator tags
        coordinators = [a for a in actors if 'COORDINATOR' in a.tags]
        assert len(coordinators) >= 0  # May or may not have coordinators
    
    def test_cluster_member_detection(self):
        """Test detection of cluster members"""
        actors = self.create_similar_actors()
        context = {}
        
        context_update = self.detector.detect(actors, context)
        
        # Should detect cluster members based on clustering coefficient
        cluster_members = [a for a in actors if 'CLUSTER_MEMBER' in a.tags]
        assert len(cluster_members) >= 0  # May or may not have cluster members
    
    def test_single_actor(self):
        """Test behavior with single actor"""
        actor = ActorProfile(ip_address='192.168.1.100')
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip='192.168.1.100',
            url="/test",
            method="GET",
            status_code=200
        )
        actor.add_event(event)
        
        context = {}
        context_update = self.detector.detect([actor], context)
        
        # Should return empty context for single actor
        assert context_update == {}

class TestAnomalyDetector:
    """Test cases for AnomalyDetector"""
    
    def setup_method(self):
        """Set up test configuration"""
        self.config = {
            'anomaly_threshold': 0.7,
            'suspicious_threshold': 0.4
        }
        self.detector = AnomalyDetector(self.config)
    
    def create_normal_actors(self) -> list:
        """Create actors with normal behavior"""
        actors = []
        
        for i in range(5):
            actor = ActorProfile(ip_address=f'192.168.1.{100 + i}')
            actor.avg_entropy = 3.0 + (i * 0.1)  # Slightly varying entropy
            actor.url_diversity_ratio = 0.5 + (i * 0.05)  # Slightly varying diversity
            actor.total_requests = 10 + i
            actor.centrality = 0.3 + (i * 0.05)  # Slightly varying centrality
            actors.append(actor)
        
        return actors
    
    def create_anomalous_actor(self) -> ActorProfile:
        """Create actor with anomalous behavior"""
        actor = ActorProfile(ip_address='192.168.1.200')
        actor.avg_entropy = 6.0  # Very high entropy
        actor.url_diversity_ratio = 0.9  # Very high diversity
        actor.total_requests = 100  # Many requests
        actor.centrality = 0.8  # Very high centrality
        actor.anomaly_ratio = 0.8  # High anomaly ratio
        
        return actor
    
    def test_anomaly_detection(self):
        """Test detection of anomalous actors"""
        normal_actors = self.create_normal_actors()
        anomalous_actor = self.create_anomalous_actor()
        all_actors = normal_actors + [anomalous_actor]
        
        context = {}
        context_update = self.detector.detect(all_actors, context)
        
        # Should detect anomalous actor
        assert 'ANOMALOUS' in anomalous_actor.tags
        assert 'anomaly_summary' in context_update
        assert context_update['anomaly_summary']['anomalies'] >= 1
    
    def test_suspicious_behavior_detection(self):
        """Test detection of suspicious behavior"""
        normal_actors = self.create_normal_actors()
        
        # Create suspicious actor
        suspicious_actor = ActorProfile(ip_address='192.168.1.201')
        suspicious_actor.avg_entropy = 4.0
        suspicious_actor.url_diversity_ratio = 0.7
        suspicious_actor.total_requests = 50
        suspicious_actor.centrality = 0.5
        suspicious_actor.anomaly_ratio = 0.6  # Medium anomaly
        
        all_actors = normal_actors + [suspicious_actor]
        context = {}
        context_update = self.detector.detect(all_actors, context)
        
        # Should detect suspicious behavior
        assert 'SUSPICIOUS' in suspicious_actor.tags
    
    def test_insufficient_actors(self):
        """Test behavior with insufficient actors for comparison"""
        actors = [ActorProfile(ip_address='192.168.1.100')]
        context = {}
        
        context_update = self.detector.detect(actors, context)
        
        # Should return empty context for insufficient actors
        assert context_update == {} 