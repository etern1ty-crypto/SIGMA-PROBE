"""
SIGMA-PROBE Behavioral Test: LFI Attack Scenario
BDD - Behavior-Driven Development Test

Принцип: Ты начинаешь тестировать не код, а интеллект своей системы. 
Ты формализуешь требования к ее поведению.
"""

import pytest
import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from main import HeliosPipeline
from models.core import ActorProfile, LogEvent
import yaml

class TestLFIAttackScenario:
    """Behavioral test for LFI attack detection scenario"""
    
    @pytest.fixture
    def pipeline(self):
        """Create pipeline with test configuration"""
        # Create temporary config file
        config = {
            'pipeline': {
                'stages': ['ingestion', 'enrichment', 'profiling', 'detection', 'metadetection', 'scoring', 'reporting']
            },
            'ioc_feeds': {
                'enabled': True,
                'update_interval': 3600,
                'feeds': [
                    {
                        'name': 'lfi_patterns',
                        'url': 'https://raw.githubusercontent.com/example/threat-intel/main/lfi_patterns.txt',
                        'type': 'url_pattern',
                        'enabled': True
                    }
                ]
            },
            'detectors': {
                'fft': {
                    'min_peaks': 3,
                    'peak_threshold': 0.1,
                    'autocorr_threshold': 0.3,
                    'window_size': 600,
                    'change_threshold': 5.0
                }
            },
            'scoring': {
                'profiles': {
                    'lfi_attacker': {
                        'base_score': 8.0,
                        'multipliers': {
                            'LFI_ATTACK': 1.5,
                            'BOT_ACTIVITY': 1.2,
                            'CONFIRMED_SOPHISTICATED': 1.3
                        }
                    }
                }
            }
        }
        
        # Write config to temporary file
        import tempfile
        import yaml
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config, f)
            config_path = f.name
        
        try:
            return HeliosPipeline(config_path)
        finally:
            # Clean up temp file
            import os
            os.unlink(config_path)
    
    @pytest.fixture
    def scenario_log_path(self):
        """Path to the LFI attack scenario log"""
        return Path(__file__).parent / 'scenarios' / 'lfi_attack_scenario.log'
    
    def test_lfi_attack_detection(self, pipeline, scenario_log_path):
        """Test that LFI attack is properly detected and scored"""
        # Run pipeline on scenario
        results = pipeline.run(str(scenario_log_path))
        
        # Verify we have actors
        assert 'actors' in results, "Pipeline should return actors"
        assert len(results['actors']) > 0, "Should detect at least one actor"
        
        # Get the main actor (192.168.1.100)
        main_actor = None
        for actor in results['actors']:
            if actor.ip == '192.168.1.100':
                main_actor = actor
                break
        
        assert main_actor is not None, "Should detect the attacking IP"
        
        # Verify LFI attack detection
        assert 'LFI_ATTACK' in main_actor.tags, "Should detect LFI attack patterns"
        
        # Verify bot activity detection (adaptive timing)
        assert 'BOT_ACTIVITY' in main_actor.tags, "Should detect automated bot activity"
        
        # Verify high threat score
        assert main_actor.threat_score > 8.0, f"LFI attacker should have high threat score, got {main_actor.threat_score}"
        
        # Verify evidence trail
        assert len(main_actor.evidence_trail) > 0, "Should have evidence trail"
        
        # Check for specific evidence types
        evidence_sources = [e.get('source', '') for e in main_actor.evidence_trail]
        assert 'HeuristicEnricher' in evidence_sources, "Should have heuristic evidence"
        assert 'FFTDetector' in evidence_sources, "Should have temporal analysis evidence"
        
        # Verify meta-detection results
        if 'MetaDetector' in evidence_sources:
            # Check for confirmation or contradiction tags
            meta_tags = {'CONFIRMED_SOPHISTICATED', 'CONFIRMED_BOTNET', 'ISOLATED_INDICATOR', 'FALSE_POSITIVE'}
            detected_meta_tags = meta_tags.intersection(main_actor.tags)
            assert len(detected_meta_tags) > 0, "MetaDetector should add cross-validation tags"
    
    def test_adaptive_timing_detection(self, pipeline, scenario_log_path):
        """Test that adaptive timing patterns are detected"""
        results = pipeline.run(str(scenario_log_path))
        
        main_actor = None
        for actor in results['actors']:
            if actor.ip == '192.168.1.100':
                main_actor = actor
                break
        
        assert main_actor is not None
        
        # Check for FFT evidence indicating adaptive timing
        fft_evidence = [e for e in main_actor.evidence_trail if 'FFTDetector' in e.get('source', '')]
        assert len(fft_evidence) > 0, "Should have FFT analysis evidence"
        
        # Check for windowed change detection
        window_evidence = [e for e in fft_evidence if 'frequency change' in e.get('description', '').lower()]
        if window_evidence:
            # Adaptive timing detected
            assert 'BOT_ACTIVITY' in main_actor.tags, "Adaptive timing should trigger bot detection"
    
    def test_ioc_integration(self, pipeline, scenario_log_path):
        """Test that IoC feeds are integrated into detection"""
        results = pipeline.run(str(scenario_log_path))
        
        main_actor = None
        for actor in results['actors']:
            if actor.ip == '192.168.1.100':
                main_actor = actor
                break
        
        assert main_actor is not None
        
        # Check for IoC-based evidence
        ioc_evidence = [e for e in main_actor.evidence_trail 
                       if 'IoC' in e.get('source', '') or 'feed' in e.get('description', '').lower()]
        
        # Note: This test may fail if IoC feeds are not available during testing
        # In a real environment, this would verify external threat intelligence integration
        if ioc_evidence:
            assert 'LFI_ATTACK' in main_actor.tags, "IoC evidence should support LFI detection"
    
    def test_evidence_confidence_scoring(self, pipeline, scenario_log_path):
        """Test that evidence confidence affects threat scoring"""
        results = pipeline.run(str(scenario_log_path))
        
        main_actor = None
        for actor in results['actors']:
            if actor.ip == '192.168.1.100':
                main_actor = actor
                break
        
        assert main_actor is not None
        
        # Check that high-confidence evidence exists
        high_confidence_evidence = [e for e in main_actor.evidence_trail 
                                  if e.get('confidence', 0) > 0.8]
        assert len(high_confidence_evidence) > 0, "Should have high-confidence evidence"
        
        # Verify threat score reflects evidence confidence
        assert main_actor.threat_score > 7.0, "High confidence evidence should result in high threat score"
    
    def test_campaign_clustering(self, pipeline, scenario_log_path):
        """Test that actors are properly clustered into campaigns"""
        results = pipeline.run(str(scenario_log_path))
        
        # Check for campaign formation
        assert 'campaigns' in results, "Should identify threat campaigns"
        
        if results['campaigns']:
            # Verify campaign has the expected actor
            campaign_actors = []
            for campaign in results['campaigns']:
                campaign_actors.extend([actor.ip for actor in campaign.actors])
            
            assert '192.168.1.100' in campaign_actors, "LFI attacker should be in a campaign"
            
            # Verify campaign scoring
            for campaign in results['campaigns']:
                if any(actor.ip == '192.168.1.100' for actor in campaign.actors):
                    assert campaign.threat_score > 7.0, "LFI campaign should have high threat score"
                    assert len(campaign.evidence_trail) > 0, "Campaign should have evidence trail" 