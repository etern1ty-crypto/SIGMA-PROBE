"""
Unit tests for SIGMA-PROBE Scoring Rules Engine
"""

import pytest
from datetime import datetime
from unittest.mock import Mock

from src.models.core import ActorProfile, LogEvent
from src.pipeline.rules_engine import ScoringRulesEngine

class TestScoringRulesEngine:
    """Test cases for ScoringRulesEngine"""
    
    def setup_method(self):
        """Set up test configuration"""
        self.config = {
            'scoring_profiles': {
                'LFI_RFI': {
                    'base_score': 8.0,
                    'modifiers': [
                        {
                            'if': 'high_entropy',
                            'value': 1.3,
                            'evidence': 'LFI/RFI with high entropy'
                        },
                        {
                            'if': 'coordinated_attack',
                            'value': 1.5,
                            'evidence': 'LFI/RFI as part of coordinated attack'
                        }
                    ]
                },
                'AUTOMATED_SCAN': {
                    'base_score': 4.0,
                    'modifiers': [
                        {
                            'if': 'fft_is_rhythmic',
                            'value': 1.5,
                            'evidence': 'Automated scanning with rhythmic patterns'
                        }
                    ]
                },
                'COORDINATOR': {
                    'base_score': 5.0,
                    'modifiers': [
                        {
                            'if': 'high_centrality',
                            'value': 1.4,
                            'evidence': 'High centrality coordinator'
                        }
                    ]
                }
            },
            'tag_combinations': {
                'LFI_RFI+COORDINATED_ATTACK': {
                    'multiplier': 1.8,
                    'evidence': 'LFI/RFI in coordinated attack - highly dangerous'
                },
                'AUTOMATED_SCAN+COORDINATOR': {
                    'multiplier': 1.4,
                    'evidence': 'Automated scanning by coordinator'
                }
            },
            'global_modifiers': {
                'large_scale_attack': {
                    'threshold': 100,
                    'multiplier': 1.2,
                    'evidence': 'Large-scale attack detected'
                }
            }
        }
        
        self.rules_engine = ScoringRulesEngine(self.config)
    
    def create_test_actor(self, ip: str, tags: set, **metrics) -> ActorProfile:
        """Helper method to create test actor"""
        actor = ActorProfile(ip_address=ip)
        actor.tags = tags
        
        # Set default metrics
        actor.avg_entropy = metrics.get('avg_entropy', 3.0)
        actor.url_diversity_ratio = metrics.get('url_diversity_ratio', 0.5)
        actor.centrality = metrics.get('centrality', 0.3)
        actor.anomaly_ratio = metrics.get('anomaly_ratio', 0.4)
        
        return actor
    
    def test_basic_tag_scoring(self):
        """Test basic scoring with single tags"""
        actor = self.create_test_actor('192.168.1.100', {'LFI_RFI'})
        
        score, evidence = self.rules_engine.calculate_score(actor, {})
        
        assert score == 8.0  # Base score for LFI_RFI
        assert len(evidence) == 0  # No modifiers applied
    
    def test_tag_with_modifier(self):
        """Test scoring with tag and modifier"""
        actor = self.create_test_actor('192.168.1.100', {'LFI_RFI'}, avg_entropy=5.0)
        
        score, evidence = self.rules_engine.calculate_score(actor, {})
        
        expected_score = 8.0 * 1.3  # Base score * high entropy modifier
        assert abs(score - expected_score) < 0.01
        assert len(evidence) == 1
        assert evidence[0]['type'] == 'modifier_applied'
    
    def test_tag_combination_scoring(self):
        """Test scoring with tag combinations"""
        actor = self.create_test_actor('192.168.1.100', {'LFI_RFI', 'COORDINATED_ATTACK'})
        
        score, evidence = self.rules_engine.calculate_score(actor, {})
        
        # Base scores: LFI_RFI (8.0) + COORDINATED_ATTACK (not in config, so 0)
        # Combination modifier: 1.8
        expected_score = 8.0 * 1.8
        assert abs(score - expected_score) < 0.01
        assert len(evidence) == 1
        assert evidence[0]['type'] == 'combination_detected'
    
    def test_multiple_attack_types(self):
        """Test dynamic combination scoring for multiple attack types"""
        actor = self.create_test_actor('192.168.1.100', {'LFI_RFI', 'SQL_INJECTION'})
        
        score, evidence = self.rules_engine.calculate_score(actor, {})
        
        # Base score: 8.0 (LFI_RFI)
        # Dynamic modifier: 1.5 (two attack types)
        expected_score = 8.0 * 1.5
        assert abs(score - expected_score) < 0.01
    
    def test_coordination_with_attack(self):
        """Test coordination + attack combination"""
        actor = self.create_test_actor('192.168.1.100', {'LFI_RFI', 'COORDINATOR'})
        
        score, evidence = self.rules_engine.calculate_score(actor, {})
        
        # Base score: 8.0 (LFI_RFI) + 5.0 (COORDINATOR) = 13.0
        # Dynamic modifier: 1.8 (coordination + attack)
        expected_score = 13.0 * 1.8
        assert abs(score - expected_score) < 0.01
    
    def test_contextual_modifier(self):
        """Test contextual modifiers based on global context"""
        actor = self.create_test_actor('192.168.1.100', {'AUTOMATED_SCAN'})
        
        context = {
            'fft_summary': {
                'prevalence': 0.6  # More than 50% are rhythmic
            }
        }
        
        score, evidence = self.rules_engine.calculate_score(actor, context)
        
        # Base score: 4.0 (AUTOMATED_SCAN)
        # Contextual modifier: 1.2 (part of widespread attack)
        expected_score = 4.0 * 1.2
        assert abs(score - expected_score) < 0.01
        assert len(evidence) == 1
        assert evidence[0]['type'] == 'contextual_modifier'
    
    def test_global_modifier(self):
        """Test global modifiers based on threat landscape"""
        actor = self.create_test_actor('192.168.1.100', {'LFI_RFI'})
        
        context = {
            'fft_summary': {'total_actors': 150},  # Large-scale attack
            'graph_summary': {'coordinators': 8}    # High coordination
        }
        
        score, evidence = self.rules_engine.calculate_score(actor, context)
        
        # Base score: 8.0 (LFI_RFI)
        # Global modifiers: 1.2 (large scale) * 1.3 (high coordination)
        expected_score = 8.0 * 1.2 * 1.3
        assert abs(score - expected_score) < 0.01
        assert len(evidence) == 2  # Two global modifiers applied
    
    def test_no_tags(self):
        """Test scoring for actor with no tags"""
        actor = self.create_test_actor('192.168.1.100', set())
        
        score, evidence = self.rules_engine.calculate_score(actor, {})
        
        assert score == 0.0
        assert len(evidence) == 0
    
    def test_high_entropy_modifier(self):
        """Test high entropy modifier condition"""
        actor = self.create_test_actor('192.168.1.100', {'LFI_RFI'}, avg_entropy=5.0)
        
        score, evidence = self.rules_engine.calculate_score(actor, {})
        
        # Should apply high entropy modifier (1.3)
        expected_score = 8.0 * 1.3
        assert abs(score - expected_score) < 0.01
    
    def test_high_centrality_modifier(self):
        """Test high centrality modifier condition"""
        actor = self.create_test_actor('192.168.1.100', {'COORDINATOR'}, centrality=0.8)
        
        score, evidence = self.rules_engine.calculate_score(actor, {})
        
        # Should apply high centrality modifier (1.4)
        expected_score = 5.0 * 1.4
        assert abs(score - expected_score) < 0.01
    
    def test_anomalous_behavior_modifier(self):
        """Test anomalous behavior modifier condition"""
        actor = self.create_test_actor('192.168.1.100', {'ANOMALOUS'}, anomaly_ratio=0.8)
        
        # Add ANOMALOUS profile to config for this test
        self.config['scoring_profiles']['ANOMALOUS'] = {
            'base_score': 5.5,
            'modifiers': [
                {
                    'if': 'anomalous_behavior',
                    'value': 1.3,
                    'evidence': 'Anomalous behavior with multiple attack types'
                }
            ]
        }
        self.rules_engine = ScoringRulesEngine(self.config)
        
        score, evidence = self.rules_engine.calculate_score(actor, {})
        
        # Should apply anomalous behavior modifier (1.3)
        expected_score = 5.5 * 1.3
        assert abs(score - expected_score) < 0.01 