"""
SIGMA-PROBE MetaDetector
"Council of Directors" - Cross-Validation Engine

Принцип: Система приобретает скепсис. Она учится сомневаться в своих же компонентах, 
перепроверять выводы и выдавать гораздо более взвешенные и точные вердикты.
"""

import logging
from typing import Dict, List, Any, Set
from collections import defaultdict

from ..models.core import ActorProfile, LogEvent
from ..pipeline.base import BaseDetector

logger = logging.getLogger(__name__)

class MetaDetector(BaseDetector):
    """Meta-detector that analyzes and cross-validates other detectors' outputs"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.confirmation_threshold = config.get('confirmation_threshold', 0.7)
        self.contradiction_threshold = config.get('contradiction_threshold', 0.3)
        self.confidence_boost = config.get('confidence_boost', 0.2)
        self.confidence_penalty = config.get('confidence_penalty', 0.3)
        
    def detect(self, actors: List[ActorProfile], context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze detector outputs and cross-validate findings"""
        logger.info(f"Running meta-detection on {len(actors)} actors")
        
        meta_analysis_results = {
            'confirmed_threats': 0,
            'contradictions_resolved': 0,
            'confidence_adjustments': 0,
            'new_tags_added': 0
        }
        
        for actor in actors:
            if not actor.evidence_trail:
                continue
                
            # Analyze evidence trail for confirmations and contradictions
            confirmations = self._find_confirmations(actor)
            contradictions = self._find_contradictions(actor)
            
            # Apply meta-analysis results
            self._apply_confirmations(actor, confirmations)
            self._apply_contradictions(actor, contradictions)
            
            # Update statistics
            if confirmations:
                meta_analysis_results['confirmed_threats'] += 1
            if contradictions:
                meta_analysis_results['contradictions_resolved'] += 1
            
            # Add meta-detector evidence
            if confirmations or contradictions:
                self._add_meta_evidence(actor, confirmations, contradictions)
        
        logger.info(f"Meta-detection complete: {meta_analysis_results}")
        return {'meta_analysis': meta_analysis_results}
    
    def _find_confirmations(self, actor: ActorProfile) -> List[Dict]:
        """Find confirming evidence patterns"""
        confirmations = []
        
        # Check for botnet confirmation
        if self._confirm_botnet(actor):
            confirmations.append({
                'type': 'CONFIRMED_BOTNET',
                'confidence': 0.95,
                'description': 'Multiple detectors confirm automated bot activity',
                'sources': ['FFTDetector', 'BehavioralClusteringDetector']
            })
        
        # Check for coordinated attack confirmation
        if self._confirm_coordinated_attack(actor):
            confirmations.append({
                'type': 'CONFIRMED_COORDINATED',
                'confidence': 0.9,
                'description': 'Graph analysis confirms coordinated attack patterns',
                'sources': ['GraphDetector', 'AnomalyDetector']
            })
        
        # Check for sophisticated attack confirmation
        if self._confirm_sophisticated_attack(actor):
            confirmations.append({
                'type': 'CONFIRMED_SOPHISTICATED',
                'confidence': 0.85,
                'description': 'Multiple attack vectors detected with high confidence',
                'sources': ['HeuristicEnricher', 'FFTDetector', 'AnomalyDetector']
            })
        
        return confirmations
    
    def _find_contradictions(self, actor: ActorProfile) -> List[Dict]:
        """Find contradictory evidence patterns"""
        contradictions = []
        
        # Check for isolated attack indicators
        if self._detect_isolated_indicators(actor):
            contradictions.append({
                'type': 'ISOLATED_INDICATOR',
                'confidence': 0.6,
                'description': 'Single attack indicator without supporting evidence',
                'sources': ['HeuristicEnricher'],
                'penalty': 0.3
            })
        
        # Check for false positive patterns
        if self._detect_false_positive_patterns(actor):
            contradictions.append({
                'type': 'FALSE_POSITIVE',
                'confidence': 0.7,
                'description': 'Normal behavior patterns contradict threat indicators',
                'sources': ['AnomalyDetector', 'GraphDetector'],
                'penalty': 0.4
            })
        
        # Check for inconsistent timing
        if self._detect_inconsistent_timing(actor):
            contradictions.append({
                'type': 'INCONSISTENT_TIMING',
                'confidence': 0.5,
                'description': 'Timing patterns inconsistent with automated behavior',
                'sources': ['FFTDetector'],
                'penalty': 0.2
            })
        
        return contradictions
    
    def _confirm_botnet(self, actor: ActorProfile) -> bool:
        """Confirm botnet activity through multiple detectors"""
        has_fft = any('FFTDetector' in evidence.get('source', '') 
                     for evidence in actor.evidence_trail)
        has_clustering = any('BehavioralClusteringDetector' in evidence.get('source', '')
                           for evidence in actor.evidence_trail)
        has_anomaly = any('AnomalyDetector' in evidence.get('source', '')
                         for evidence in actor.evidence_trail)
        
        # Need at least 2 confirming detectors
        confirmations = sum([has_fft, has_clustering, has_anomaly])
        return confirmations >= 2
    
    def _confirm_coordinated_attack(self, actor: ActorProfile) -> bool:
        """Confirm coordinated attack through graph analysis"""
        has_graph = any('GraphDetector' in evidence.get('source', '')
                       for evidence in actor.evidence_trail)
        has_anomaly = any('AnomalyDetector' in evidence.get('source', '')
                         for evidence in actor.evidence_trail)
        
        # Need both graph and anomaly confirmation
        return has_graph and has_anomaly
    
    def _confirm_sophisticated_attack(self, actor: ActorProfile) -> bool:
        """Confirm sophisticated attack with multiple vectors"""
        attack_tags = {'LFI_ATTACK', 'SQLI_ATTACK', 'XSS_ATTACK', 'PATH_TRAVERSAL'}
        detected_attacks = len(attack_tags.intersection(actor.tags))
        
        has_heuristic = any('HeuristicEnricher' in evidence.get('source', '')
                           for evidence in actor.evidence_trail)
        has_temporal = any('FFTDetector' in evidence.get('source', '')
                          for evidence in actor.evidence_trail)
        
        return detected_attacks >= 2 and (has_heuristic or has_temporal)
    
    def _detect_isolated_indicators(self, actor: ActorProfile) -> bool:
        """Detect isolated attack indicators without supporting evidence"""
        attack_tags = {'LFI_ATTACK', 'SQLI_ATTACK', 'XSS_ATTACK', 'PATH_TRAVERSAL'}
        has_attack_tags = bool(attack_tags.intersection(actor.tags))
        
        # Check if only heuristic evidence exists
        only_heuristic = all('HeuristicEnricher' in evidence.get('source', '')
                            for evidence in actor.evidence_trail)
        
        return has_attack_tags and only_heuristic and len(actor.evidence_trail) == 1
    
    def _detect_false_positive_patterns(self, actor: ActorProfile) -> bool:
        """Detect patterns that suggest false positives"""
        # Check for normal behavior indicators
        has_normal_anomaly = any('AnomalyDetector' in evidence.get('source', '') 
                               and 'normal' in evidence.get('description', '').lower()
                               for evidence in actor.evidence_trail)
        
        has_low_centrality = any('GraphDetector' in evidence.get('source', '')
                               and 'low centrality' in evidence.get('description', '').lower()
                               for evidence in actor.evidence_trail)
        
        return has_normal_anomaly or has_low_centrality
    
    def _detect_inconsistent_timing(self, actor: ActorProfile) -> bool:
        """Detect inconsistent timing patterns"""
        fft_evidence = [e for e in actor.evidence_trail 
                       if 'FFTDetector' in e.get('source', '')]
        
        if not fft_evidence:
            return False
        
        # Check if FFT found no rhythmic patterns but other detectors flagged as bot
        has_no_rhythm = any('no rhythmic' in e.get('description', '').lower() 
                           for e in fft_evidence)
        has_bot_tags = 'BOT_ACTIVITY' in actor.tags
        
        return has_no_rhythm and has_bot_tags
    
    def _apply_confirmations(self, actor: ActorProfile, confirmations: List[Dict]):
        """Apply confirming evidence to actor"""
        for confirmation in confirmations:
            # Add new confirmed tag
            actor.tags.add(confirmation['type'])
            
            # Boost confidence of related evidence
            for evidence in actor.evidence_trail:
                if any(source in evidence.get('source', '') 
                      for source in confirmation['sources']):
                    evidence['confidence'] = min(1.0, 
                                              evidence.get('confidence', 0.0) + self.confidence_boost)
    
    def _apply_contradictions(self, actor: ActorProfile, contradictions: List[Dict]):
        """Apply contradictory evidence to actor"""
        for contradiction in contradictions:
            # Add contradiction tag
            actor.tags.add(contradiction['type'])
            
            # Reduce confidence of conflicting evidence
            penalty = contradiction.get('penalty', self.confidence_penalty)
            for evidence in actor.evidence_trail:
                if any(source in evidence.get('source', '') 
                      for source in contradiction['sources']):
                    evidence['confidence'] = max(0.0, 
                                              evidence.get('confidence', 0.0) - penalty)
    
    def _add_meta_evidence(self, actor: ActorProfile, confirmations: List[Dict], 
                          contradictions: List[Dict]):
        """Add meta-detector evidence to actor"""
        if confirmations:
            actor.evidence_trail.append({
                'source': 'MetaDetector',
                'confidence': 0.9,
                'description': f'Cross-validation confirmed {len(confirmations)} threat patterns'
            })
        
        if contradictions:
            actor.evidence_trail.append({
                'source': 'MetaDetector',
                'confidence': 0.8,
                'description': f'Resolved {len(contradictions)} contradictory indicators'
            }) 