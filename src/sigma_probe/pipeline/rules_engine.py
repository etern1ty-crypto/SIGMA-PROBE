"""
SIGMA-PROBE Rules Engine
Архитектура v2.0 - 'Helios'

Принцип: Разделение ответственности - RulesEngine отвечает за "КАК", ScoringEngine за "ЧТО".
"""

import logging
from typing import Dict, List, Any, Set, Tuple
from ..models.core import ActorProfile

logger = logging.getLogger(__name__)

class ScoringRulesEngine:
    """Dedicated engine for interpreting and applying scoring rules"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scoring_profiles = config.get('scoring_profiles', {})
        self.tag_combinations = config.get('tag_combinations', {})
        self.global_modifiers = config.get('global_modifiers', {})
    
    def calculate_score(self, actor: ActorProfile, context: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculate threat score for an actor based on tags and context
        
        Returns:
            Tuple of (final_score, evidence_list)
        """
        evidence_list = []
        
        # Calculate base score from individual tags
        base_score = self._calculate_base_score(actor, evidence_list)
        
        # Apply tag combination modifiers
        combination_modifier = self._calculate_tag_combination_modifier(actor.tags, evidence_list)
        
        # Apply contextual modifiers
        contextual_modifier = self._calculate_contextual_modifier(actor, context, evidence_list)
        
        # Apply global modifiers
        global_modifier = self._calculate_global_modifier(context, evidence_list)
        
        # Calculate final score
        final_score = base_score * combination_modifier * contextual_modifier * global_modifier
        
        return final_score, evidence_list
    
    def _calculate_base_score(self, actor: ActorProfile, evidence_list: List[Dict[str, Any]]) -> float:
        """Calculate base score from individual tags"""
        base_score = 0.0
        
        for tag in actor.tags:
            if tag in self.scoring_profiles:
                profile = self.scoring_profiles[tag]
                tag_score = profile.get('base_score', 0.0)
                base_score += tag_score
                
                # Apply tag-specific modifiers
                modifiers = profile.get('modifiers', [])
                for modifier in modifiers:
                    if self._evaluate_modifier_condition(actor, modifier):
                        modifier_value = modifier.get('value', 1.0)
                        base_score *= modifier_value
                        
                        # Add evidence for modifier application
                        evidence = modifier.get('evidence', f"Applied {tag} modifier: {modifier_value}")
                        evidence_list.append({
                            'source': 'RulesEngine',
                            'type': 'modifier_applied',
                            'details': evidence,
                            'confidence': 0.7
                        })
        
        return base_score
    
    def _evaluate_modifier_condition(self, actor: ActorProfile, modifier: Dict[str, Any]) -> bool:
        """Evaluate if a modifier condition is met"""
        condition = modifier.get('if', '')
        
        if condition == 'fft_is_rhythmic':
            return 'AUTOMATED_SCAN' in actor.tags
        
        elif condition == 'url_diversity_ratio':
            threshold = modifier.get('threshold', 0.8)
            return actor.url_diversity_ratio > threshold
        
        elif condition == 'high_entropy':
            threshold = modifier.get('threshold', 4.5)
            return actor.avg_entropy > threshold
        
        elif condition == 'high_centrality':
            threshold = modifier.get('threshold', 0.5)
            return actor.centrality > threshold
        
        elif condition == 'anomalous_behavior':
            threshold = modifier.get('threshold', 0.7)
            return actor.anomaly_ratio > threshold
        
        elif condition == 'coordinated_attack':
            return 'COORDINATED_ATTACK' in actor.tags or 'COORDINATOR' in actor.tags
        
        elif condition == 'multiple_attack_types':
            attack_tags = {'LFI_RFI', 'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION'}
            return len(actor.tags.intersection(attack_tags)) >= 2
        
        return False
    
    def _calculate_tag_combination_modifier(self, tags: Set[str], evidence_list: List[Dict[str, Any]]) -> float:
        """Calculate modifier based on tag combinations"""
        modifier = 1.0
        
        # Check for predefined tag combinations
        for combination, config in self.tag_combinations.items():
            combination_tags = set(combination.split('+'))
            if combination_tags.issubset(tags):
                combination_modifier = config.get('multiplier', 1.0)
                modifier *= combination_modifier
                
                # Add evidence for combination detection
                evidence = config.get('evidence', f"Detected tag combination: {combination}")
                evidence_list.append({
                    'source': 'RulesEngine',
                    'type': 'combination_detected',
                    'details': evidence,
                    'confidence': 0.8
                })
        
        # Dynamic combination scoring
        dynamic_modifier = self._calculate_dynamic_combination_modifier(tags)
        modifier *= dynamic_modifier
        
        return modifier
    
    def _calculate_dynamic_combination_modifier(self, tags: Set[str]) -> float:
        """Calculate dynamic modifier based on tag interactions"""
        modifier = 1.0
        
        # Attack type combinations
        attack_tags = {'LFI_RFI', 'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION'}
        attack_count = len(tags.intersection(attack_tags))
        
        if attack_count >= 3:
            modifier *= 2.0  # Multiple attack types
        elif attack_count == 2:
            modifier *= 1.5  # Two attack types
        
        # Coordination + attack combinations
        if ('COORDINATOR' in tags or 'COORDINATED_ATTACK' in tags) and attack_count > 0:
            modifier *= 1.8  # Coordinated attacks are more dangerous
        
        # Automation + attack combinations
        if ('AUTOMATED_SCAN' in tags or 'MANUAL_SCAN' in tags) and attack_count > 0:
            modifier *= 1.3  # Systematic attacks
        
        # Anomaly + attack combinations
        if 'ANOMALOUS' in tags and attack_count > 0:
            modifier *= 1.4  # Anomalous attacks are more concerning
        
        return modifier
    
    def _calculate_contextual_modifier(self, actor: ActorProfile, context: Dict[str, Any], evidence_list: List[Dict[str, Any]]) -> float:
        """Calculate contextual modifier based on global context"""
        modifier = 1.0
        
        # FFT context
        fft_summary = context.get('fft_summary', {})
        if fft_summary:
            prevalence = fft_summary.get('prevalence', 0.0)
            if prevalence > 0.5:  # More than half are rhythmic
                if 'AUTOMATED_SCAN' in actor.tags:
                    modifier *= 1.2  # Part of widespread automated attack
                    evidence_list.append({
                        'source': 'RulesEngine',
                        'type': 'contextual_modifier',
                        'details': f"Part of widespread automated attack (prevalence: {prevalence:.2f})",
                        'confidence': 0.6
                    })
                else:
                    modifier *= 0.8  # Stands out as non-automated
        
        # Graph context
        graph_summary = context.get('graph_summary', {})
        if graph_summary:
            avg_centrality = graph_summary.get('avg_centrality', 0.0)
            if actor.centrality > avg_centrality * 2:
                modifier *= 1.3  # High centrality in coordinated attack
                evidence_list.append({
                    'source': 'RulesEngine',
                    'type': 'contextual_modifier',
                    'details': f"High centrality ({actor.centrality:.2f}) in coordinated environment",
                    'confidence': 0.7
                })
            elif actor.centrality < avg_centrality * 0.5:
                modifier *= 0.9  # Low centrality, less concerning
        
        # Anomaly context
        anomaly_summary = context.get('anomaly_summary', {})
        if anomaly_summary:
            anomaly_rate = anomaly_summary.get('anomaly_rate', 0.0)
            if anomaly_rate > 0.3:  # High anomaly rate
                if actor.anomaly_ratio > 0.7:
                    modifier *= 1.4  # Highly anomalous in anomalous environment
                    evidence_list.append({
                        'source': 'RulesEngine',
                        'type': 'contextual_modifier',
                        'details': f"Highly anomalous in anomalous environment (rate: {anomaly_rate:.2f})",
                        'confidence': 0.8
                    })
                else:
                    modifier *= 0.7  # Normal in anomalous environment
        
        # Clustering context
        clustering_summary = context.get('clustering_summary', {})
        if clustering_summary:
            largest_cluster = clustering_summary.get('largest_cluster', 0)
            if largest_cluster >= 5:  # Large coordinated attack
                if 'COORDINATED_ATTACK' in actor.tags or 'COORDINATOR' in actor.tags:
                    modifier *= 1.5  # Part of large coordinated attack
                    evidence_list.append({
                        'source': 'RulesEngine',
                        'type': 'contextual_modifier',
                        'details': f"Part of large coordinated attack (cluster size: {largest_cluster})",
                        'confidence': 0.8
                    })
        
        return modifier
    
    def _calculate_global_modifier(self, context: Dict[str, Any], evidence_list: List[Dict[str, Any]]) -> float:
        """Calculate global modifier based on overall threat landscape"""
        modifier = 1.0
        
        # Check for global threat indicators
        total_actors = 0
        for summary in [context.get('fft_summary', {}), context.get('graph_summary', {}), 
                       context.get('anomaly_summary', {}), context.get('clustering_summary', {})]:
            if summary:
                total_actors = max(total_actors, summary.get('total_actors', 0))
        
        # Apply global modifiers based on threat landscape
        if total_actors > 100:
            modifier *= 1.2  # Large-scale attack
            evidence_list.append({
                'source': 'RulesEngine',
                'type': 'global_modifier',
                'details': f"Large-scale attack detected ({total_actors} actors)",
                'confidence': 0.7
            })
        elif total_actors > 50:
            modifier *= 1.1  # Medium-scale attack
            evidence_list.append({
                'source': 'RulesEngine',
                'type': 'global_modifier',
                'details': f"Medium-scale attack detected ({total_actors} actors)",
                'confidence': 0.6
            })
        
        # Check for coordinated attack indicators
        coordinators = context.get('graph_summary', {}).get('coordinators', 0)
        if coordinators > 5:
            modifier *= 1.3  # Highly coordinated attack
            evidence_list.append({
                'source': 'RulesEngine',
                'type': 'global_modifier',
                'details': f"Highly coordinated attack ({coordinators} coordinators)",
                'confidence': 0.8
            })
        
        # Check for anomaly indicators
        anomalies = context.get('anomaly_summary', {}).get('anomalies', 0)
        if anomalies > 10:
            modifier *= 1.2  # High anomaly rate
            evidence_list.append({
                'source': 'RulesEngine',
                'type': 'global_modifier',
                'details': f"High anomaly rate ({anomalies} anomalous actors)",
                'confidence': 0.7
            })
        
        return modifier 