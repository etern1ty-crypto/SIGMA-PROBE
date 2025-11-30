"""
SIGMA-PROBE Scoring Engine
Архитектура v2.0 - 'Helios'

Принцип 3: Скоринг — это не просто подсчет, это контекстная оценка угроз.
"""

import numpy as np
from typing import Dict, List, Any, Set
import logging
from collections import Counter

from sigma_probe.models.core import ActorProfile, ThreatCampaign
from .rules_engine import ScoringRulesEngine
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN

logger = logging.getLogger(__name__)

class ScoringEngine:
    """Simplified scoring engine that orchestrates the scoring process"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rules_engine = ScoringRulesEngine(config)
        
    def score_actors(self, actors: List[ActorProfile], context: Dict[str, Any]) -> List[ActorProfile]:
        """
        Score actors using the rules engine.
        
        Args:
            actors: List of ActorProfile objects to score.
            context: Global context dictionary.
            
        Returns:
            List of scored ActorProfile objects.
        """
        logger.info(f"Scoring {len(actors)} actors with rules engine")
        
        for actor in actors:
            # Use rules engine to calculate score
            final_score, evidence_list = self.rules_engine.calculate_score(actor, context)
            
            # Store score in actor
            actor.threat_score = final_score
            
            # Add evidence from rules engine
            for evidence in evidence_list:
                actor.add_evidence(
                    evidence['source'],
                    evidence['type'],
                    evidence['details'],
                    evidence.get('confidence', 1.0)
                )
            
            # Add summary evidence
            actor.add_evidence(
                "ScoringEngine",
                "threat_score_calculated",
                f"Final threat score: {final_score:.2f}",
                0.9
            )
        
        return actors
    
    def cluster_campaigns(self, actors: List[ActorProfile], context: Dict[str, Any]) -> List[ThreatCampaign]:
        """
        Cluster actors into campaigns using behavioral vectors.
        
        Args:
            actors: List of ActorProfile objects.
            context: Global context dictionary.
            
        Returns:
            List of ThreatCampaign objects.
        """
        logger.info(f"Clustering {len(actors)} actors into campaigns")
        
        if len(actors) < 2:
            return []
        
        # Extract behavioral vectors
        behavioral_vectors = []
        valid_actors = []
        
        for actor in actors:
            vector = actor.get_behavioral_vector()
            if vector and sum(vector) > 0:  # Only include actors with meaningful behavior
                behavioral_vectors.append(vector)
                valid_actors.append(actor)
        
        if len(behavioral_vectors) < 2:
            return []
        
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
                    actor.add_tag('COORDINATED_ATTACK', 'ScoringEngine')
                    actor.add_evidence(
                        'ScoringEngine',
                        "coordinated_attack_detected",
                        f"Part of coordinated cluster {cluster_id} with {len(cluster_actors)} actors",
                        0.8
                    )
            elif len(cluster_actors) == 2:
                # Small coordinated pair
                for actor in cluster_actors:
                    actor.add_tag('PAIRED_ATTACK', 'ScoringEngine')
                    actor.add_evidence(
                        'ScoringEngine',
                        "paired_attack_detected",
                        f"Part of attack pair in cluster {cluster_id}",
                        0.6
                    )
        
        # Detect isolated actors (noise in DBSCAN)
        isolated_actors = [actor for actor in valid_actors if actor.ip_address not in 
                          [a.ip_address for cluster in clusters.values() for a in cluster]]
        
        for actor in isolated_actors:
            actor.add_tag('ISOLATED_ATTACKER', 'ScoringEngine')
            actor.add_evidence(
                'ScoringEngine',
                "isolated_attacker_detected",
                "Actor shows unique behavioral pattern",
                0.5
            )
        
        # Create campaign objects
        campaigns = []
        for cluster_id, cluster_actors in clusters.items():
            campaign = ThreatCampaign(
                campaign_id=f"campaign_{cluster_id}",
                actors=cluster_actors
            )
            
            # Update campaign metrics
            campaign._update_campaign_metrics()
            
            # Add campaign evidence
            campaign.add_evidence(
                "ScoringEngine",
                "campaign_created",
                f"Created campaign with {len(cluster_actors)} actors using behavioral clustering"
            )
            
            campaigns.append(campaign)
        
        logger.info(f"Created {len(campaigns)} campaigns from {len(actors)} actors")
        return campaigns