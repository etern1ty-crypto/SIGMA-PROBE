"""
SIGMA-PROBE Enrichment Stage
Архитектура v2.0 - 'Helios'

Принцип: Элегантность через простоту - один этап, одна ответственность.
"""

import logging
from typing import List, Dict, Any
from ..models.core import LogEvent

logger = logging.getLogger(__name__)

class EnrichmentStage:
    """Clean, single-responsibility enrichment stage"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = "EnrichmentStage"
    
    def process(self, events: List[LogEvent]) -> List[LogEvent]:
        """Process events by calling their built-in feature calculation"""
        logger.info(f"Enriching {len(events)} events")
        
        enriched_events = []
        for event in events:
            # Let the model handle its own enrichment
            event.calculate_features()
            enriched_events.append(event)
        
        logger.info(f"Enriched {len(enriched_events)} events")
        return enriched_events 