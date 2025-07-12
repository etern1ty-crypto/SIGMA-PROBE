"""
SIGMA-PROBE Main Module
Архитектура v2.0 - 'Helios'

Принцип 4: Конвейер — это не просто последовательность, это интеллектуальная система.
"""

import yaml
import logging
import sys
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
from multiprocessing import Pool, cpu_count

from .pipeline.ingestion import LogIngestionStage
from .pipeline.enrichment import EnrichmentStage
from .pipeline.profiling import ActorProfilingStage
from .pipeline.detectors import (
    FFTDetector, GraphDetector, AnomalyDetector, BehavioralClusteringDetector
)
from .pipeline.metadetector import MetaDetector
from .pipeline.recommendations import NarrativeEngine
from .pipeline.scoring import ScoringEngine
from .pipeline.reporting import ReportingStage
from .intelligence.ioc_manager import IoCManager
from .intelligence.mitre_mapping import MitreMapping
from .models.core import LogEvent, ActorProfile, ThreatCampaign

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sigma_probe.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def enrich_event_worker(event: LogEvent) -> LogEvent:
    """Worker function for parallel enrichment"""
    event.calculate_features()
    return event

class HeliosPipeline:
    """Enhanced pipeline with context sharing, evidence trail, and parallel processing"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.context = {}  # Shared context between stages
        self.evidence_summary = []
        
        # Initialize pipeline stages
        self._initialize_stages()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    def _initialize_stages(self):
        """Initialize all pipeline stages"""
        # Ingestion stage
        self.ingestion = LogIngestionStage(self.config.get('ingestion', {}))
        
        # Enrichment stage (simplified)
        self.enrichment = EnrichmentStage(self.config.get('enrichment', {}))
        
        # Profiling stage
        self.profiling = ActorProfilingStage(self.config.get('profiling', {}))
        
        # Detection stages
        detection_config = self.config.get('detection', {})
        self.detectors = []
        
        detector_classes = {
            'FFTDetector': FFTDetector,
            'GraphDetector': GraphDetector,
            'AnomalyDetector': AnomalyDetector,
            'BehavioralClusteringDetector': BehavioralClusteringDetector,
            'MetaDetector': MetaDetector
        }
        
        for detector_name in detection_config.get('detectors', []):
            if detector_name in detector_classes:
                detector_config = detection_config.get(f'{detector_name.lower()}_detector', {})
                detector = detector_classes[detector_name](detector_config)
                self.detectors.append(detector)
                logger.info(f"Initialized detector: {detector_name}")
        
        # Scoring engine
        scoring_config = self.config.get('scoring_engine', {})
        self.scoring_engine = ScoringEngine(scoring_config)
        
        # Narrative engine
        self.narrative_engine = NarrativeEngine(self.config.get('recommendations', {}))
        
        # MITRE mapping
        self.mitre_mapping = MitreMapping()
        
        # Reporting stage
        self.reporting = ReportingStage(self.config.get('reporting', {}))
    
    def run(self) -> Dict[str, Any]:
        """Run the complete pipeline with context sharing and parallel processing"""
        logger.info("Starting SIGMA-PROBE Helios pipeline")
        start_time = datetime.now()
        
        try:
            # Stage 1: Ingestion
            logger.info("=== Stage 1: Ingestion ===")
            events = self.ingestion.process()
            logger.info(f"Ingested {len(events)} events")
            
            # Stage 2: Enrichment with parallel processing
            logger.info("=== Stage 2: Enrichment ===")
            enriched_events = self._parallel_enrichment(events)
            logger.info(f"Enriched {len(enriched_events)} events")
            
            # Stage 2.5: IoC Integration
            logger.info("=== Stage 2.5: IoC Integration ===")
            if 'ioc_feeds' in self.config:
                self.ioc_manager = IoCManager(self.config['ioc_feeds'])
                self.ioc_manager.update_feeds()
                logger.info("IoC feeds updated")
            
            # Stage 3: Profiling
            logger.info("=== Stage 3: Profiling ===")
            profiling_context = {'events': enriched_events}
            profiling_result = self.profiling.process(profiling_context)
            actors = list(profiling_result.get('actors', {}).values())
            logger.info(f"Created {len(actors)} actor profiles")
            
            # Stage 4: Detection with Context Sharing
            logger.info("=== Stage 4: Detection ===")
            for detector in self.detectors:
                logger.info(f"Running {detector.name}")
                context_update = detector.detect(actors, self.context)
                self.context.update(context_update)
                logger.info(f"Context updated by {detector.name}")
            
            # Stage 5: Scoring with Context
            logger.info("=== Stage 5: Scoring ===")
            scored_actors = self.scoring_engine.score_actors(actors, self.context)
            logger.info(f"Scored {len(scored_actors)} actors")
            
            # Stage 6: Campaign Clustering
            logger.info("=== Stage 6: Campaign Clustering ===")
            campaigns = self.scoring_engine.cluster_campaigns(scored_actors, self.context)
            logger.info(f"Created {len(campaigns)} campaigns")
            
            # Stage 7: Recommendations & MITRE Mapping
            logger.info("=== Stage 7: Recommendations & MITRE Mapping ===")
            recommendations = self.narrative_engine.generate_recommendations(scored_actors, campaigns)
            
            # Add MITRE techniques to actors and campaigns
            for actor in scored_actors:
                actor.mitre_techniques = self.mitre_mapping.get_all_techniques_for_actor(actor)
            
            for campaign in campaigns:
                campaign.mitre_techniques = self.mitre_mapping.get_all_techniques_for_campaign(campaign)
            
            logger.info(f"Generated {len(recommendations)} recommendations")
            
            # Stage 8: Reporting
            logger.info("=== Stage 8: Reporting ===")
            report_data = self._prepare_report_data(scored_actors, campaigns, recommendations)
            reports = self.reporting.generate_reports(report_data)
            
            # Calculate execution time
            execution_time = datetime.now() - start_time
            
            # Print evidence summary
            self._print_evidence_summary(scored_actors, campaigns)
            
            # Print context summary
            self._print_context_summary()
            
            logger.info(f"Pipeline completed in {execution_time}")
            
            return {
                'actors': scored_actors,
                'campaigns': campaigns,
                'context': self.context,
                'execution_time': execution_time,
                'reports': reports
            }
            
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            raise
    
    def _parallel_enrichment(self, events: List[LogEvent]) -> List[LogEvent]:
        """Process events in parallel using multiprocessing"""
        pipeline_config = self.config.get('pipeline', {})
        parallel_config = pipeline_config.get('parallel', {})
        
        if parallel_config.get('enabled', False):
            max_workers = parallel_config.get('max_workers', min(4, cpu_count()))
            logger.info(f"Using parallel processing with {max_workers} workers")
            
            # Process events in parallel
            with Pool(processes=max_workers) as pool:
                enriched_events = pool.map(enrich_event_worker, events)
            
            return enriched_events
        else:
            # Fallback to sequential processing
            logger.info("Using sequential processing")
            return self.enrichment.process(events)
    
    def _prepare_report_data(self, actors: List[ActorProfile], campaigns: List[ThreatCampaign], 
                           recommendations: List[Any] = None) -> Dict[str, Any]:
        """Prepare data for reporting"""
        return {
            'actors': actors,
            'campaigns': campaigns,
            'recommendations': recommendations if recommendations else [],
            'context': self.context,
            'pipeline_config': self.config,
            'generated_at': datetime.now().isoformat()
        }
    
    def _print_evidence_summary(self, actors: List[ActorProfile], campaigns: List[ThreatCampaign]):
        """Print a summary of evidence trails"""
        print("\n" + "="*80)
        print("EVIDENCE TRAIL SUMMARY")
        print("="*80)
        
        # Actor evidence summary
        print(f"\nACTOR EVIDENCE ({len(actors)} actors):")
        print("-" * 60)
        
        for i, actor in enumerate(actors[:5]):  # Show first 5 actors
            print(f"\nActor {i+1}: {actor.ip_address}")
            print(f"  Tags: {', '.join(actor.tags) if actor.tags else 'None'}")
            print(f"  Threat Score: {getattr(actor, 'threat_score', 0.0):.2f}")
            print(f"  Evidence Entries: {len(actor.evidence_trail)}")
            
            # Show recent evidence
            recent_evidence = actor.evidence_trail[-3:] if actor.evidence_trail else []
            for evidence in recent_evidence:
                print(f"    - {evidence['source']}: {evidence['details']}")
        
        if len(actors) > 5:
            print(f"\n... and {len(actors) - 5} more actors")
        
        # Campaign evidence summary
        print(f"\nCAMPAIGN EVIDENCE ({len(campaigns)} campaigns):")
        print("-" * 60)
        
        for i, campaign in enumerate(campaigns):
            print(f"\nCampaign {i+1}: {campaign.campaign_id}")
            print(f"  Type: {campaign.campaign_type}")
            print(f"  Actors: {len(campaign.actors)}")
            print(f"  Threat Score: {campaign.threat_score:.2f}")
            print(f"  Primary Tags: {', '.join(campaign.primary_tags) if campaign.primary_tags else 'None'}")
            print(f"  Evidence Entries: {len(campaign.evidence_trail)}")
            
            # Show recent evidence
            recent_evidence = campaign.evidence_trail[-2:] if campaign.evidence_trail else []
            for evidence in recent_evidence:
                print(f"    - {evidence['source']}: {evidence['details']}")
    
    def _print_context_summary(self):
        """Print a summary of shared context"""
        print("\n" + "="*80)
        print("CONTEXT SUMMARY")
        print("="*80)
        
        for context_key, context_data in self.context.items():
            print(f"\n{context_key.upper()}:")
            if isinstance(context_data, dict):
                for key, value in context_data.items():
                    print(f"  {key}: {value}")
            else:
                print(f"  {context_data}")

def main():
    """Main entry point"""
    try:
        # Initialize and run pipeline
        pipeline = HeliosPipeline()
        results = pipeline.run()
        
        print(f"\nPipeline completed successfully!")
        print(f"Processed {len(results['actors'])} actors")
        print(f"Created {len(results['campaigns'])} campaigns")
        print(f"Execution time: {results['execution_time']}")
        
        return results
        
    except Exception as e:
        logger.error(f"Pipeline execution failed: {e}")
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    main() 