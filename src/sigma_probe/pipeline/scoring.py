"""Apply final scores after all detection and correlation tags exist."""
from __future__ import annotations

from ..config import ScoringConfig
from ..models.core import Evidence
from .base import AnalysisContext
from .rules_engine import ScoringRulesEngine


class ScoringEngine:
    def __init__(self, config: ScoringConfig) -> None:
        self.rules = ScoringRulesEngine(config)

    def process(self, context: AnalysisContext) -> None:
        for actor in context.actors:
            actor.threat_score, actor.score_breakdown = self.rules.calculate_score(actor)
            actor.severity = self.rules.severity(actor.threat_score)
            actor.add_evidence(Evidence(
                source='ScoringEngine', kind='risk_score',
                details='Triage priority on a 0–100 scale, not a probability or proof of exploitation.',
                confidence=1.0, metrics={'score': actor.threat_score, **actor.score_breakdown},
            ))
        for campaign in context.campaigns:
            campaign.update_metrics()
        context.actors.sort(key=lambda actor: (-actor.threat_score, actor.ip_address))
        context.summary['scoring'] = {
            'scale': '0..100', 'medium_threshold': self.rules.config.medium_threshold,
            'high_threshold': self.rules.config.high_threshold,
        }
