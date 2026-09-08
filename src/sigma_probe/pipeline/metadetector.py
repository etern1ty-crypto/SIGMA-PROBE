"""Evidence synthesis without invented attribution or confidence inflation."""
from __future__ import annotations

from ..models.core import BEHAVIOR_TAGS, PAYLOAD_TAGS, Evidence
from .base import AnalysisContext


class MetaDetector:
    def process(self, context: AnalysisContext) -> None:
        count = 0
        for actor in context.actors:
            if actor.suppressed:
                continue
            families = []
            if actor.tags & PAYLOAD_TAGS:
                families.append('request_payload')
            if actor.tags & BEHAVIOR_TAGS:
                families.append('request_behavior')
            if 'IOC_MATCH' in actor.tags:
                families.append('local_intelligence')
            if len(families) >= 2:
                actor.tags.add('MULTIPLE_SIGNALS')
                actor.add_evidence(Evidence(
                    source='MetaDetector', kind='MULTIPLE_SIGNALS',
                    details='Several signal families are present; they are not statistically independent proof of compromise.',
                    confidence=0.7, metrics={'families': ', '.join(families)},
                ))
                count += 1
        context.summary['meta'] = {'actors_with_multiple_signal_families': count}
