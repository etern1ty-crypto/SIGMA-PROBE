"""Bounded additive risk, never eval(), dynamic imports or global contagion."""
from __future__ import annotations

import math

from ..config import ScoringConfig
from ..models.core import ActorProfile, PAYLOAD_TAGS


class ScoringRulesEngine:
    def __init__(self, config: ScoringConfig) -> None:
        self.config = config

    def calculate_score(self, actor: ActorProfile) -> tuple[int, dict[str, int]]:
        if actor.suppressed:
            return 0, {'allowlist_suppression': 0}
        contributions = {tag: self.config.weights[tag] for tag in sorted(actor.tags) if self.config.weights.get(tag, 0) > 0}
        payload_requests = sum(bool(event.heuristic_flags & PAYLOAD_TAGS) for event in actor.events)
        # A request matching multiple payload tags counts ONCE for repetition.
        if payload_requests > 1 and any(self.config.weights.get(tag, 0) for tag in actor.tags & PAYLOAD_TAGS):
            bonus = min(self.config.repetition_bonus_cap, 3 * math.floor(math.log2(payload_requests)))
            if bonus:
                contributions['repeated_payload_requests'] = bonus
        raw = sum(contributions.values())
        if raw > 100:
            contributions['cap_adjustment'] = 100 - raw
        return min(100, raw), contributions

    def severity(self, score: int) -> str:
        if score >= self.config.high_threshold:
            return 'high'
        if score >= self.config.medium_threshold:
            return 'medium'
        return 'low' if score > 0 else 'info'
