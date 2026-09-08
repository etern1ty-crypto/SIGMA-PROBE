"""A concrete, typed pipeline contract without no-op detector implementations."""
from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..models.core import ActorProfile, ThreatCampaign

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AnalysisContext:
    actors: list[ActorProfile]
    campaigns: list[ThreatCampaign] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


class Pipeline:
    def __init__(self, stages: Sequence[Callable[[AnalysisContext], None]]) -> None:
        self.stages = tuple(stages)

    def execute(self, context: AnalysisContext) -> AnalysisContext:
        for stage in self.stages:
            logger.debug('Running stage %s', stage.__qualname__)
            stage(context)
        return context
