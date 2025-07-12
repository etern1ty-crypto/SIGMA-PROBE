"""
SIGMA-PROBE Pipeline Architecture
Принцип 2: Не линейное выполнение, а конвейерная обработка (Pipeline)
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Iterator, Optional
from src.models.core import LogEvent, ActorProfile, ThreatCampaign, PipelineContext


class PipelineStage(ABC):
    """Базовый класс для всех этапов конвейера"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
    
    @abstractmethod
    def process(self, context: PipelineContext) -> PipelineContext:
        """Обрабатывает данные и возвращает обновленный контекст"""
        pass
    
    def __str__(self):
        return f"{self.name}"


class Enricher(PipelineStage):
    """Базовый класс для обогатителей признаков"""
    
    @abstractmethod
    def enrich(self, event: LogEvent) -> Dict[str, float]:
        """Обогащает событие признаками"""
        pass
    
    def process(self, context: PipelineContext) -> PipelineContext:
        """Обрабатывает поток событий и обогащает их"""
        events = context.get('events', [])
        
        for event in events:
            features = self.enrich(event)
            event.features.update(features)
        
        context['events'] = events
        return context


class Detector(PipelineStage):
    """Базовый класс для детекторов сигнатур"""
    
    @abstractmethod
    def detect(self, actors: Dict[str, ActorProfile]) -> Dict[str, ActorProfile]:
        """Анализирует профили акторов и добавляет сигнатуры"""
        pass
    
    def process(self, context: PipelineContext) -> PipelineContext:
        """Обрабатывает профили акторов"""
        actors = context.get('actors', {})
        updated_actors = self.detect(actors)
        context['actors'] = updated_actors
        return context


class Pipeline:
    """Основной конвейер обработки"""
    
    def __init__(self, stages: List[PipelineStage]):
        self.stages = stages
    
    def execute(self, initial_context: PipelineContext) -> PipelineContext:
        """Выполняет все этапы конвейера"""
        context = initial_context.copy()
        
        for stage in self.stages:
            print(f"Выполняется этап: {stage}")
            context = stage.process(context)
        
        return context
    
    def add_stage(self, stage: PipelineStage):
        """Добавляет новый этап в конвейер"""
        self.stages.append(stage)
    
    def get_stage(self, stage_name: str) -> Optional[PipelineStage]:
        """Возвращает этап по имени"""
        for stage in self.stages:
            if stage.name == stage_name:
                return stage
        return None 