"""
Этап C: Профилирование Акторов (Actor Profiling)
Агрегация событий по IP-адресам и создание профилей акторов
"""

from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict
from sigma_probe.models.core import LogEvent, ActorProfile, PipelineContext
from sigma_probe.pipeline.base import PipelineStage


class ActorProfilingStage(PipelineStage):
    """Агрегирует события по IP-адресам и создает профили акторов"""
    
    def process(self, context: PipelineContext) -> PipelineContext:
        """Создает профили акторов из событий"""
        events = context.get('events', [])
        
        if not events:
            print("Нет событий для профилирования")
            context['actors'] = {}
            return context
        
        # Группировка событий по IP
        ip_events = defaultdict(list)
        for event in events:
            ip_events[str(event.source_ip)].append(event)
        
        # Создание профилей акторов
        actors = {}
        for ip_str, ip_events_list in ip_events.items():
            actor = self._create_actor_profile(ip_events_list)
            actors[ip_str] = actor
        
        print(f"Создано {len(actors)} профилей акторов")
        context['actors'] = actors
        return context
    
    def _create_actor_profile(self, events: List[LogEvent]) -> ActorProfile:
        """Создает профиль актора из списка событий"""
        if not events:
            raise ValueError("Нельзя создать профиль из пустого списка событий")
        
        # Базовые данные
        ip_address = events[0].source_ip
        event_count = len(events)
        
        # Временные рамки
        timestamps = [event.timestamp for event in events]
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        
        # Создание профиля
        profile = ActorProfile(
            ip_address=ip_address,
            event_count=event_count,
            first_seen=first_seen,
            last_seen=last_seen,
            events=events
        )
        
        return profile


class ActorEnrichmentStage(PipelineStage):
    """Дополнительное обогащение профилей акторов"""
    
    def process(self, context: PipelineContext) -> PipelineContext:
        """Обогащает профили акторов дополнительной информацией"""
        actors = context.get('actors', {})
        
        for ip_str, actor in actors.items():
            self._enrich_actor_profile(actor)
        
        context['actors'] = actors
        return context
    
    def _enrich_actor_profile(self, actor: ActorProfile):
        """Обогащает профиль актора дополнительными метриками"""
        events = actor.events
        
        if not events:
            return
        
        # Статистика по HTTP методам
        methods = [event.http_method for event in events]
        method_counts = {}
        for method in methods:
            method_counts[method] = method_counts.get(method, 0) + 1
        
        # Статистика по статус кодам
        status_codes = [event.status_code for event in events]
        status_counts = {}
        for status in status_codes:
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Статистика по URL
        urls = [event.url_normalized for event in events]
        unique_urls = len(set(urls))
        
        # Временные характеристики
        timestamps = [event.timestamp for event in events]
        time_span = (max(timestamps) - min(timestamps)).total_seconds()
        
        # Добавление в behavioral_signatures
        actor.behavioral_signatures.update({
            'method_distribution': method_counts,
            'status_distribution': status_counts,
            'unique_urls_count': unique_urls,
            'total_urls_count': len(urls),
            'time_span_seconds': time_span,
            'avg_events_per_second': len(events) / max(time_span, 1),
            'url_diversity_ratio': unique_urls / max(len(urls), 1)
        })
        
        # Анализ User-Agent
        user_agents = [event.user_agent for event in events]
        unique_agents = len(set(user_agents))
        actor.behavioral_signatures['unique_user_agents'] = unique_agents
        actor.behavioral_signatures['user_agent_diversity'] = unique_agents / max(len(user_agents), 1)