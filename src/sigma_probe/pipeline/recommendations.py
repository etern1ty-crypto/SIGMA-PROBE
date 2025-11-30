"""
SIGMA-PROBE Narrative Engine
"Recommendation Engine" - Генератор Рекомендаций

Принцип: Система не просто показывает проблему, она предлагает решение.
Это та самая "магия", за которую компании платят огромные деньги.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass

from ..models.core import ActorProfile, ThreatCampaign

logger = logging.getLogger(__name__)

@dataclass
class Recommendation:
    """Структура рекомендации"""
    priority: str  # HIGH, MEDIUM, LOW
    category: str  # IMMEDIATE_ACTION, INVESTIGATION, MONITORING
    title: str
    description: str
    action_items: List[str]
    mitre_techniques: List[str]
    confidence: float

class NarrativeEngine:
    """Движок генерации рекомендаций и повествования"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.recommendations = []
        
    def generate_recommendations(self, actors: List[ActorProfile], 
                               campaigns: List[ThreatCampaign]) -> List[Recommendation]:
        """Генерирует рекомендации на основе анализа акторов и кампаний"""
        logger.info("Generating actionable recommendations...")
        
        recommendations = []
        
        # Анализ акторов
        for actor in actors:
            actor_recs = self._analyze_actor(actor)
            recommendations.extend(actor_recs)
        
        # Анализ кампаний
        for campaign in campaigns:
            campaign_recs = self._analyze_campaign(campaign)
            recommendations.extend(campaign_recs)
        
        # Глобальные рекомендации
        global_recs = self._generate_global_recommendations(actors, campaigns)
        recommendations.extend(global_recs)
        
        # Сортировка по приоритету
        recommendations.sort(key=lambda x: self._priority_score(x.priority), reverse=True)
        
        self.recommendations = recommendations
        logger.info(f"Generated {len(recommendations)} recommendations")
        
        return recommendations
    
    def _analyze_actor(self, actor: ActorProfile) -> List[Recommendation]:
        """Анализирует отдельного актора и генерирует рекомендации"""
        recommendations = []
        
        # Ботнет с SQL-инъекциями
        if {'CONFIRMED_BOTNET', 'SQLI_ATTACK'}.issubset(actor.tags):
            recommendations.append(Recommendation(
                priority="HIGH",
                category="IMMEDIATE_ACTION",
                title=f"Botnet SQL Injection Attack - {actor.ip}",
                description=f"Актор {actor.ip} с высокой долей уверенности является частью ботнета, "
                          f"проводящего автоматизированные SQL-инъекции. "
                          f"Активность: {actor.first_seen} - {actor.last_seen}",
                action_items=[
                    f"Немедленно заблокировать IP {actor.ip} на файрволе (уровень 7)",
                    f"Проверить логи базы данных на предмет успешных запросов за период "
                    f"с {actor.first_seen} по {actor.last_seen}",
                    "Провести аудит всех SQL-запросов за последние 24 часа",
                    "Проверить права доступа к базе данных"
                ],
                mitre_techniques=["T1190", "T1071.001"],
                confidence=0.95
            ))
        
        # LFI/RFI атаки
        elif {'LFI_ATTACK', 'CONFIRMED_SOPHISTICATED'}.issubset(actor.tags):
            recommendations.append(Recommendation(
                priority="HIGH",
                category="IMMEDIATE_ACTION",
                title=f"Sophisticated LFI Attack - {actor.ip}",
                description=f"Обнаружена изощренная LFI-атака от {actor.ip}. "
                          f"Актор демонстрирует адаптивное поведение и попытки обхода защиты.",
                action_items=[
                    f"Блокировать IP {actor.ip} на уровне веб-сервера",
                    "Провести аудит прав доступа для веб-сервера",
                    "Проверить все скрипты, работающие с инклудами (include, require)",
                    "Обновить WAF правила для блокировки path traversal",
                    "Проверить логи на предмет успешных попыток доступа к системным файлам"
                ],
                mitre_techniques=["T1083", "T1190"],
                confidence=0.9
            ))
        
        # Координированные атаки
        elif {'CONFIRMED_COORDINATED', 'BOT_ACTIVITY'}.issubset(actor.tags):
            recommendations.append(Recommendation(
                priority="MEDIUM",
                category="INVESTIGATION",
                title=f"Coordinated Bot Activity - {actor.ip}",
                description=f"Актор {actor.ip} участвует в координированной атаке. "
                          f"Обнаружены паттерны взаимодействия с другими акторами.",
                action_items=[
                    f"Мониторить активность IP {actor.ip}",
                    "Анализировать связи с другими подозрительными IP",
                    "Проверить, не является ли частью DDoS атаки",
                    "Обновить правила IDS/IPS для подобных паттернов"
                ],
                mitre_techniques=["T1071.001", "T1595"],
                confidence=0.8
            ))
        
        # Изолированные индикаторы
        elif 'ISOLATED_INDICATOR' in actor.tags:
            recommendations.append(Recommendation(
                priority="LOW",
                category="MONITORING",
                title=f"Isolated Threat Indicator - {actor.ip}",
                description=f"Обнаружен единичный индикатор угрозы от {actor.ip}. "
                          f"Требуется дополнительный мониторинг.",
                action_items=[
                    f"Добавить IP {actor.ip} в список для мониторинга",
                    "Настроить алерты при повторной активности",
                    "Провести базовую проверку репутации IP"
                ],
                mitre_techniques=["T1595"],
                confidence=0.6
            ))
        
        return recommendations
    
    def _analyze_campaign(self, campaign: ThreatCampaign) -> List[Recommendation]:
        """Анализирует кампанию и генерирует рекомендации"""
        recommendations = []
        
        # Координированные LFI атаки
        if {'COORDINATED_ATTACK', 'LFI_ATTACK'}.issubset(campaign.primary_tags):
            recommendations.append(Recommendation(
                priority="HIGH",
                category="IMMEDIATE_ACTION",
                title=f"Coordinated LFI Campaign - {campaign.campaign_id}",
                description=f"Обнаружена скоординированная атака типа LFI с участием "
                          f"{len(campaign.actors)} акторов. Это указывает на целенаправленную "
                          f"попытку получить доступ к файловой системе.",
                action_items=[
                    "Провести аудит прав доступа для веб-сервера",
                    "Проверить все скрипты, работающие с инклудами (include, require)",
                    "Обновить WAF правила для блокировки path traversal",
                    "Проверить логи на предмет успешных попыток доступа",
                    "Рассмотреть возможность обновления веб-приложений"
                ],
                mitre_techniques=["T1083", "T1190", "T1071.001"],
                confidence=0.9
            ))
        
        # Ботнет кампании
        elif {'BOTNET_ACTIVITY', 'MULTI_VECTOR'}.issubset(campaign.primary_tags):
            recommendations.append(Recommendation(
                priority="HIGH",
                category="IMMEDIATE_ACTION",
                title=f"Multi-Vector Botnet Campaign - {campaign.campaign_id}",
                description=f"Обнаружена кампания ботнета с множественными векторами атак. "
                          f"Участвует {len(campaign.actors)} акторов.",
                action_items=[
                    "Блокировать все IP из кампании на уровне сети",
                    "Провести анализ трафика для выявления C&C серверов",
                    "Обновить правила IDS/IPS",
                    "Проверить все системы на предмет компрометации",
                    "Рассмотреть возможность привлечения IR команды"
                ],
                mitre_techniques=["T1071.001", "T1190", "T1595"],
                confidence=0.95
            ))
        
        return recommendations
    
    def _generate_global_recommendations(self, actors: List[ActorProfile], 
                                       campaigns: List[ThreatCampaign]) -> List[Recommendation]:
        """Генерирует глобальные рекомендации на основе общей картины"""
        recommendations = []
        
        # Статистика
        high_threat_actors = [a for a in actors if getattr(a, 'threat_score', 0) > 8.0]
        confirmed_botnets = [a for a in actors if 'CONFIRMED_BOTNET' in a.tags]
        coordinated_attacks = [c for c in campaigns if 'COORDINATED_ATTACK' in c.primary_tags]
        
        # Рекомендации по общей картине
        if len(high_threat_actors) > 5:
            recommendations.append(Recommendation(
                priority="HIGH",
                category="IMMEDIATE_ACTION",
                title="High Volume of Threat Actors Detected",
                description=f"Обнаружено {len(high_threat_actors)} высокоугрожающих акторов. "
                          f"Это указывает на возможную целенаправленную атаку.",
                action_items=[
                    "Провести полный аудит безопасности инфраструктуры",
                    "Обновить все системы безопасности",
                    "Рассмотреть возможность привлечения IR команды",
                    "Проверить все точки входа в систему"
                ],
                mitre_techniques=["T1190", "T1595"],
                confidence=0.8
            ))
        
        if len(confirmed_botnets) > 3:
            recommendations.append(Recommendation(
                priority="HIGH",
                category="IMMEDIATE_ACTION",
                title="Multiple Botnet Activities Detected",
                description=f"Обнаружено {len(confirmed_botnets)} подтвержденных ботнетов. "
                          f"Возможно, инфраструктура находится под атакой.",
                action_items=[
                    "Провести анализ сетевого трафика",
                    "Проверить все системы на малвары",
                    "Обновить антивирусные решения",
                    "Проверить логи DNS на подозрительную активность"
                ],
                mitre_techniques=["T1071.001", "T1595"],
                confidence=0.9
            ))
        
        return recommendations
    
    def _priority_score(self, priority: str) -> int:
        """Возвращает числовой приоритет для сортировки"""
        return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(priority, 0)
    
    def get_recommendations_summary(self) -> Dict[str, Any]:
        """Возвращает сводку рекомендаций"""
        if not self.recommendations:
            return {"message": "No recommendations generated"}
        
        high_priority = [r for r in self.recommendations if r.priority == "HIGH"]
        medium_priority = [r for r in self.recommendations if r.priority == "MEDIUM"]
        low_priority = [r for r in self.recommendations if r.priority == "LOW"]
        
        return {
            "total_recommendations": len(self.recommendations),
            "high_priority": len(high_priority),
            "medium_priority": len(medium_priority),
            "low_priority": len(low_priority),
            "immediate_actions": len([r for r in self.recommendations if r.category == "IMMEDIATE_ACTION"]),
            "investigations": len([r for r in self.recommendations if r.category == "INVESTIGATION"]),
            "monitoring": len([r for r in self.recommendations if r.category == "MONITORING"])
        } 