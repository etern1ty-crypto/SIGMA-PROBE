"""Human-review playbooks. Never issue firewall changes or execution commands."""
from __future__ import annotations

from ..models.core import ActorProfile, Recommendation

_PLAYBOOKS = (
    ('payload-review', {'LFI_RFI', 'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION'}, 'Проверить попытки эксплуатации приложения', (
        'Сопоставить указанные строки с error-логами приложения, WAF и серверной телеметрией.',
        'Не считать HTTP 200 доказательством успешной эксплуатации; проверить фактический ответ и побочные эффекты.',
        'Устранить подтверждённую причину в приложении; WAF-правило сначала проверить в наблюдательном режиме.',
    )),
    ('secret-path-review', {'SENSITIVE_PATH'}, 'Проверить доступность служебных файлов', (
        'Проверить, что .env, .git и резервные копии не выдаются веб-сервером.',
        'При подтверждённой выдаче секрета ограничить доступ и организовать его ротацию по процедуре инцидента.',
    )),
    ('authentication-review', {'AUTH_FAILURE_BURST'}, 'Разобрать серию отказов авторизации', (
        'Проверить реальные auth-события: access-log не содержит результата проверки пароля во всех приложениях.',
        'Оценить rate limiting и MFA; отделить общие NAT/proxy-адреса от отдельного клиента.',
        'Не блокировать подсети автоматически по одному агрегированному IP.',
    )),
    ('probe-review', {'ENUMERATION', 'AUTOMATED_SCAN', 'SCANNER_UA'}, 'Отделить разрешённые проверки от сканирования', (
        'Сопоставить источник с согласованными окнами сканирования и инвентарём мониторинга.',
        'Проверить корректность real client IP на доверенном reverse proxy.',
        'Вводить исключения только по проверенным IP/CIDR, не по легко подделываемому User-Agent.',
    )),
    ('ioc-review', {'IOC_MATCH'}, 'Подтвердить актуальность локального индикатора', (
        'Проверить происхождение, время действия и SHA-256 локального IoC snapshot.',
        'Сопоставить индикатор с request-level evidence; репутационное совпадение само по себе не подтверждает инцидент.',
    )),
    ('correlation-review', {'CORRELATED_ACTIVITY'}, 'Проверить похожую активность нескольких источников', (
        'Проверить общие подозрительные пути и временные интервалы внутри одного сайта.',
        'Не интерпретировать сходство как доказанный ботнет, общую организацию или канал C2.',
    )),
    ('errors-review', {'ERROR_BURST'}, 'Проверить всплеск HTTP-ошибок', (
        'Сопоставить ошибки с деплоем, health checks, rate limiting и отказами upstream.',
        'Искать запросы с содержательными признаками атаки, прежде чем предпринимать блокировки.',
    )),
)


class NarrativeEngine:
    def generate_recommendations(self, actors: list[ActorProfile]) -> list[Recommendation]:
        result = []
        priorities = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
        for identifier, tags, title, actions in _PLAYBOOKS:
            matched = [actor for actor in actors if not actor.suppressed and actor.threat_score > 0 and actor.tags & tags]
            if not matched:
                continue
            priority = max((actor.severity for actor in matched), key=priorities.__getitem__)
            result.append(Recommendation(
                id=identifier, priority=priority, title=title,
                actor_ids=sorted(actor.ip_address for actor in matched),
                action_items=list(actions),
                rationale='Рекомендация для ручного расследования; никаких действий на инфраструктуре не выполнено.',
            ))
        return sorted(result, key=lambda r: (-priorities[r.priority], r.id))
