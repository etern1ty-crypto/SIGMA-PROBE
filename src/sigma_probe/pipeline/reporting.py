"""A single privacy-safe report projection and atomic multi-format publication."""
from __future__ import annotations

import errno
import hashlib
import html
import json
import logging
import os
import shutil
import tempfile
import uuid
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from .. import __version__
from ..config import Settings
from ..models.core import AnalysisResult
from ..privacy import PrivacyProjector, display_text
from ..validation import SigmaProbeError

logger = logging.getLogger(__name__)


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f'Unsupported report type: {type(value).__name__}')


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False, default=_json_default) + '\n'


def build_report(result: AnalysisResult, config: Settings, projector: PrivacyProjector) -> dict[str, Any]:
    severity = Counter(actor.severity for actor in result.actors if not actor.suppressed)
    actors = []
    for actor in result.actors:
        evidence = []
        for item in actor.evidence_trail:
            entry = asdict(item)
            if 'group_id' in entry['metrics']:
                entry['metrics']['group_id'] = projector.identifier(entry['metrics']['group_id'], 'group')
            for reference in entry['references']:
                reference['url'] = projector.url(reference['url'])
            evidence.append(entry)
        actors.append({
            'ip_address': projector.identifier(actor.ip_address), 'score': actor.threat_score,
            'severity': actor.severity, 'suppressed': actor.suppressed,
            'tags': sorted(actor.tags), 'score_breakdown': actor.score_breakdown,
            'metrics': {
                'requests': actor.total_requests, 'unique_paths': actor.unique_urls,
                'response_bytes': actor.total_response_bytes,
                'error_ratio': round(actor.error_ratio, 6), 'avg_url_entropy': round(actor.avg_entropy, 6),
                'first_seen': actor.first_seen.isoformat() if actor.first_seen else None,
                'last_seen': actor.last_seen.isoformat() if actor.last_seen else None,
            },
            'behavior': actor.behavioral_signatures, 'evidence': evidence,
            'mitre_techniques': actor.mitre_techniques,
        })
    recommendations = []
    for recommendation in result.recommendations:
        item = asdict(recommendation)
        item['actor_ids'] = [projector.identifier(value) for value in item['actor_ids']]
        recommendations.append(item)
    sources = []
    for source in result.ingestion.sources:
        item = asdict(source)
        item['name'] = display_text(item['name'], 256)
        sources.append(item)
    return {
        'schema_version': '1.0',
        'metadata': {
            'tool': 'SIGMA-PROBE', 'version': __version__, 'site': config.site,
            'generated_at': result.generated_at.isoformat(),
            'elapsed_seconds': round(result.elapsed_seconds, 6),
            'input_status': 'partial' if result.ingestion.partial else 'complete',
            'config_sha256': hashlib.sha256(json_text(config.to_dict()).encode('utf-8')).hexdigest(),
            'privacy': {'query_included': config.privacy.include_query, 'ip_pseudonymization': config.privacy.anonymize_ips, 'key_mode': projector.key_mode if config.privacy.anonymize_ips else 'not_applicable'},
            'limitations': [
                'Signals describe observed requests, not proven exploitation or operator identity.',
                'Scores prioritize review; evidence confidence is heuristic, not a calibrated probability.',
                'HTTP 200 and matching ATT&CK context do not establish compromise.',
                'One run covers one site and the explicitly supplied files; no live collection or automatic blocking.',
                'IP pseudonyms and query removal are not complete PII anonymization; URL paths may contain sensitive values.',
            ],
        },
        'summary': {
            'accepted_events': result.ingestion.total('accepted'), 'actors': len(result.actors),
            'high': severity['high'], 'medium': severity['medium'], 'low': severity['low'],
            'info': severity['info'], 'suppressed': sum(a.suppressed for a in result.actors),
            'correlation_groups': len(result.campaigns), 'invalid_lines': result.ingestion.total('invalid'),
            'filtered_events': result.ingestion.total('filtered'),
        },
        'inputs': sources, 'parse_errors': result.ingestion.errors,
        'detectors': result.detector_summary,
        'actors': actors,
        'campaigns': [
            {'id': projector.identifier(c.campaign_id, 'group'), 'type': c.campaign_type,
             'mean_score': c.threat_score, 'actors': [projector.identifier(a.ip_address) for a in c.actors],
             'tags': c.primary_tags, 'mitre_techniques': c.mitre_techniques}
            for c in result.campaigns
        ],
        'recommendations': recommendations,
    }


def _escape(value: Any) -> str:
    return html.escape(display_text(str(value), 16_384), quote=True)


def render_html(data: dict[str, Any], config: Settings) -> str:
    """Every dynamic scalar is escaped. No attacker URL becomes a link."""
    esc = _escape
    summary, meta = data['summary'], data['metadata']
    css = files('sigma_probe').joinpath('assets/report.css').read_text(encoding='utf-8')
    parts = [
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
        f'<title>SIGMA-PROBE · {esc(meta["site"])}</title><style>{css}</style></head><body><main>',
        '<div class="brand">SIGMA / PROBE</div><p class="eyebrow">Локальный анализ access-логов</p>',
        f'<h1>Очередь расследования<br>{esc(meta["site"])}</h1>',
        '<p class="lead">От запросов к проверяемым сигналам: приоритет, строки-источники и конкретные следующие шаги. Без автоматических блокировок.</p>',
        f'<p class="meta">{esc(meta["generated_at"])} · v{esc(meta["version"])} · {esc(meta["input_status"])}</p>',
    ]
    if summary['invalid_lines']:
        parts.append(f'<div class="note warning"><strong>Входные данные обработаны частично.</strong> Некорректных строк: {esc(summary["invalid_lines"])}. Они не участвовали в детекции; отчёт не означает полный охват.</div>')
    if config.privacy.include_query:
        parts.append('<div class="note warning"><strong>Query-параметры включены.</strong> Отчёт может содержать токены и персональные данные. Проверьте перед передачей.</div>')
    parts.append('<section aria-label="Сводка" class="kpis">')
    for key, label in (('accepted_events', 'Запросов принято'), ('actors', 'Источников / IP'), ('high', 'Высокий приоритет'), ('correlation_groups', 'Групп сходства')):
        parts.append(f'<div class="kpi"><strong>{esc(summary[key])}</strong><span>{label}</span></div>')
    parts.append('</section><div class="note">Это сигналы для проверки, не доказанные взломы. Периодичность и сходство запросов не подтверждают ботнет или общую организацию.</div>')
    parts.append('<h2>01 / Приоритеты</h2>')
    limit = config.reporting.max_display_actors
    parts.append(f'<p class="meta">Показано {min(len(data["actors"]), limit)} из {len(data["actors"])} источников. Полная детализация доступна в формате JSON. Подавлено allowlist: {summary["suppressed"]}.</p>')
    if not data['actors']:
        parts.append('<div class="empty">В заданном наборе файлов и временном окне нет принятых событий. Это не заключение о безопасности сайта.</div>')
    for actor in data['actors'][:limit]:
        level = actor['severity']
        # Severity is produced internally; whitelist also protects this
        # renderer when used directly with an external JSON object.
        level_class = level if level in ('high', 'medium', 'low', 'info') else 'info'
        parts.append(f'<details class="actor"><summary><span class="actor-id">{esc(actor["ip_address"])}</span><span class="badge {level_class}">{esc("allowlist" if actor["suppressed"] else level)}</span><span class="score">{esc(actor["score"])} / 100</span></summary><div class="body">')
        metrics = actor['metrics']
        parts.append(f'<div class="facts"><span>Запросов: {esc(metrics["requests"])}</span><span>Путей: {esc(metrics["unique_paths"])}</span><span>Доля ошибок: {esc(metrics["error_ratio"])}</span></div>')
        parts.append(f'<p class="meta">{esc(metrics["first_seen"])} → {esc(metrics["last_seen"])}</p>')
        parts.append('<div class="tags">' + ''.join(f'<span class="tag">{esc(tag)}</span>' for tag in actor['tags']) + '</div>')
        parts.append('<h3>Из чего складывается приоритет</h3><div class="table-wrap"><table><thead><tr><th scope="col">Сигнал</th><th scope="col">Баллы</th></tr></thead><tbody>')
        for key, value in actor['score_breakdown'].items():
            parts.append(f'<tr><td>{esc(key)}</td><td class="number">{esc(value)}</td></tr>')
        parts.append('</tbody></table></div><h3>Основания</h3>')
        for item in actor['evidence'][:config.reporting.max_evidence_per_actor]:
            parts.append(f'<div class="evidence"><p><strong>{esc(item["kind"])}</strong> · {esc(item["source"])}</p><p>{esc(item["details"])}</p>')
            if item['metrics']:
                parts.append('<p class="meta">' + ' · '.join(f'{esc(key)}: {esc(value)}' for key, value in item['metrics'].items()) + '</p>')
            parts.append('<ul class="refs">')
            for reference in item['references']:
                parts.append(f'<li>{esc(reference["input_id"])}:{esc(reference["line"])} · {esc(reference["timestamp"])} · HTTP {esc(reference["status_code"])}<br><code>{esc(reference["method"])} {esc(reference["url"])}</code></li>')
            parts.append('</ul></div>')
        if len(actor['evidence']) > config.reporting.max_evidence_per_actor:
            parts.append('<p class="meta">Остальные основания доступны в JSON-отчёте.</p>')
        if actor['mitre_techniques']:
            parts.append('<p class="meta">ATT&amp;CK, только контекст: ' + '; '.join(f'{esc(t["id"])} — {esc(t["name"])}' for t in actor['mitre_techniques']) + '</p>')
        parts.append('</div></details>')
    parts.append('<h2>02 / Похожая активность</h2>')
    if not data['campaigns']:
        parts.append('<p class="empty">Групп, удовлетворяющих настроенным условиям сходства и времени, не найдено.</p>')
    for campaign in data['campaigns']:
        parts.append(f'<div class="group"><h3>{esc(campaign["id"])}</h3><p class="members">{esc(", ".join(campaign["actors"]))}</p><p>Средний приоритет: <strong>{esc(campaign["mean_score"])}</strong> / 100</p><p class="meta">Эвристическая группа, не атрибуция кампании.</p></div>')
    parts.append('<h2>03 / Следующие шаги</h2>')
    if not data['recommendations']:
        parts.append('<p class="empty">Нет приоритетных рекомендаций по принятым событиям. Проверьте полноту входных файлов и окно наблюдения.</p>')
    for item in data['recommendations']:
        parts.append(f'<article class="playbook"><p class="eyebrow">{esc(item["priority"])}</p><h3>{esc(item["title"])}</h3><p class="members">{esc(", ".join(item["actor_ids"]))}</p><ol>')
        parts.extend(f'<li>{esc(action)}</li>' for action in item['action_items'])
        parts.append(f'</ol><p class="meta">{esc(item["rationale"])}</p></article>')
    parts.append('<h2>04 / Происхождение данных</h2><div class="table-wrap"><table><thead><tr><th scope="col">Источник</th><th scope="col">Принято</th><th scope="col">Ошибок</th><th scope="col">Вне окна</th></tr></thead><tbody>')
    for source in data['inputs']:
        parts.append(f'<tr><td>{esc(source["input_id"])} · {esc(source["name"])}</td><td>{esc(source["accepted"])}</td><td>{esc(source["invalid"])}</td><td>{esc(source["filtered"])}</td></tr>')
    parts.append('</tbody></table></div><p class="meta">SHA-256 конфигурации: <code>' + esc(meta['config_sha256']) + '</code></p>')
    parts.append('<footer>Сформировано локально. Исходные логи не отправлялись в сеть. Query скрывается по умолчанию; пути URL всё ещё могут содержать чувствительные данные. Отчёт нужно проверить перед передачей клиенту.</footer></main></body></html>')
    return ''.join(parts)


def render_text(data: dict[str, Any], config: Settings) -> str:
    lines = [f'SIGMA-PROBE {__version__} | {display_text(data["metadata"]["site"])}', 'LOCAL ACCESS-LOG TRIAGE — human review required', '', json_text(data['summary']).strip(), '']
    if data['summary']['invalid_lines']:
        lines.append('WARNING: partial input; malformed lines were not analyzed.')
    for actor in data['actors'][:config.reporting.max_display_actors]:
        lines.append(f'{actor["ip_address"]}  {actor["severity"].upper()}  {actor["score"]}/100  suppressed={actor["suppressed"]}')
        lines.append('Tags: ' + ', '.join(actor['tags']))
        for item in actor['evidence'][:config.reporting.max_evidence_per_actor]:
            lines.append(f'  {item["source"]}/{item["kind"]}: {display_text(item["details"])}')
            for ref in item['references']:
                lines.append(f'    {ref["input_id"]}:{ref["line"]} {ref["method"]} {ref["url"]} [{ref["status_code"]}]')
        lines.append('')
    lines.append('RECOMMENDATIONS')
    for item in data['recommendations']:
        lines.append(f'{item["priority"].upper()} — {item["title"]}')
        lines.extend('  - ' + action for action in item['action_items'])
    lines.extend(['', 'Complete actor/evidence records are available with JSON output.', 'A signal is not proof of compromise or a calibrated probability.'])
    return '\n'.join(lines) + '\n'


def _check_output_root(root: Path) -> Path:
    if root.is_symlink():
        raise SigmaProbeError('Output directory must not be a symlink')
    # Resolve trusted ancestor mounts once (/data and /var are often links).
    # The destination itself may not be a link, and bundle members are created
    # exclusively inside a new private directory beneath this resolved root.
    root = root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not root.is_dir():
        raise SigmaProbeError('Output path must be a directory')
    if os.name == 'posix' and root.stat().st_mode & 0o022:
        raise SigmaProbeError('Output directory must not be writable by group or others; use chmod 700')
    return root


class ReportingStage:
    def __init__(self, config: Settings) -> None:
        self.config = config

    def write(self, data: dict[str, Any]) -> dict[str, str]:
        root = _check_output_root(Path(self.config.reporting.output_dir).absolute())
        run_id = datetime.fromisoformat(data['metadata']['generated_at']).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:12]
        destination = root / run_id
        temporary: Path | None = Path(tempfile.mkdtemp(prefix='.sigma-probe-', dir=root))
        renderers = {'json': lambda: json_text(data), 'html': lambda: render_html(data, self.config), 'text': lambda: render_text(data, self.config)}
        extensions = {'json': 'json', 'html': 'html', 'text': 'txt'}
        result: dict[str, str] = {}
        try:
            for format_name in self.config.reporting.formats:
                content = renderers[format_name]()
                filename = f'report.{extensions[format_name]}'
                target = temporary / filename
                with target.open('x', encoding='utf-8', newline='\n') as handle:
                    if os.name == 'posix':
                        os.fchmod(handle.fileno(), 0o600)
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                result[format_name] = str(destination / filename)
            if destination.exists():
                raise SigmaProbeError('Report destination collision; run again')
            os.replace(temporary, destination)
            temporary = None
            if os.name == 'posix':
                descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    try:
                        os.fsync(descriptor)
                    except OSError as exc:
                        if exc.errno not in (errno.EINVAL, errno.ENOTSUP):
                            raise
                        logger.warning('Filesystem does not support directory fsync')
                finally:
                    os.close(descriptor)
        finally:
            if temporary is not None:
                shutil.rmtree(temporary)
        return result
