from datetime import datetime, timedelta, timezone
from pathlib import Path

from sigma_probe.models.core import ActorProfile, LogEvent
from sigma_probe.pipeline.enrichment import EnrichmentStage

ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 9, 8, tzinfo=timezone.utc)


def event(url='/', ip='203.0.113.1', seconds=0, status=200, agent='', line=1):
    return EnrichmentStage().process(LogEvent(
        timestamp=BASE + timedelta(seconds=seconds), source_ip=ip, url=url,
        method='GET', status_code=status, user_agent=agent, line_number=line,
    ))


def actor(ip, urls, *, interval=5, start=0, status=404, agent=''):
    result = ActorProfile(ip_address=ip)
    for index, url in enumerate(urls):
        result.add_event(event(url, ip, start + index * interval, status, agent, index + 1))
    return result


def combined(ip='203.0.113.1', target='/', status=200, agent='Mozilla/5.0', stamp='08/Sep/2026:00:00:00 +0000', size='128'):
    return f'{ip} - - [{stamp}] "GET {target} HTTP/1.1" {status} {size} "-" "{agent}"\n'
