"""Finite, bounded Combined/Common/JSONL input with traceable error counts."""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import re
import sys
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from ..config import InputConfig, LimitsConfig
from ..models.core import IngestionStats, InputFileStats, LogEvent
from ..validation import LimitExceeded, SigmaProbeError, canonical_ip, utc_datetime

logger = logging.getLogger(__name__)
_QUOTED = r'(?:[^"\\]|\\.)*'
_LOG = re.compile(
    rf'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    rf'"(?P<request>{_QUOTED})"\s+(?P<status>[0-9][0-9][0-9])\s+(?P<size>[0-9]+|-)'
    rf'(?:\s+"(?P<referer>{_QUOTED})"\s+"(?P<agent>{_QUOTED})")?\s*$'
)
_TIME = re.compile(r'^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$')
_MONTHS = {name: i for i, name in enumerate(('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), 1)}
_ESCAPES = re.compile(r'\\x([0-9a-fA-F]{2})|\\(["\\])')


def _unescape(value: str) -> str:
    return _ESCAPES.sub(lambda m: chr(int(m[1], 16)) if m[1] else m[2], value)


def _combined_time(value: str) -> datetime:
    match = _TIME.fullmatch(value)
    if not match:
        raise SigmaProbeError('Invalid access-log timestamp')
    day, month, year, hour, minute, second, sign, offset_h, offset_m = match.groups()
    try:
        if int(offset_h) > 23 or int(offset_m) > 59:
            raise ValueError('Invalid UTC offset')
        offset = timedelta(hours=int(offset_h), minutes=int(offset_m))
        if sign == '-':
            offset = -offset
        return datetime(int(year), _MONTHS[month.title()], int(day), int(hour), int(minute), int(second), tzinfo=timezone(offset)).astimezone(timezone.utc)
    except (ValueError, KeyError) as exc:
        raise SigmaProbeError('Invalid access-log timestamp') from exc


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SigmaProbeError('Duplicate JSON keys')
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise SigmaProbeError('Non-finite JSON numbers are not allowed')


def _pick(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    values = [data[key] for key in keys if key in data]
    if not values:
        return default
    if any(value != values[0] for value in values[1:]):
        raise SigmaProbeError('Conflicting JSON aliases')
    return values[0]


def _log_int(value: Any, default: int | None = None) -> int:
    if value == '-' and default is not None:
        return default
    if type(value) is int:
        return value
    if isinstance(value, str) and re.fullmatch(r'[0-9]{1,19}', value):
        return int(value)
    raise SigmaProbeError('Expected an unsigned integer in log data')


class LogIngestionStage:
    name = 'LogIngestionStage'

    def __init__(self, config: InputConfig, limits: LimitsConfig) -> None:
        self.config = config
        self.limits = limits
        self.stats = IngestionStats()
        self._trusted = tuple(ip_network(cidr) for cidr in config.trusted_proxy_cidrs)

    def _source_ip(self, peer: Any, forwarded: Any) -> str:
        peer = canonical_ip(peer)
        address = ip_address(peer)
        if not self._trusted or not any(address in net for net in self._trusted):
            return peer
        if forwarded in (None, '', '-'):
            return peer
        if not isinstance(forwarded, str) or len(forwarded) > 2048:
            raise SigmaProbeError('Invalid forwarded chain')
        chain = forwarded.split(',')
        if len(chain) > 32:
            raise SigmaProbeError('Forwarded chain exceeds 32 hops')
        # Right-to-left trust boundary; never blindly accept the first IP.
        addresses = [canonical_ip(item.strip()) for item in chain] + [peer]
        for candidate in reversed(addresses):
            if not any(ip_address(candidate) in net for net in self._trusted):
                return candidate
        return addresses[0]

    def parse_line(self, line: str, input_id: str = 'input-1', line_number: int = 1) -> LogEvent:
        format_name = self.config.format
        if format_name == 'auto':
            format_name = 'json' if line.lstrip().startswith('{') else 'combined'
        if format_name in ('json', 'jsonl'):
            try:
                data = json.loads(line, object_pairs_hook=_json_pairs, parse_constant=_nonfinite)
            except (ValueError, RecursionError) as exc:
                raise SigmaProbeError('Malformed JSON') from exc
            if not isinstance(data, dict):
                raise SigmaProbeError('JSON log record must be an object')
            peer = _pick(data, 'source_ip', 'remote_addr')
            method = _pick(data, 'method', 'request_method', 'http_method')
            url = _pick(data, 'url', 'request_uri', 'url_raw')
            return LogEvent(
                timestamp=utc_datetime(_pick(data, 'timestamp', 'time_iso8601')),
                source_ip=self._source_ip(peer, _pick(data, 'http_x_forwarded_for', 'x_forwarded_for')),
                url=url, method=method,
                status_code=_log_int(_pick(data, 'status_code', 'status')),
                user_agent=_pick(data, 'user_agent', 'http_user_agent', default='') or '',
                host=_pick(data, 'host'),
                response_size=_log_int(_pick(data, 'response_size', 'body_bytes_sent', default=0), 0),
                input_id=input_id, line_number=line_number,
            )
        match = _LOG.fullmatch(line)
        if match is None:
            raise SigmaProbeError('Malformed Common/Combined log record')
        data = match.groupdict()
        if format_name == 'common' and data['agent'] is not None:
            raise SigmaProbeError('Expected Common format without agent fields')
        request = _unescape(data['request'])
        request_match = re.fullmatch(r'(\S+) (.+) HTTP/[0-9]+(?:\.[0-9]+)?', request)
        if request_match is None:
            raise SigmaProbeError('Missing or malformed HTTP request line')
        return LogEvent(
            timestamp=_combined_time(data['time']), source_ip=data['ip'],
            method=request_match[1], url=request_match[2],
            status_code=int(data['status']), response_size=_log_int(data['size'], 0),
            user_agent=_unescape(data['agent'] or ''), input_id=input_id, line_number=line_number,
        )

    def process(self, paths: tuple[str, ...] | list[str], stdin: BinaryIO | None = None) -> Iterator[LogEvent]:
        self.stats = IngestionStats()
        identities: set[tuple[int, int] | str] = set()
        total_bytes = 0
        total_events = 0
        observed_hosts: set[str] = set()
        for index, raw_path in enumerate(paths, 1):
            if raw_path == '-':
                identity: tuple[int, int] | str = '-'
                handle_context = nullcontext(stdin if stdin is not None else sys.stdin.buffer)
                name = '<stdin>'
            else:
                path = Path(raw_path)
                if not path.is_file():
                    raise SigmaProbeError(f'Input {index} must be an existing regular file')
                stat = path.stat()
                identity = (stat.st_dev, stat.st_ino)
                handle_context = gzip.open(path, 'rb') if path.suffix.lower() == '.gz' else path.open('rb')
                name = path.name
            if identity in identities:
                # Files are opened only after identity checking below; close a
                # freshly opened duplicate before raising.
                if raw_path != '-':
                    handle_context.close()
                raise SigmaProbeError('Duplicate input file or repeated stdin')
            identities.add(identity)
            source = InputFileStats(input_id=f'input-{index}', name=name)
            self.stats.sources.append(source)
            digest = hashlib.sha256()
            with handle_context as handle:
                while True:
                    raw = handle.readline(self.limits.max_line_bytes + 1)
                    if not raw:
                        break
                    if len(raw) > self.limits.max_line_bytes:
                        raise LimitExceeded(f'{source.input_id}: max_line_bytes exceeded')
                    total_bytes += len(raw)
                    if total_bytes > self.limits.max_input_bytes:
                        raise LimitExceeded('max_input_bytes exceeded (decompressed bytes)')
                    source.bytes_read += len(raw)
                    source.lines += 1
                    digest.update(raw)
                    if not raw.strip():
                        source.blank += 1
                        continue
                    try:
                        line = raw.decode('utf-8').rstrip('\r\n')
                        event = self.parse_line(line, source.input_id, source.lines)
                    except (SigmaProbeError, UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
                        source.invalid += 1
                        if len(self.stats.errors) < 20:
                            self.stats.errors.append({'input_id': source.input_id, 'line': source.lines, 'reason': 'invalid_record'})
                        if self.config.invalid_policy == 'error':
                            raise SigmaProbeError(f'{source.input_id} line {source.lines}: invalid record') from None
                        continue
                    if event.host:
                        observed_hosts.add(event.host)
                        if len(observed_hosts) > 1:
                            raise SigmaProbeError('Multiple JSON host values detected; split sites into separate runs')
                    if (self.config.since and event.timestamp < self.config.since) or (self.config.until and event.timestamp >= self.config.until):
                        source.filtered += 1
                        continue
                    total_events += 1
                    if total_events > self.limits.max_events:
                        raise LimitExceeded('max_events exceeded')
                    source.accepted += 1
                    yield event
            source.sha256 = digest.hexdigest()
            logger.info('Read %s: accepted=%d invalid=%d filtered=%d', source.input_id, source.accepted, source.invalid, source.filtered)
        nonblank = self.stats.total('lines') - self.stats.total('blank')
        invalid = self.stats.total('invalid')
        if nonblank and invalid == nonblank:
            raise SigmaProbeError('No valid records: every non-blank line was invalid')
        if nonblank and invalid / nonblank > self.config.max_error_ratio:
            raise SigmaProbeError('Invalid-record ratio exceeds input.max_error_ratio')
