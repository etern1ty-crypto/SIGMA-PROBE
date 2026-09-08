"""Bounded URL normalization and conservative, passive request signatures."""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import unquote, urlsplit

from ..models.core import LogEvent
from ..validation import SigmaProbeError

# Fixed, non-configurable regexes keep untrusted feed data out of the regex
# engine. A match describes an attempt, never successful exploitation.
_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ('LFI_RFI', re.compile(r'(?:\.\.[/\\]|(?:php|file|data|zip)://|/(?:etc/(?:passwd|shadow)|proc/self/environ)(?:\b|/))', re.I)),
    ('SQL_INJECTION', re.compile(r"(?:\bunion\s+(?:all\s+)?select\b|['\"]\s*(?:or|and)\s+['\"\w]+\s*=\s*['\"\w]+|;\s*(?:drop|alter)\s+table\b|\b(?:sleep|benchmark)\s*\()", re.I)),
    ('XSS', re.compile(r'(?:<\s*(?:script|iframe|object)\b|javascript\s*:|<[^<>]{0,256}\s+on[a-z]+\s*=)', re.I)),
    ('COMMAND_INJECTION', re.compile(r'(?:[;|`]\s*(?:cat|whoami|uname|wget|curl|bash|sh|chmod)\b|\$\(\s*(?:id|whoami|cat|curl)\b|[?&](?:cmd|exec|command)=\s*(?:cat|whoami|uname|wget|curl|bash|sh)\b)', re.I)),
)
_SENSITIVE = re.compile(r'(?:^|/)(?:\.env(?:\.[^/]*)?|\.git|\.svn|wp-config\.php(?:\.(?:bak|old|save))?|config\.(?:yaml|yml|toml|ini)|phpinfo\.php)(?:$|/)', re.I)
_SCANNER = re.compile(r'\b(?:sqlmap|nikto|nmap|masscan|nuclei|gobuster|dirbuster)\b', re.I)


def decoded_variants(target: str) -> tuple[str, ...]:
    """At most two percent-decoding passes; '+' is a space only in query."""
    variants = [target]
    for _ in range(2):
        path, marker, query = variants[-1].partition('?')
        decoded = unquote(path, errors='replace')
        if marker:
            decoded += '?' + unquote(query.replace('+', ' '), errors='replace')
        if decoded == variants[-1]:
            break
        variants.append(decoded)
    return tuple(variants)


def normalized_path(target: str) -> str:
    # Do not interpret a leading // as a hostname: it can be an origin-form
    # path. Query is not part of the identity used for correlation.
    if target.startswith(('http://', 'https://')):
        try:
            path = urlsplit(target).path or '/'
        except ValueError as exc:
            raise SigmaProbeError('Malformed absolute URL') from exc
    else:
        path = target.split('?', 1)[0].split('#', 1)[0]
    for _ in range(2):
        decoded = unquote(path, errors='replace')
        if decoded == path:
            break
        path = decoded
    # Do not collapse .. segments; they are evidence. Preserve case, because
    # most web servers have case-sensitive paths.
    return path or '/'


class EnrichmentStage:
    name = 'EnrichmentStage'

    def process(self, event: LogEvent) -> LogEvent:
        event.path = normalized_path(event.url)
        counts = Counter(event.url)
        event.entropy = -sum((n / len(event.url)) * math.log2(n / len(event.url)) for n in counts.values())
        event.heuristic_flags.clear()
        variants = decoded_variants(event.url)
        for tag, pattern in _SIGNATURES:
            if any(pattern.search(value) for value in variants):
                event.heuristic_flags.add(tag)
        if _SENSITIVE.search(event.path):
            event.heuristic_flags.add('SENSITIVE_PATH')
        if _SCANNER.search(event.user_agent):
            event.heuristic_flags.add('SCANNER_UA')
        return event
