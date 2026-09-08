"""A deliberately small ATT&CK context mapping, not incident attribution."""
from __future__ import annotations

from collections.abc import Iterable

_TECHNIQUES = {
    'T1190': {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'url': 'https://attack.mitre.org/techniques/T1190/', 'status': 'context_only'},
    'T1595': {'id': 'T1595', 'name': 'Active Scanning', 'tactic': 'Reconnaissance', 'url': 'https://attack.mitre.org/techniques/T1595/', 'status': 'context_only'},
    'T1110': {'id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access', 'url': 'https://attack.mitre.org/techniques/T1110/', 'status': 'context_only'},
}
_TAGS = {
    'LFI_RFI': ('T1190',), 'SQL_INJECTION': ('T1190',), 'XSS': ('T1190',),
    'COMMAND_INJECTION': ('T1190',), 'SENSITIVE_PATH': ('T1595',),
    'SCANNER_UA': ('T1595',), 'ENUMERATION': ('T1595',), 'AUTOMATED_SCAN': ('T1595',),
    'AUTH_FAILURE_BURST': ('T1110',),
}


class MitreMapping:
    def get_techniques_for_tags(self, tags: Iterable[str]) -> list[dict[str, str]]:
        identifiers = {identifier for tag in tags for identifier in _TAGS.get(tag, ())}
        return [_TECHNIQUES[identifier].copy() for identifier in sorted(identifiers)]
