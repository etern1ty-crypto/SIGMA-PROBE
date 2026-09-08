"""One privacy projection shared by every output format."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from .config import PrivacyConfig
from .validation import SigmaProbeError


def display_text(value: str, maximum: int = 4096) -> str:
    """Keep terminal/HTML payloads printable, including decoded URL controls."""
    output = ''.join(c if ord(c) >= 32 and not 127 <= ord(c) <= 159 and not 0xD800 <= ord(c) <= 0xDFFF and not 0x202A <= ord(c) <= 0x202E and not 0x2066 <= ord(c) <= 0x2069 else f'\\u{ord(c):04x}' for c in value)
    return output if len(output) <= maximum else output[:maximum] + ' [truncated for display]'


class PrivacyProjector:
    def __init__(self, config: PrivacyConfig, hmac_key: str | None = None) -> None:
        self.config = config
        if hmac_key and len(hmac_key.encode('utf-8')) < 32:
            raise SigmaProbeError('SIGMA_PROBE_HMAC_KEY must contain at least 32 UTF-8 bytes')
        self._key = hmac_key.encode('utf-8') if hmac_key else secrets.token_bytes(32)
        self.key_mode = 'operator_key' if hmac_key else 'ephemeral_per_run'

    def identifier(self, value: str, prefix: str = 'ip') -> str:
        if not self.config.anonymize_ips:
            return value
        digest = hmac.new(self._key, (prefix + ':' + value).encode('utf-8'), hashlib.sha256).hexdigest()[:24]
        return f'{prefix}-{digest}'

    def url(self, value: str) -> str:
        value = value.split('#', 1)[0]
        if value.startswith(('http://', 'https://')):
            parts = urlsplit(value)
            value = (parts.path or '/') + ('?' + parts.query if parts.query else '')
        if not self.config.include_query:
            value = value.split('?', 1)[0]
        return display_text(value, 2048)
