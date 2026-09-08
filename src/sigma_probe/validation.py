"""Small, strict validators shared by configuration and domain objects."""
from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any


class SigmaProbeError(Exception):
    """Expected input, configuration, or resource-budget error."""


class LimitExceeded(SigmaProbeError):
    """Refuse incomplete analysis instead of silently truncating it."""


class RunInterrupted(KeyboardInterrupt):
    """An interruption that carries the conventional process exit code."""

    def __init__(self, signum: int) -> None:
        self.signum = signum
        super().__init__(f"Interrupted by signal {signum}")


def text(value: Any, name: str, maximum: int = 4096, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value) or len(value) > maximum:
        raise SigmaProbeError(f"{name}: expected a string of length {'0' if empty else '1'}..{maximum}")
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise SigmaProbeError(f"{name}: control characters are not allowed")
    return value


def integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SigmaProbeError(f"{name}: expected an integer in [{minimum}, {maximum}]")
    return value


def number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if type(value) not in (float, int) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise SigmaProbeError(f"{name}: expected a finite number in [{minimum}, {maximum}]")
    return float(value)


def boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise SigmaProbeError(f"{name}: expected true or false")
    return value


def choice(value: Any, name: str, values: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in values:
        raise SigmaProbeError(f"{name}: expected one of {', '.join(values)}")
    return value


def canonical_ip(value: Any) -> str:
    text(value, "IP address", 45)
    if '%' in value:
        raise SigmaProbeError("Scoped IPv6 addresses are not supported")
    try:
        return str(ip_address(value))
    except ValueError as exc:
        raise SigmaProbeError("Invalid IPv4 or IPv6 address") from exc


def canonical_network(value: Any) -> str:
    text(value, "CIDR", 49)
    if '%' in value:
        raise SigmaProbeError("Scoped IPv6 networks are not supported")
    try:
        return str(ip_network(value, strict=False))
    except ValueError as exc:
        raise SigmaProbeError("Invalid IPv4 or IPv6 CIDR") from exc


def utc_datetime(value: Any, name: str = "timestamp") -> datetime:
    try:
        if isinstance(value, datetime):
            result = value
        elif isinstance(value, str):
            result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        elif type(value) in (int, float) and math.isfinite(value):
            result = datetime.fromtimestamp(value, tz=timezone.utc)
        else:
            raise ValueError("Unsupported timestamp type")
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError("Timezone missing")
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError) as exc:
        raise SigmaProbeError(f"{name}: expected an ISO 8601 timestamp with timezone or Unix seconds") from exc


def safe_identifier(value: Any, name: str) -> str:
    value = text(value, name, 64)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', value):
        raise SigmaProbeError(f"{name}: use letters, digits, dots, dashes or underscores")
    return value
