"""Validated TOML configuration; no executable rules or implicit .env loading."""
from __future__ import annotations

import os
import tomllib
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, TypeVar

from .validation import (
    SigmaProbeError, boolean, canonical_network, choice, integer, number,
    safe_identifier, text, utc_datetime,
)

DEFAULT_WEIGHTS = {
    'LFI_RFI': 45, 'SQL_INJECTION': 45, 'XSS': 35, 'COMMAND_INJECTION': 55,
    'SENSITIVE_PATH': 15, 'SCANNER_UA': 5, 'ENUMERATION': 25,
    'AUTOMATED_SCAN': 10, 'AUTH_FAILURE_BURST': 40, 'ERROR_BURST': 10,
    'IOC_MATCH': 35, 'CORRELATED_ACTIVITY': 10, 'MULTIPLE_SIGNALS': 0,
}


def _strings(value: Any, name: str, maximum: int = 100) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        raise SigmaProbeError(f"{name}: expected an array with at most {maximum} entries")
    result = tuple(text(item, name) for item in value)
    if len(set(result)) != len(result):
        raise SigmaProbeError(f"{name}: duplicate entries are not allowed")
    return result


@dataclass(frozen=True)
class InputConfig:
    files: tuple[str, ...] = ()
    format: str = 'auto'
    invalid_policy: str = 'skip'
    max_error_ratio: float = 0.05
    since: datetime | None = None
    until: datetime | None = None
    trusted_proxy_cidrs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, 'files', _strings(self.files, 'input.files'))
        choice(self.format, 'input.format', ('auto', 'nginx', 'apache', 'combined', 'common', 'json', 'jsonl'))
        choice(self.invalid_policy, 'input.invalid_policy', ('skip', 'error'))
        number(self.max_error_ratio, 'input.max_error_ratio', 0, 1)
        proxies = _strings(self.trusted_proxy_cidrs, 'input.trusted_proxy_cidrs')
        object.__setattr__(self, 'trusted_proxy_cidrs', tuple(canonical_network(p) for p in proxies))
        for name in ('since', 'until'):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, utc_datetime(value, f'input.{name}'))
        if self.since is not None and self.until is not None and self.since >= self.until:
            raise SigmaProbeError('input.since must be earlier than input.until')


@dataclass(frozen=True)
class LimitsConfig:
    max_events: int = 100_000
    max_actors: int = 10_000
    max_input_bytes: int = 268_435_456
    max_line_bytes: int = 65_536
    max_candidate_pairs: int = 100_000
    max_pair_evaluations: int = 1_000_000

    def __post_init__(self) -> None:
        bounds = {
            'max_events': (1, 10_000_000), 'max_actors': (1, 100_000),
            'max_input_bytes': (1, 10_737_418_240), 'max_line_bytes': (64, 1_048_576),
            'max_candidate_pairs': (1, 10_000_000), 'max_pair_evaluations': (1, 100_000_000),
        }
        for name, (low, high) in bounds.items():
            integer(getattr(self, name), f'limits.{name}', low, high)


@dataclass(frozen=True)
class DetectionConfig:
    temporal_min_events: int = 10
    temporal_cv: float = 0.15
    enumeration_min_paths: int = 10
    enumeration_error_ratio: float = 0.7
    burst_window_seconds: int = 300
    auth_failure_threshold: int = 10
    error_burst_threshold: int = 30
    login_paths: tuple[str, ...] = ('/login', '/wp-login.php', '/api/login', '/api/auth/login')
    correlation_enabled: bool = True
    correlation_min_paths: int = 2
    correlation_similarity: float = 0.7
    correlation_window_seconds: int = 300
    correlation_max_cluster_size: int = 50

    def __post_init__(self) -> None:
        for name, minimum, maximum in (
            ('temporal_min_events', 3, 100_000), ('enumeration_min_paths', 2, 100_000),
            ('burst_window_seconds', 1, 86_400), ('auth_failure_threshold', 2, 100_000),
            ('error_burst_threshold', 2, 100_000), ('correlation_min_paths', 1, 1000),
            ('correlation_window_seconds', 1, 86_400), ('correlation_max_cluster_size', 2, 500),
        ):
            integer(getattr(self, name), f'detection.{name}', minimum, maximum)
        for name in ('temporal_cv', 'enumeration_error_ratio', 'correlation_similarity'):
            number(getattr(self, name), f'detection.{name}', 0, 1)
        boolean(self.correlation_enabled, 'detection.correlation_enabled')
        paths = _strings(self.login_paths, 'detection.login_paths')
        if any(not p.startswith('/') or '?' in p or '#' in p for p in paths):
            raise SigmaProbeError('detection.login_paths: use absolute URL paths without query or fragment')
        object.__setattr__(self, 'login_paths', paths)


@dataclass(frozen=True)
class ScoringConfig:
    weights: dict[str, int] = field(default_factory=lambda: DEFAULT_WEIGHTS.copy())
    repetition_bonus_cap: int = 15
    medium_threshold: int = 40
    high_threshold: int = 70

    def __post_init__(self) -> None:
        if not isinstance(self.weights, dict) or set(self.weights) - DEFAULT_WEIGHTS.keys():
            raise SigmaProbeError('scoring.weights: unknown tag or invalid table')
        weights = DEFAULT_WEIGHTS.copy()
        for tag, value in self.weights.items():
            weights[tag] = integer(value, f'scoring.weights.{tag}', 0, 100)
        object.__setattr__(self, 'weights', weights)
        integer(self.repetition_bonus_cap, 'scoring.repetition_bonus_cap', 0, 30)
        integer(self.medium_threshold, 'scoring.medium_threshold', 1, 99)
        integer(self.high_threshold, 'scoring.high_threshold', 2, 100)
        if self.medium_threshold >= self.high_threshold:
            raise SigmaProbeError('scoring.medium_threshold must be below high_threshold')


@dataclass(frozen=True)
class PrivacyConfig:
    anonymize_ips: bool = False
    include_query: bool = False

    def __post_init__(self) -> None:
        boolean(self.anonymize_ips, 'privacy.anonymize_ips')
        boolean(self.include_query, 'privacy.include_query')


@dataclass(frozen=True)
class ReportingConfig:
    output_dir: str = 'reports'
    formats: tuple[str, ...] = ('json', 'html', 'text')
    max_display_actors: int = 100
    max_evidence_per_actor: int = 12
    sample_events: int = 3

    def __post_init__(self) -> None:
        text(self.output_dir, 'reporting.output_dir')
        formats = _strings(self.formats, 'reporting.formats', 3)
        if not formats:
            raise SigmaProbeError('reporting.formats cannot be empty')
        for value in formats:
            choice(value, 'reporting.formats', ('json', 'html', 'text'))
        object.__setattr__(self, 'formats', formats)
        integer(self.max_display_actors, 'reporting.max_display_actors', 1, 10_000)
        integer(self.max_evidence_per_actor, 'reporting.max_evidence_per_actor', 1, 100)
        integer(self.sample_events, 'reporting.sample_events', 1, 20)


@dataclass(frozen=True)
class IoCFileConfig:
    name: str
    path: str
    type: str
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        safe_identifier(self.name, 'ioc.files.name')
        text(self.path, 'ioc.files.path')
        if '://' in self.path:
            raise SigmaProbeError('IoC feeds must be local files, not URLs')
        choice(self.type, 'ioc.files.type', ('ip', 'url_path', 'user_agent'))
        if self.expires_at is not None:
            object.__setattr__(self, 'expires_at', utc_datetime(self.expires_at, 'ioc.files.expires_at'))


@dataclass(frozen=True)
class IoCConfig:
    enabled: bool = False
    files: tuple[IoCFileConfig, ...] = ()
    max_file_bytes: int = 1_048_576
    max_entries: int = 10_000

    def __post_init__(self) -> None:
        boolean(self.enabled, 'ioc.enabled')
        if not isinstance(self.files, (list, tuple)) or len(self.files) > 20:
            raise SigmaProbeError('ioc.files must contain at most 20 local feeds')
        if any(not isinstance(f, IoCFileConfig) for f in self.files):
            raise SigmaProbeError('ioc.files must contain IoCFileConfig objects')
        object.__setattr__(self, 'files', tuple(self.files))
        if len({f.name for f in self.files}) != len(self.files):
            raise SigmaProbeError('ioc.files: duplicate feed names')
        if self.enabled and not self.files:
            raise SigmaProbeError('ioc.enabled requires at least one local feed')
        integer(self.max_file_bytes, 'ioc.max_file_bytes', 1, 10_485_760)
        integer(self.max_entries, 'ioc.max_entries', 1, 100_000)


@dataclass(frozen=True)
class Settings:
    schema_version: int = 1
    site: str = 'local-site'
    log_level: str = 'INFO'
    allowlist_cidrs: tuple[str, ...] = ()
    input: InputConfig = field(default_factory=InputConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    ioc: IoCConfig = field(default_factory=IoCConfig)

    def __post_init__(self) -> None:
        integer(self.schema_version, 'schema_version', 1, 1)
        text(self.site, 'site', 120)
        choice(self.log_level, 'log_level', ('DEBUG', 'INFO', 'WARNING', 'ERROR'))
        cidrs = _strings(self.allowlist_cidrs, 'allowlist_cidrs', 1000)
        object.__setattr__(self, 'allowlist_cidrs', tuple(canonical_network(c) for c in cidrs))
        for name, cls in _SECTIONS.items():
            if not isinstance(getattr(self, name), cls):
                raise SigmaProbeError(f'{name}: expected {cls.__name__}')

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_SECTIONS = {
    'input': InputConfig, 'limits': LimitsConfig, 'detection': DetectionConfig,
    'scoring': ScoringConfig, 'privacy': PrivacyConfig, 'reporting': ReportingConfig,
    'ioc': IoCConfig,
}
_T = TypeVar('_T')


def _construct(cls: type[_T], values: Any, label: str) -> _T:
    if not isinstance(values, dict):
        raise SigmaProbeError(f'{label}: expected a table')
    unknown = values.keys() - {f.name for f in fields(cls)}
    if unknown:
        raise SigmaProbeError(f"{label}: unknown settings: {', '.join(sorted(unknown))}")
    try:
        return cls(**values)
    except TypeError as exc:
        raise SigmaProbeError(f'{label}: missing or invalid fields') from exc


def settings_from_dict(data: dict[str, Any]) -> Settings:
    values = dict(data)
    for name, cls in _SECTIONS.items():
        if name not in values:
            continue
        section = values[name]
        if name == 'ioc' and isinstance(section, dict) and 'files' in section:
            section = dict(section)
            raw_files = section['files']
            if not isinstance(raw_files, (list, tuple)):
                raise SigmaProbeError('ioc.files must be an array of tables')
            section['files'] = tuple(_construct(IoCFileConfig, f, 'ioc.files') for f in raw_files)
        values[name] = _construct(cls, section, name)
    return _construct(Settings, values, 'config')


def _merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(
    path: str | Path | None = None, *, overrides: dict[str, Any] | None = None,
    environ: Mapping[str, str] | None = None,
) -> Settings:
    """Precedence: defaults < TOML < environment < explicit overrides.

    TOML file paths resolve relative to that file. Paths supplied through
    environment/CLI overrides resolve relative to the current directory.
    """
    env = os.environ if environ is None else environ
    selected = path if path is not None else env.get('SIGMA_PROBE_CONFIG')
    data: dict[str, Any] = {}
    if selected:
        config_path = Path(selected).absolute()
        try:
            with config_path.open('rb') as handle:
                raw = handle.read(65_537)
            if len(raw) > 65_536:
                raise SigmaProbeError('Configuration exceeds 64 KiB')
            data = tomllib.loads(raw.decode('utf-8'))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
            raise SigmaProbeError('Cannot read a valid UTF-8 TOML configuration') from exc
        # Validate before resolving paths: malformed nested sections must not
        # cause a TypeError or be silently overwritten by CLI arguments.
        settings_from_dict(data)
        root = config_path.parent
        if 'input' in data and 'files' in data['input']:
            data['input']['files'] = [str(root / p) if p != '-' else '-' for p in data['input']['files']]
        if 'reporting' in data and 'output_dir' in data['reporting']:
            data['reporting']['output_dir'] = str(root / data['reporting']['output_dir'])
        for feed in data.get('ioc', {}).get('files', []):
            feed['path'] = str(root / feed['path'])
    env_overlay: dict[str, Any] = {}
    for variable, key in (('SIGMA_PROBE_SITE', 'site'), ('SIGMA_PROBE_LOG_LEVEL', 'log_level')):
        if variable in env:
            env_overlay[key] = env[variable]
    if 'SIGMA_PROBE_OUTPUT_DIR' in env:
        env_overlay['reporting'] = {'output_dir': env['SIGMA_PROBE_OUTPUT_DIR']}
    data = _merge(data, env_overlay)
    if overrides:
        data = _merge(data, overrides)
    return settings_from_dict(data)
