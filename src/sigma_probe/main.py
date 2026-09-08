"""CLI and reusable offline analysis orchestration. Importing has no side effects."""
from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import signal
import sys
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from . import __version__
from .config import Settings, load_config
from .intelligence.ioc_manager import IoCManager
from .intelligence.mitre_mapping import MitreMapping
from .models.core import AnalysisResult
from .pipeline.base import AnalysisContext, Pipeline
from .pipeline.detectors import BehaviorDetector, GraphDetector, TemporalDetector
from .pipeline.enrichment import EnrichmentStage
from .pipeline.ingestion import LogIngestionStage
from .pipeline.metadetector import MetaDetector
from .pipeline.profiling import ActorProfilingStage
from .pipeline.recommendations import NarrativeEngine
from .pipeline.reporting import ReportingStage, build_report, json_text
from .pipeline.scoring import ScoringEngine
from .privacy import PrivacyProjector
from .validation import RunInterrupted, SigmaProbeError

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    def __init__(self, config: Settings | str | Path | None = None, *, hmac_key: str | None = None) -> None:
        self.config = copy.deepcopy(config) if isinstance(config, Settings) else load_config(config)
        self._hmac_key = hmac_key

    def run(
        self, input_paths: str | Sequence[str] | None = None, *,
        write_reports: bool = True, stdin: BinaryIO | None = None,
    ) -> AnalysisResult:
        """One finite run, one site, one fresh state. Raw API results are sensitive."""
        started = time.perf_counter()
        paths = self.config.input.files if input_paths is None else ((input_paths,) if isinstance(input_paths, str) else tuple(input_paths))
        if not paths:
            raise SigmaProbeError('Supply --input or configure input.files')
        config = replace(self.config, input=replace(self.config.input, files=tuple(paths)))
        projector = PrivacyProjector(config.privacy, self._hmac_key if config.privacy.anonymize_ips else None)
        ingestion = LogIngestionStage(config.input, config.limits)
        enrichment = EnrichmentStage()
        intelligence = IoCManager(config.ioc)

        with closing(ingestion.process(list(paths), stdin)) as incoming:
            enriched = (intelligence.enrich_event(enrichment.process(event)) for event in incoming)
            actors = ActorProfilingStage(config).process(enriched)
        context = AnalysisContext(actors=actors)
        Pipeline([
            BehaviorDetector(config.detection).process,
            TemporalDetector(config.detection).process,
            GraphDetector(config.detection, config.limits).process,
            MetaDetector().process,
            ScoringEngine(config.scoring).process,
        ]).execute(context)
        context.summary['ioc'] = intelligence.get_stats()
        mapping = MitreMapping()
        for actor in context.actors:
            actor.mitre_techniques = mapping.get_techniques_for_tags(actor.tags)
        for campaign in context.campaigns:
            campaign.mitre_techniques = mapping.get_techniques_for_tags(campaign.primary_tags)
        result = AnalysisResult(
            site=config.site, actors=context.actors, campaigns=context.campaigns,
            recommendations=NarrativeEngine().generate_recommendations(context.actors),
            ingestion=ingestion.stats, detector_summary=context.summary,
            elapsed_seconds=time.perf_counter() - started,
        )
        result.report = build_report(result, config, projector)
        if write_reports:
            result.report_paths = ReportingStage(config).write(result.report)
        logger.info('Analysis complete: events=%d actors=%d partial=%s', result.ingestion.total('accepted'), len(result.actors), result.ingestion.partial)
        return result


# A name-level migration alias only. The 3.x return type and configuration
# are intentionally new and documented; no misleading emulation of v2.
HeliosPipeline = AnalysisPipeline


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {'timestamp': datetime.now(timezone.utc).isoformat(), 'level': record.levelname, 'logger': record.name, 'message': record.getMessage()}
        if record.exc_info:
            payload['exception'] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


@contextmanager
def _interrupt_handlers() -> Iterator[None]:
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    def stop(signum: int, frame: Any) -> None:
        # Ignore repeated interruptions until cleanup finishes. Raising also
        # interrupts a blocking stdin read, unlike a polling-only stop flag.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        raise RunInterrupted(signum)

    for sig in previous:
        signal.signal(sig, stop)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='sigma-probe', description='Offline web access-log security triage. No scanning, uploads or automatic blocking.')
    parser.add_argument('--version', action='version', version=f'sigma-probe {__version__}')
    commands = parser.add_subparsers(dest='command', required=True)
    validate = commands.add_parser('validate-config', help='Validate TOML without analyzing or writing reports')
    validate.add_argument('--config', '-c')
    analyze = commands.add_parser('analyze', help='Analyze a finite set of local logs')
    analyze.add_argument('--config', '-c', help='TOML configuration path')
    analyze.add_argument('--input', '-i', action='append', help='Input file (repeatable), .gz, or - for stdin')
    analyze.add_argument('--output', '-o', help='Parent directory for a new atomic report bundle')
    analyze.add_argument('--input-format', choices=('auto', 'nginx', 'apache', 'combined', 'common', 'json', 'jsonl'))
    analyze.add_argument('--format', action='append', choices=('json', 'html', 'text'), help='Report format (repeatable)')
    analyze.add_argument('--site', help='Exactly one site/tenant per run')
    analyze.add_argument('--since', help='Inclusive ISO 8601 timestamp with timezone')
    analyze.add_argument('--until', help='Exclusive ISO 8601 timestamp with timezone')
    analyze.add_argument('--strict', action='store_true', help='Reject the first malformed input record')
    analyze.add_argument('--max-events', type=int)
    analyze.add_argument('--max-input-bytes', type=int)
    analyze.add_argument('--allowlist', action='append', help='Explicit IP/CIDR suppression; evidence is retained')
    analyze.add_argument('--anonymize-ips', action=argparse.BooleanOptionalAction, default=None)
    analyze.add_argument('--include-query', action=argparse.BooleanOptionalAction, default=None)
    analyze.add_argument('--fail-on', choices=('none', 'low', 'medium', 'high'), default='none', help='Exit 3 at or above this severity, after writing reports')
    analyze.add_argument('--log-level', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR'))
    analyze.add_argument('--json-logs', action='store_true', help='Structured logs in stderr')
    analyze.add_argument('--debug', action='store_true', help='Include tracebacks for failures')
    return parser


def _overrides(args: argparse.Namespace) -> dict[str, Any]:
    values: dict[str, Any] = {}
    mappings = {
        'input': ('input', 'files'), 'input_format': ('input', 'format'),
        'since': ('input', 'since'), 'until': ('input', 'until'),
        'output': ('reporting', 'output_dir'), 'format': ('reporting', 'formats'),
        'max_events': ('limits', 'max_events'), 'max_input_bytes': ('limits', 'max_input_bytes'),
        'anonymize_ips': ('privacy', 'anonymize_ips'), 'include_query': ('privacy', 'include_query'),
    }
    for source, (section, key) in mappings.items():
        value = getattr(args, source)
        if value is not None:
            values.setdefault(section, {})[key] = value
    if args.strict:
        values.setdefault('input', {})['invalid_policy'] = 'error'
    for source, target in (('site', 'site'), ('log_level', 'log_level'), ('allowlist', 'allowlist_cidrs')):
        value = getattr(args, source)
        if value is not None:
            values[target] = value
    return values


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    # Preserve the README's historical `python -m ... --input ...` spelling.
    if arguments and arguments[0].startswith('-') and arguments[0] not in ('--help', '-h', '--version'):
        arguments.insert(0, 'analyze')
    parser = _parser()
    args = parser.parse_args(arguments)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonLogFormatter() if getattr(args, 'json_logs', False) else logging.Formatter('%(levelname)s %(name)s: %(message)s'))
    package_logger = logging.getLogger('sigma_probe')
    previous_handlers, previous_level, previous_propagate = package_logger.handlers[:], package_logger.level, package_logger.propagate
    package_logger.handlers = [handler]
    package_logger.propagate = False
    package_logger.setLevel(logging.INFO)
    try:
        with _interrupt_handlers():
            if args.command == 'validate-config':
                config = load_config(args.config)
                print(json_text({'valid': True, 'schema_version': config.schema_version, 'site': config.site}), end='', flush=True)
                return 0
            config = load_config(args.config, overrides=_overrides(args))
            package_logger.setLevel(logging.DEBUG if args.debug else config.log_level)
            if config.privacy.include_query:
                logger.warning('Query strings are enabled; review reports for secrets before sharing')
            logger.info('Starting offline analysis')
            result = AnalysisPipeline(config, hmac_key=os.environ.get('SIGMA_PROBE_HMAC_KEY')).run()
            priorities = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
            threshold = priorities.get(args.fail_on, 4)
            failed = any(not actor.suppressed and priorities[actor.severity] >= threshold for actor in result.actors)
            exit_code = 4 if result.ingestion.partial else (3 if failed else 0)
            print(json_text({'summary': result.report['summary'], 'reports': result.report_paths, 'input_status': 'partial' if result.ingestion.partial else 'complete', 'exit_code': exit_code}), end='', flush=True)
            return exit_code
    except RunInterrupted as exc:
        logger.warning('Interrupted; no partially written report bundle was published')
        return 128 + exc.signum
    except KeyboardInterrupt:
        logger.warning('Interrupted')
        return 130
    except BrokenPipeError:
        # Prevent another flush failure during interpreter shutdown.
        if hasattr(sys.stdout, 'fileno'):
            try:
                with open(os.devnull, 'w') as sink:
                    os.dup2(sink.fileno(), sys.stdout.fileno())
            except (OSError, ValueError):
                logger.debug('Could not detach closed stdout')
        return 1
    except (SigmaProbeError, OSError, EOFError) as exc:
        message = str(exc) if isinstance(exc, SigmaProbeError) else 'File read/write failed; verify paths, permissions and compression'
        logger.error('%s', message, exc_info=getattr(args, 'debug', False))
        return 2
    except Exception:
        logger.error('Unexpected internal error; use --debug for a traceback', exc_info=getattr(args, 'debug', False))
        return 1
    finally:
        handler.close()
        package_logger.handlers = previous_handlers
        package_logger.setLevel(previous_level)
        package_logger.propagate = previous_propagate


if __name__ == '__main__':
    raise SystemExit(main())
