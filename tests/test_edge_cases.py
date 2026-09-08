import io
import json
import random
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sigma_probe.config import DetectionConfig, InputConfig, LimitsConfig, ReportingConfig, Settings
from sigma_probe.main import AnalysisPipeline
from sigma_probe.pipeline.base import AnalysisContext
from sigma_probe.pipeline.detectors import GraphDetector
from sigma_probe.pipeline.ingestion import LogIngestionStage
from sigma_probe.pipeline.reporting import ReportingStage
from sigma_probe.privacy import display_text
from sigma_probe.validation import SigmaProbeError
from tests.helpers import ROOT, actor, event


class EdgeCaseTests(unittest.TestCase):
    def test_broad_actor_window_is_not_sufficient_correlation(self):
        a = actor('203.0.113.1', ['/a?f=../etc/passwd', '/b?f=../etc/passwd'])
        a.add_event(event('/health', '203.0.113.1', seconds=7205))
        b = actor('203.0.113.2', ['/a?f=../etc/passwd', '/b?f=../etc/passwd'], start=7200)
        context = AnalysisContext([a, b])
        GraphDetector(DetectionConfig(), LimitsConfig()).process(context)
        self.assertEqual(context.campaigns, [])

    def test_url_bidi_controls_are_printable_escapes(self):
        output = display_text('/path\u202eevil\u2066')
        self.assertNotIn('\u202e', output)
        self.assertNotIn('\u2066', output)
        self.assertIn('\\u202e', output)

    def test_report_invalid_timestamp_does_not_leak_staging_directory(self):
        result = AnalysisPipeline(Settings()).run(str(ROOT / 'examples/access.log'), write_reports=False)
        result.report['metadata']['generated_at'] = 'invalid'
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                ReportingStage(Settings(reporting=ReportingConfig(output_dir=directory))).write(result.report)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_seeded_malformed_records_fail_as_validation_not_crashes(self):
        rng = random.Random(20260908)
        stage = LogIngestionStage(InputConfig(format='json'), LimitsConfig())
        values = [None, [], {}, True, -1, 200, 1e300, '', '/', '203.0.113.1', '2026-09-08T00:00:00Z']
        for _ in range(500):
            row = {key: rng.choice(values) for key in ('source_ip', 'timestamp', 'url', 'method', 'status_code', 'user_agent')}
            try:
                stage.parse_line(json.dumps(row))
            except SigmaProbeError:
                continue
            except Exception as exc:
                self.fail(f'Unhandled parser error: {type(exc).__name__}: {exc}')

    def test_filtered_input_not_false_partial(self):
        config = replace(Settings(), input=InputConfig(since='2030-01-01T00:00:00Z'))
        result = AnalysisPipeline(config).run(str(ROOT / 'examples/access.log'), write_reports=False)
        self.assertEqual(result.ingestion.total('filtered'), 56)
        self.assertEqual(result.report['metadata']['input_status'], 'complete')
        self.assertEqual(result.report['summary']['actors'], 0)

    def test_multi_host_json_refused_instead_of_cross_site_grouping(self):
        rows = [{'timestamp': '2026-09-08T00:00:00Z', 'source_ip': '203.0.113.1', 'method': 'GET', 'url': '/', 'status_code': 200, 'host': host} for host in ('one.example.test', 'two.example.test')]
        with self.assertRaisesRegex(SigmaProbeError, 'Multiple JSON host'):
            AnalysisPipeline(Settings()).run('-', write_reports=False, stdin=io.BytesIO(''.join(json.dumps(row) + '\n' for row in rows).encode()))

    def test_malformed_absolute_url_is_validation_error(self):
        for target in ('http://[broken/', 'http:///no-host'):
            with self.assertRaises(SigmaProbeError):
                event(target)

    def test_input_iterator_closed_on_profiling_abort(self):
        from unittest.mock import patch
        from sigma_probe.validation import LimitExceeded
        state = {'closed': False}
        def incoming(*args):
            try:
                yield event('/', '203.0.113.1')
                yield event('/', '203.0.113.2')
            finally:
                state['closed'] = True
        with patch('sigma_probe.main.LogIngestionStage.process', incoming):
            with self.assertRaises(LimitExceeded):
                AnalysisPipeline(replace(Settings(), limits=LimitsConfig(max_actors=1))).run('-', write_reports=False)
        self.assertTrue(state['closed'])
