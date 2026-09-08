import io
import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from sigma_probe.config import PrivacyConfig, ReportingConfig, Settings
from sigma_probe.main import AnalysisPipeline
from sigma_probe.pipeline.reporting import ReportingStage, json_text, render_html, render_text
from sigma_probe.privacy import PrivacyProjector
from sigma_probe.validation import RunInterrupted, SigmaProbeError
from tests.helpers import ROOT, combined


class ReportTests(unittest.TestCase):
    def result(self, config=None):
        return AnalysisPipeline(config or Settings()).run(str(ROOT / 'examples/access.log'), write_reports=False)

    def test_query_redaction_applies_to_every_format(self):
        result = self.result()
        self.assertNotIn('DEMO_NOT_A_REAL_SECRET', json_text(result.report))
        for renderer in (render_html, render_text):
            self.assertNotIn('DEMO_NOT_A_REAL_SECRET', renderer(result.report, Settings()))
        url = '/read?file=../etc/passwd&token=PRIVATE_SECRET'
        result = AnalysisPipeline(Settings()).run('-', write_reports=False, stdin=io.BytesIO(combined(target=url).encode()))
        self.assertNotIn('PRIVATE_SECRET', json_text(result.report))
        self.assertEqual(result.report['actors'][0]['evidence'][0]['references'][0]['url'], '/read')

    def test_explicit_query_opt_in(self):
        config = Settings(privacy=PrivacyConfig(include_query=True))
        result = AnalysisPipeline(config).run('-', write_reports=False, stdin=io.BytesIO(combined(target='/read?file=../etc/passwd&token=EXPLICIT_SECRET').encode()))
        self.assertIn('EXPLICIT_SECRET', json_text(result.report))
        self.assertIn('Query-параметры включены', render_html(result.report, config))

    def test_hmac_consistent_across_references_and_formats(self):
        config = Settings(privacy=PrivacyConfig(anonymize_ips=True))
        result = AnalysisPipeline(config, hmac_key='synthetic-test-key-' * 3).run(str(ROOT / 'examples/access.log'), write_reports=False)
        for value in (json_text(result.report), render_html(result.report, config), render_text(result.report, config)):
            self.assertNotIn('203.0.113.10', value)
            self.assertNotIn('2001:db8::21', value)
        identifiers = {a['ip_address'] for a in result.report['actors']}
        self.assertTrue(all(identifier.startswith('ip-') for identifier in identifiers))
        for campaign in result.report['campaigns']:
            self.assertTrue(set(campaign['actors']) <= identifiers)
        for recommendation in result.report['recommendations']:
            self.assertTrue(set(recommendation['actor_ids']) <= identifiers)
        self.assertEqual(result.report['metadata']['privacy']['key_mode'], 'operator_key')

    def test_ephemeral_pseudonyms_not_reused_between_runs(self):
        config = Settings(privacy=PrivacyConfig(anonymize_ips=True))
        first, second = self.result(config), self.result(config)
        self.assertNotEqual(first.report['actors'][0]['ip_address'], second.report['actors'][0]['ip_address'])

    def test_invalid_hmac_key_rejected(self):
        with self.assertRaises(SigmaProbeError):
            PrivacyProjector(PrivacyConfig(anonymize_ips=True), 'short')

    def test_html_escapes_site_payload_and_evidence(self):
        config = Settings(site='<img src=x onerror=alert(1)>', privacy=PrivacyConfig(include_query=True))
        data = combined(target='/?q=%3Cscript%3Ealert(1)%3C/script%3E')
        result = AnalysisPipeline(config).run('-', write_reports=False, stdin=io.BytesIO(data.encode()))
        result.report['actors'][0]['evidence'][0]['details'] = '<script>alert(2)</script>'
        html = render_html(result.report, config)
        self.assertNotIn('<script>', html)
        self.assertNotIn('<img ', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn('Content-Security-Policy', html)
        self.assertNotIn('<script src=', html)
        self.assertNotIn('https://fonts', html)

    def test_html_actor_limit_does_not_truncate_json(self):
        config = Settings(reporting=ReportingConfig(max_display_actors=1))
        result = self.result(config)
        self.assertEqual(len(result.report['actors']), 7)
        self.assertEqual(render_html(result.report, config).count('<details class="actor">'), 1)

    def test_unknown_json_types_and_nan_rejected(self):
        with self.assertRaises(TypeError):
            json_text({'unsupported': object()})
        with self.assertRaises(ValueError):
            json_text({'invalid': float('nan')})

    def test_atomic_bundle_and_posix_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Settings(reporting=ReportingConfig(output_dir=str(Path(directory) / 'reports')))
            result = self.result(config)
            paths = ReportingStage(config).write(result.report)
            self.assertEqual(set(paths), {'json', 'html', 'text'})
            parents = {Path(p).parent for p in paths.values()}
            self.assertEqual(len(parents), 1)
            for p in paths.values():
                self.assertTrue(Path(p).is_file())
                if os.name == 'posix':
                    self.assertEqual(Path(p).stat().st_mode & 0o777, 0o600)
            if os.name == 'posix':
                self.assertEqual(next(iter(parents)).stat().st_mode & 0o777, 0o700)
            self.assertEqual(json.loads(Path(paths['json']).read_text(encoding='utf-8'))['summary'], result.report['summary'])

    def test_renderer_failure_rolls_back_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'reports'
            config = Settings(reporting=ReportingConfig(output_dir=str(root)))
            with patch('sigma_probe.pipeline.reporting.render_html', side_effect=ValueError('synthetic renderer failure')):
                with self.assertRaises(ValueError):
                    ReportingStage(config).write(self.result().report)
            self.assertEqual(list(root.iterdir()), [])

    def test_interrupt_during_report_write_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'reports'
            config = Settings(reporting=ReportingConfig(output_dir=str(root)))
            with patch('sigma_probe.pipeline.reporting.render_html', side_effect=RunInterrupted(15)):
                with self.assertRaises(RunInterrupted):
                    ReportingStage(config).write(self.result().report)
            self.assertEqual(list(root.iterdir()), [])

    def test_output_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            real, link = Path(directory) / 'real', Path(directory) / 'link'
            real.mkdir()
            link.symlink_to(real, target_is_directory=True)
            config = Settings(reporting=ReportingConfig(output_dir=str(link)))
            with self.assertRaises(SigmaProbeError):
                ReportingStage(config).write(self.result().report)
            self.assertEqual(list(real.iterdir()), [])

    @unittest.skipUnless(os.name == 'posix', 'POSIX file permission checks only apply on POSIX')
    def test_world_writable_output_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'reports'
            root.mkdir()
            root.chmod(0o777)
            config = Settings(reporting=ReportingConfig(output_dir=str(root)))
            with self.assertRaises(SigmaProbeError):
                ReportingStage(config).write(self.result().report)

    def test_concurrent_reports_do_not_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Settings(reporting=ReportingConfig(output_dir=str(Path(directory) / 'reports'), formats=('json',)))
            data = self.result().report
            with ThreadPoolExecutor(max_workers=4) as executor:
                reports = list(executor.map(lambda _: ReportingStage(config).write(data), range(4)))
            self.assertEqual(len({r['json'] for r in reports}), 4)
            self.assertTrue(all(Path(r['json']).is_file() for r in reports))

    def test_url_userinfo_fragment_and_control_never_leak(self):
        projector = PrivacyProjector(PrivacyConfig())
        self.assertEqual(projector.url('https://user:secret@example.test/path?q=secret#fragment'), '/path')
        self.assertNotIn('\n', projector.url('/path\nInjected'))

    def test_empty_report_and_input_accounting(self):
        result = AnalysisPipeline(Settings()).run('-', write_reports=False, stdin=io.BytesIO(b'\n'))
        html = render_html(result.report, Settings())
        self.assertIn('нет принятых событий', html)
        for source in result.report['inputs']:
            self.assertEqual(source['lines'], source['blank'] + source['invalid'] + source['filtered'] + source['accepted'])
