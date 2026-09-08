import tempfile
import unittest
from pathlib import Path

from sigma_probe.config import Settings, load_config, settings_from_dict
from sigma_probe.validation import SigmaProbeError
from tests.helpers import ROOT


class ConfigTests(unittest.TestCase):
    def test_example_valid(self):
        config = load_config(ROOT / 'config.example.toml', environ={})
        self.assertEqual(config.site, 'demo-site')
        self.assertTrue(Path(config.input.files[0]).is_absolute())

    def test_unknown_top_level_and_nested_settings(self):
        for value in ({'misspelled': 1}, {'input': {'formatt': 'json'}}, {'detection': {'fft': True}}, {'scoring': {'weights': {'FAKE': 1}}}):
            with self.subTest(value=value), self.assertRaises(SigmaProbeError):
                settings_from_dict(value)

    def test_invalid_types_and_ranges(self):
        for value in ({'limits': {'max_events': True}}, {'limits': {'max_events': -1}}, {'privacy': {'anonymize_ips': 'false'}}, {'detection': {'temporal_cv': float('nan')}}, {'scoring': {'weights': {'XSS': '35'}}}, {'reporting': {'formats': []}}, {'input': {'max_error_ratio': 2}}, {'schema_version': 2}):
            with self.subTest(value=value), self.assertRaises(SigmaProbeError):
                settings_from_dict(value)

    def test_time_window_validation(self):
        for window in ({'since': '2026-09-08'}, {'since': '2026-09-08T01:00:00Z', 'until': '2026-09-08T00:00:00Z'}):
            with self.assertRaises(SigmaProbeError):
                settings_from_dict({'input': window})

    def test_nonfinite_toml_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.toml'
            path.write_text('[detection]\ntemporal_cv = nan\n')
            with self.assertRaises(SigmaProbeError):
                load_config(path, environ={})

    def test_config_duplicate_keys_invalid_syntax_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.toml'
            for content in ('site="a"\nsite="b"', '[broken', '#' * 65537):
                path.write_text(content)
                with self.subTest(size=len(content)), self.assertRaises(SigmaProbeError):
                    load_config(path, environ={})

    def test_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.toml'
            path.write_text('site="file"\n[reporting]\noutput_dir="relative"\n')
            config = load_config(path, environ={'SIGMA_PROBE_SITE': 'environment'}, overrides={'site': 'cli'})
            self.assertEqual(config.site, 'cli')
            self.assertEqual(config.reporting.output_dir, str(Path(directory) / 'relative'))
            config = load_config(path, environ={'SIGMA_PROBE_OUTPUT_DIR': 'environment-reports'})
            self.assertEqual(config.reporting.output_dir, 'environment-reports')

    def test_environment_config_path(self):
        config = load_config(environ={'SIGMA_PROBE_CONFIG': str(ROOT / 'config.example.toml')})
        self.assertEqual(config.site, 'demo-site')

    def test_partial_weights_preserve_defaults(self):
        config = settings_from_dict({'scoring': {'weights': {'XSS': 20}}})
        self.assertEqual(config.scoring.weights['XSS'], 20)
        self.assertEqual(config.scoring.weights['LFI_RFI'], 45)

    def test_duplicate_input_and_output_formats(self):
        for config in ({'input': {'files': ['-', '-']}}, {'reporting': {'formats': ['json', 'json']}}):
            with self.assertRaises(SigmaProbeError):
                settings_from_dict(config)

    def test_allowlist_and_proxy_validation(self):
        c = settings_from_dict({'allowlist_cidrs': ['192.0.2.3/24'], 'input': {'trusted_proxy_cidrs': ['2001:db8::/32']}})
        self.assertEqual(c.allowlist_cidrs, ('192.0.2.0/24',))
        with self.assertRaises(SigmaProbeError):
            settings_from_dict({'allowlist_cidrs': ['all']})

    def test_ioc_requires_files_and_rejects_urls(self):
        with self.assertRaises(SigmaProbeError):
            settings_from_dict({'ioc': {'enabled': True}})
        with self.assertRaises(SigmaProbeError):
            settings_from_dict({'ioc': {'files': [{'name': 'test', 'type': 'ip', 'path': 'https://example.test/feed'}]}})

    def test_mutable_weight_defaults_are_independent(self):
        a, b = Settings(), Settings()
        a.scoring.weights['XSS'] = 0
        self.assertEqual(b.scoring.weights['XSS'], 35)
