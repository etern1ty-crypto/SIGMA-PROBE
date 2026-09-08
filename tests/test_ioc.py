import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from sigma_probe.config import IoCConfig, IoCFileConfig, Settings
from sigma_probe.intelligence.ioc_manager import IoCManager
from sigma_probe.main import AnalysisPipeline
from sigma_probe.validation import LimitExceeded, SigmaProbeError
from tests.helpers import BASE, ROOT, event


class IoCTests(unittest.TestCase):
    def test_exact_ip_not_substring_and_cidr_ipv6(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ips.txt'
            path.write_text('192.0.2.1\n2001:db8::/32\n')
            manager = IoCManager(IoCConfig(enabled=True, files=(IoCFileConfig('local', str(path), 'ip'),)))
            yes, no, six = event(ip='192.0.2.1'), event(ip='192.0.2.10'), event(ip='2001:db8::abcd')
            for e in (yes, no, six):
                manager.enrich_event(e)
            self.assertIn('IOC_MATCH', yes.heuristic_flags)
            self.assertNotIn('IOC_MATCH', no.heuristic_flags)
            self.assertIn('IOC_MATCH', six.heuristic_flags)
            self.assertEqual(manager.get_stats()['matched_events'], 2)

    def test_local_ioc_is_applied_end_to_end(self):
        config = Settings(ioc=IoCConfig(enabled=True, files=(IoCFileConfig('synthetic', str(ROOT / 'examples/ioc-ips.txt'), 'ip'),)))
        result = AnalysisPipeline(config).run(str(ROOT / 'examples/access.log'), write_reports=False)
        a = next(a for a in result.actors if a.ip_address == '192.0.2.44')
        self.assertIn('IOC_MATCH', a.tags)
        self.assertEqual(a.threat_score, 35)
        self.assertEqual(result.detector_summary['ioc']['matched_events'], 1)

    def test_path_is_exact_and_ua_is_literal(self):
        with tempfile.TemporaryDirectory() as directory:
            path, ua = Path(directory) / 'paths', Path(directory) / 'ua'
            path.write_text('/blocked\n')
            ua.write_text('customscan\n')
            manager = IoCManager(IoCConfig(enabled=True, files=(IoCFileConfig('paths', str(path), 'url_path'), IoCFileConfig('agents', str(ua), 'user_agent'))))
            for e, expected in ((event('/blocked'), True), (event('/blocked-extra'), False), (event('/', agent='CUSTOMSCAN/1.0'), True)):
                manager.enrich_event(e)
                self.assertEqual('IOC_MATCH' in e.heuristic_flags, expected)

    def test_expired_feed_rejected_before_read(self):
        config = IoCConfig(enabled=True, files=(IoCFileConfig('expired', '/does/not/exist', 'ip', BASE),))
        with self.assertRaisesRegex(SigmaProbeError, 'expired'):
            IoCManager(config, now=BASE + timedelta(seconds=1))

    def test_invalid_empty_and_oversized_feeds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ips'
            for data in ('not-an-ip\n', '# no values\n'):
                path.write_text(data)
                with self.assertRaises(SigmaProbeError):
                    IoCManager(IoCConfig(enabled=True, files=(IoCFileConfig('local', str(path), 'ip'),)))
            path.write_text('192.0.2.1\n192.0.2.2\n')
            for config in (IoCConfig(enabled=True, max_file_bytes=1, files=(IoCFileConfig('local', str(path), 'ip'),)), IoCConfig(enabled=True, max_entries=1, files=(IoCFileConfig('local', str(path), 'ip'),))):
                with self.assertRaises(LimitExceeded):
                    IoCManager(config)

    def test_disabled_ioc_does_not_read_files(self):
        manager = IoCManager(IoCConfig(enabled=False, files=(IoCFileConfig('missing', '/does/not/exist', 'ip'),)))
        self.assertEqual(manager.get_stats()['feeds'], [])
