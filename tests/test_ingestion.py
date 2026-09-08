import gzip
import io
import json
import tempfile
import unittest
from pathlib import Path

from sigma_probe.config import InputConfig, LimitsConfig
from sigma_probe.pipeline.ingestion import LogIngestionStage
from sigma_probe.validation import LimitExceeded, SigmaProbeError
from tests.helpers import BASE, combined


class IngestionTests(unittest.TestCase):
    def stage(self, **settings):
        return LogIngestionStage(InputConfig(**settings), LimitsConfig())

    def test_nginx_combined(self):
        e = self.stage().parse_line(combined())
        self.assertEqual((e.method, e.url, e.status_code, e.response_size), ('GET', '/', 200, 128))
        self.assertEqual(e.timestamp, BASE)

    def test_common_ipv6_dash_bytes_and_timezone(self):
        line = '2001:db8::1 - - [08/Sep/2026:03:00:00 +0300] "GET / HTTP/1.1" 200 -'
        e = self.stage(format='common').parse_line(line)
        self.assertEqual(e.timestamp, BASE)
        self.assertEqual((e.source_ip, e.response_size), ('2001:db8::1', 0))

    def test_escaped_quotes_and_hex(self):
        e = self.stage().parse_line(combined(agent=r'Agent \"quoted\" \x41'))
        self.assertEqual(e.user_agent, 'Agent "quoted" A')

    def test_json_canonical_and_nginx_aliases(self):
        for row in ({'timestamp': BASE.isoformat(), 'source_ip': '203.0.113.1', 'method': 'GET', 'url': '/', 'status_code': 200}, {'time_iso8601': BASE.isoformat(), 'remote_addr': '203.0.113.1', 'request_method': 'GET', 'request_uri': '/', 'status': '200', 'body_bytes_sent': '-'}):
            with self.subTest(row=row):
                self.assertEqual(self.stage().parse_line(json.dumps(row)).timestamp, BASE)

    def test_json_rejects_alias_conflicts_and_duplicate_keys(self):
        base = {'timestamp': BASE.isoformat(), 'source_ip': '203.0.113.1', 'method': 'GET', 'url': '/', 'status_code': 200}
        with self.assertRaises(SigmaProbeError):
            self.stage().parse_line(json.dumps({**base, 'request_uri': '/other'}))
        with self.assertRaises(SigmaProbeError):
            self.stage(format='json').parse_line('{"url":"/a","url":"/b"}')

    def test_json_rejects_nonfinite_values_and_booleans(self):
        for row in ('{"timestamp":NaN}', '[]', '{"status":true}', '{"x":Infinity}'):
            with self.assertRaises(SigmaProbeError):
                self.stage(format='json').parse_line(row)

    def test_untrusted_forwarded_header_ignored(self):
        row = {'timestamp': BASE.isoformat(), 'remote_addr': '198.51.100.5', 'request_method': 'GET', 'request_uri': '/', 'status': 200, 'http_x_forwarded_for': '203.0.113.99'}
        self.assertEqual(self.stage().parse_line(json.dumps(row)).source_ip, '198.51.100.5')

    def test_trusted_proxy_right_to_left(self):
        row = {'timestamp': BASE.isoformat(), 'remote_addr': '10.0.0.2', 'request_method': 'GET', 'request_uri': '/', 'status': 200, 'http_x_forwarded_for': '203.0.113.99, 198.51.100.5, 10.0.0.1'}
        stage = self.stage(trusted_proxy_cidrs=('10.0.0.0/24',))
        self.assertEqual(stage.parse_line(json.dumps(row)).source_ip, '198.51.100.5')
        row['http_x_forwarded_for'] = 'invalid'
        with self.assertRaises(SigmaProbeError):
            stage.parse_line(json.dumps(row))

    def test_time_filter_lower_inclusive_upper_exclusive(self):
        stage = self.stage(since='2026-09-08T00:00:00Z', until='2026-09-08T00:00:01Z')
        data = combined() + combined(stamp='08/Sep/2026:00:00:01 +0000')
        self.assertEqual(len(list(stage.process(['-'], io.BytesIO(data.encode())))), 1)
        self.assertEqual(stage.stats.total('filtered'), 1)

    def test_partial_input_counted_and_safe_error_messages(self):
        stage = self.stage(max_error_ratio=0.5)
        data = combined() + 'invalid SECRET_TOKEN\n'
        self.assertEqual(len(list(stage.process(['-'], io.BytesIO(data.encode())))), 1)
        self.assertTrue(stage.stats.partial)
        self.assertNotIn('SECRET_TOKEN', str(stage.stats.errors))

    def test_strict_ratio_and_all_invalid_failure(self):
        for cfg, data in (({'invalid_policy': 'error'}, combined() + 'bad\n'), ({'max_error_ratio': 0.1}, combined() + 'bad\n'), ({'max_error_ratio': 1}, 'bad\n')):
            with self.subTest(cfg=cfg), self.assertRaises(SigmaProbeError):
                list(self.stage(**cfg).process(['-'], io.BytesIO(data.encode())))

    def test_empty_blank_input_is_explicit_and_valid(self):
        stage = self.stage()
        self.assertEqual(list(stage.process(['-'], io.BytesIO(b'\n  \n'))), [])
        self.assertEqual(stage.stats.total('blank'), 2)
        self.assertFalse(stage.stats.partial)

    def test_input_limits(self):
        for limits, data in ((LimitsConfig(max_events=1), (combined() * 2).encode()), (LimitsConfig(max_input_bytes=1), combined().encode()), (LimitsConfig(max_line_bytes=64), b'x' * 65)):
            with self.subTest(limits=limits), self.assertRaises(LimitExceeded):
                list(LogIngestionStage(InputConfig(), limits).process(['-'], io.BytesIO(data)))

    def test_gzip_and_decompressed_hash(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.gz'
            raw = combined().encode()
            path.write_bytes(gzip.compress(raw))
            stage = self.stage()
            self.assertEqual(len(list(stage.process([str(path)]))), 1)
            self.assertEqual(stage.stats.sources[0].sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(stage.stats.sources[0].bytes_read, len(raw))

    def test_duplicate_file_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.log'
            path.write_text(combined())
            with self.assertRaises(SigmaProbeError):
                list(self.stage().process([str(path), str(path.parent / '.' / path.name)]))

    def test_missing_file_and_directory_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in (directory, str(Path(directory) / 'missing')):
                with self.assertRaises(SigmaProbeError):
                    list(self.stage().process([path]))

    def test_invalid_utf8_counted_without_replacement(self):
        stage = self.stage(max_error_ratio=0.5)
        list(stage.process(['-'], io.BytesIO(combined().encode() + b'\xff\n')))
        self.assertEqual(stage.stats.total('invalid'), 1)

    def test_dash_request_is_invalid_not_fake_event(self):
        with self.assertRaises(SigmaProbeError):
            self.stage().parse_line('203.0.113.1 - - [08/Sep/2026:00:00:00 +0000] "-" 400 0')

    def test_reuse_resets_stats_and_stdin_is_not_closed(self):
        stage = self.stage()
        handle = io.BytesIO(combined().encode())
        list(stage.process(['-'], handle))
        self.assertFalse(handle.closed)
        list(stage.process(['-'], io.BytesIO(combined().encode())))
        self.assertEqual(stage.stats.total('accepted'), 1)
