import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import ROOT, combined


def environment():
    return {**{k: v for k, v in os.environ.items() if not k.startswith('SIGMA_PROBE_')}, 'PYTHONPATH': str(ROOT / 'src')}


class CLITests(unittest.TestCase):
    def cli(self, *args, input=None, cwd=None):
        return subprocess.run([sys.executable, '-m', 'sigma_probe', *args], cwd=cwd or ROOT, env=environment(), input=input, capture_output=True, text=True, timeout=30)

    def test_version_and_help(self):
        result = self.cli('--version')
        self.assertEqual(result.returncode, 0)
        self.assertIn('3.0.0rc1', result.stdout)
        self.assertIn('analyze', self.cli('--help').stdout)

    def test_real_cli_writes_reports_and_clean_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.cli('analyze', '-i', 'examples/access.log', '-o', directory, '--format', 'json')
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload['summary']['accepted_events'], 56)
            self.assertTrue(Path(payload['reports']['json']).is_file())
            self.assertIn('Starting offline analysis', result.stderr)

    def test_fail_on_high_exit_three_after_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.cli('analyze', '-i', 'examples/access.log', '-o', directory, '--fail-on', 'high')
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertTrue(Path(json.loads(result.stdout)['reports']['html']).is_file())

    def test_input_partial_exit_four_precedes_risk(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'partial.toml'
            config.write_text('[input]\nmax_error_ratio=0.5\n')
            result = self.cli('analyze', '-c', str(config), '-i', '-', '-o', str(Path(directory) / 'reports'), '--fail-on', 'low', input=combined(target='/read?f=../etc/passwd') + 'invalid\n')
            self.assertEqual(result.returncode, 4, result.stderr)
            self.assertEqual(json.loads(result.stdout)['input_status'], 'partial')

    def test_bad_input_and_config_exit_two_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            for args in (('analyze', '-i', '/not/a/real/path', '-o', directory), ('analyze', '-i', 'examples/access.log', '--max-events', '0'), ('validate-config', '-c', '/missing')):
                result = self.cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('Traceback', result.stderr)
                self.assertEqual(result.stdout, '')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_unknown_cli_parameter_rejected(self):
        self.assertEqual(self.cli('analyze', '--made-up').returncode, 2)

    def test_legacy_flag_spelling_works(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.cli('--input', 'examples/access.log', '--output', directory, '--format', 'json')
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_stdin_and_json_logging(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.cli('analyze', '-i', '-', '-o', directory, '--json-logs', input=combined())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['summary']['accepted_events'], 1)
            self.assertTrue(all(json.loads(line)['level'] == 'INFO' for line in result.stderr.splitlines()))

    def test_config_validation_has_no_filesystem_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.cli('validate-config', '-c', str(ROOT / 'config.example.toml'), cwd=directory)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_import_has_no_logfile_or_other_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-c', 'import sigma_probe.main'], cwd=directory, env={**environment(), 'PYTHONDONTWRITEBYTECODE': '1'}, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_invalid_gzip_fails_without_partial_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.gz'
            path.write_bytes(b'not gzip')
            output = Path(directory) / 'reports'
            result = self.cli('analyze', '-i', str(path), '-o', str(output))
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())

    def signal_case(self, signum):
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, '-m', 'sigma_probe', 'analyze', '-i', '-', '-o', directory]
            process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stderr, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=10), 'CLI failed to reach ready state')
                    line = process.stderr.readline()
                    self.assertIn('Starting offline analysis', line)
                process.send_signal(signum)
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 128 + signum, stderr)
                self.assertEqual(stdout, '')
                self.assertNotIn('Traceback', stderr)
                self.assertEqual(list(Path(directory).iterdir()), [])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=10)

    @unittest.skipIf(sys.platform == 'win32', 'POSIX signals and pipe selectors are POSIX-specific')
    def test_sigterm_while_stdin_blocked(self):
        self.signal_case(signal.SIGTERM)

    @unittest.skipIf(sys.platform == 'win32', 'POSIX signals and pipe selectors are POSIX-specific')
    def test_sigint_while_stdin_blocked(self):
        self.signal_case(signal.SIGINT)
