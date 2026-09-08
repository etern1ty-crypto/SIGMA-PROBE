import base64
import csv
import hashlib
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import build_backend
from tests.helpers import ROOT


class PackagingTests(unittest.TestCase):
    def test_wheel_metadata_assets_and_record_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            name = build_backend.build_wheel(directory)
            with zipfile.ZipFile(Path(directory) / name) as archive:
                self.assertIn('sigma_probe/assets/report.css', archive.namelist())
                metadata = archive.read('sigma_probe-3.0.0rc1.dist-info/METADATA').decode()
                self.assertNotIn('Requires-Dist:', metadata)
                self.assertIn('Requires-Python: >=3.11', metadata)
                record = archive.read('sigma_probe-3.0.0rc1.dist-info/RECORD').decode()
                for filename, digest, length in csv.reader(io.StringIO(record)):
                    if not digest:
                        continue
                    data = archive.read(filename)
                    computed = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
                    self.assertEqual(computed, digest)
                    self.assertEqual(len(data), int(length))

    def test_wheel_is_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / 'a', Path(directory) / 'b'
            first = a / build_backend.build_wheel(str(a))
            second = b / build_backend.build_wheel(str(b))
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_sdist_has_safe_paths_and_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / build_backend.build_sdist(directory)
            with tarfile.open(path) as archive:
                names = archive.getnames()
                self.assertTrue(any(name.endswith('/build_backend.py') for name in names))
                self.assertTrue(any(name.endswith('/tests/fixtures/lfi_scenario.log') for name in names))
                self.assertTrue(all(not name.startswith('/') and '..' not in Path(name).parts for name in names))
                self.assertFalse(any('__pycache__' in name or name.endswith('/.env') for name in names))

    def test_zipapp_runs_without_site_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, 'scripts/build_dist.py', '--output', directory], cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            app = str(Path(directory) / 'sigma-probe.pyz')
            version = subprocess.run([sys.executable, '-I', '-S', app, '--version'], capture_output=True, text=True, timeout=20)
            self.assertEqual(version.returncode, 0, version.stderr)
            report = subprocess.run([sys.executable, '-I', '-S', app, 'analyze', '-i', str(ROOT / 'examples/access.log'), '-o', str(Path(directory) / 'reports')], capture_output=True, text=True, timeout=20)
            self.assertEqual(report.returncode, 0, report.stderr)
            self.assertIn('accepted_events', report.stdout)


class SourceSelectionTests(unittest.TestCase):
    def test_local_venv_symlinks_are_not_source_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.venv/bin').mkdir(parents=True)
            (root / '.venv/bin/python').symlink_to(sys.executable)
            (root / 'src/sigma_probe').mkdir(parents=True)
            (root / 'src/sigma_probe/__init__.py').write_text('')
            with patch.object(build_backend, 'ROOT', root):
                files = build_backend._source_files()
            self.assertEqual([p.relative_to(root).as_posix() for p in files], ['src/sigma_probe/__init__.py'])

    def test_symlink_in_selected_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'src').mkdir()
            (root / 'src/bad.py').symlink_to(sys.executable)
            with patch.object(build_backend, 'ROOT', root):
                with self.assertRaises(ValueError):
                    build_backend._source_files()
