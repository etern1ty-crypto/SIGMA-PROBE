"""Minimal PEP 517 backend for this dependency-free, pure-Python package.

Only stdlib is used. This is deliberately specific to SIGMA-PROBE, not a
replacement for general-purpose packaging tools. Wheel RECORD hashes and
source archives are reproducible with SOURCE_DATE_EPOCH.
"""
from __future__ import annotations

import ast
import base64
import csv
import gzip
import hashlib
import io
import os
import tarfile
import tomllib
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _project() -> dict[str, Any]:
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']
    module = ast.parse((ROOT / 'src/sigma_probe/__init__.py').read_text(encoding='utf-8'))
    version = next(ast.literal_eval(node.value) for node in module.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == '__version__' for target in node.targets))
    if version != project['version']:
        raise ValueError('Package and pyproject versions disagree')
    return project


def _metadata_files() -> tuple[str, dict[str, bytes]]:
    project = _project()
    stem = f"sigma_probe-{project['version']}.dist-info"
    metadata = '\n'.join([
        'Metadata-Version: 2.4', 'Name: sigma-probe', f"Version: {project['version']}",
        f"Summary: {project['description']}", f"Requires-Python: {project['requires-python']}",
        f"License-Expression: {project['license']}", 'License-File: LICENSE', 'License-File: NOTICE',
        'Author: Original project: Etern1ty Crypto / eternity-crypto',
        'Description-Content-Type: text/markdown; charset=UTF-8', '',
        (ROOT / 'README.md').read_text(encoding='utf-8'),
    ])
    return stem, {
        f'{stem}/METADATA': metadata.encode('utf-8'),
        f'{stem}/WHEEL': b'Wheel-Version: 1.0\nGenerator: sigma-probe-stdlib-backend\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
        f'{stem}/entry_points.txt': b'[console_scripts]\nsigma-probe = sigma_probe.main:main\n',
        f'{stem}/licenses/LICENSE': (ROOT / 'LICENSE').read_bytes(),
        f'{stem}/licenses/NOTICE': (ROOT / 'NOTICE').read_bytes(),
    }


def get_requires_for_build_wheel(config_settings: Any = None) -> list[str]:
    return []


def get_requires_for_build_sdist(config_settings: Any = None) -> list[str]:
    return []


def prepare_metadata_for_build_wheel(metadata_directory: str, config_settings: Any = None) -> str:
    stem, content = _metadata_files()
    for name, data in content.items():
        path = Path(metadata_directory) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return stem


def build_wheel(wheel_directory: str, config_settings: Any = None, metadata_directory: str | None = None) -> str:
    stem, content = _metadata_files()
    for path in sorted((ROOT / 'src/sigma_probe').rglob('*')):
        if path.is_symlink():
            raise ValueError('Symlinks are not allowed in package sources')
        if path.is_file() and path.suffix in ('.py', '.css'):
            content[path.relative_to(ROOT / 'src').as_posix()] = path.read_bytes()
    rows = []
    for name, data in sorted(content.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode('ascii')
        rows.append((name, 'sha256=' + digest, str(len(data))))
    rows.append((f'{stem}/RECORD', '', ''))
    buffer = io.StringIO(newline='')
    csv.writer(buffer, lineterminator='\n').writerows(rows)
    content[f'{stem}/RECORD'] = buffer.getvalue().encode('utf-8')
    filename = f"sigma_probe-{_project()['version']}-py3-none-any.whl"
    target = Path(wheel_directory)
    target.mkdir(parents=True, exist_ok=True)
    import time
    epoch = max(315532800, int(os.environ.get('SOURCE_DATE_EPOCH', '1577836800')))
    stamp = time.gmtime(epoch)[:6]
    with zipfile.ZipFile(target / filename, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(content.items()):
            info = zipfile.ZipInfo(name, stamp)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    return filename


def _source_files() -> list[Path]:
    allowed_roots = {'src', 'tests', 'examples', 'scripts', 'docs', '.github', 'evidence'}
    allowed_files = {'pyproject.toml', 'build_backend.py', 'README.md', 'LICENSE', 'NOTICE', 'CONTRIBUTING.md', 'SECURITY.md', 'CHANGELOG.md', 'Dockerfile', 'docker-compose.yml', '.dockerignore', '.gitignore', '.env.example', 'requirements.txt', 'config.example.toml'}
    result = []
    candidates = [ROOT / name for name in sorted(allowed_files)]
    for name in sorted(allowed_roots):
        folder = ROOT / name
        if folder.is_symlink():
            raise ValueError('Symlinks are not allowed in source archives')
        if folder.exists():
            candidates.extend(folder.rglob('*'))
    for path in candidates:
        relative = path.relative_to(ROOT)
        if '__pycache__' in relative.parts or path.suffix in ('.pyc', '.pyo'):
            continue
        if path.is_symlink():
            raise ValueError('Symlinks are not allowed in source archives')
        if path.is_file():
            result.append(path)
    return sorted(result)


def build_sdist(sdist_directory: str, config_settings: Any = None) -> str:
    project = _project()
    prefix = f"sigma_probe-{project['version']}"
    filename = prefix + '.tar.gz'
    output = Path(sdist_directory)
    output.mkdir(parents=True, exist_ok=True)
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '1577836800'))
    with (output / filename).open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch) as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as archive:
                for path in _source_files():
                    data = path.read_bytes()
                    info = tarfile.TarInfo(prefix + '/' + path.relative_to(ROOT).as_posix())
                    info.size, info.mtime, info.mode = len(data), epoch, 0o644
                    archive.addfile(info, io.BytesIO(data))
                info = tarfile.TarInfo(prefix + '/PKG-INFO')
                metadata = _metadata_files()[1][prefix + '.dist-info/METADATA']
                info.size, info.mtime, info.mode = len(metadata), epoch, 0o644
                archive.addfile(info, io.BytesIO(metadata))
    return filename
