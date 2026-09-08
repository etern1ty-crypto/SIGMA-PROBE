"""Build a wheel, source tarball and portable zipapp entirely offline."""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import build_backend


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    wheel = build_backend.build_wheel(str(output))
    sdist = build_backend.build_sdist(str(output))
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory)
        shutil.copytree(ROOT / 'src/sigma_probe', source / 'sigma_probe', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        (source / '__main__.py').write_text('from sigma_probe.main import main\nraise SystemExit(main())\n', encoding='utf-8')
        epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '1577836800'))
        for path in source.rglob('*'):
            os.utime(path, (epoch, epoch))
        zipapp.create_archive(source, target=output / 'sigma-probe.pyz', interpreter='/usr/bin/env python3', compressed=True)
    for name in (wheel, sdist, 'sigma-probe.pyz'):
        print(output / name)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
