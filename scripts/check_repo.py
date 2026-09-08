"""Offline structural checks; intentionally not advertised as a full linter."""
from __future__ import annotations

import ast
import json
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    errors = []
    python_files = sorted([*ROOT.joinpath('src').rglob('*.py'), *ROOT.joinpath('tests').rglob('*.py'), *ROOT.joinpath('scripts').rglob('*.py'), ROOT / 'build_backend.py'])
    for path in python_files:
        source = path.read_text(encoding='utf-8')
        try:
            tree = ast.parse(source, filename=str(path))
            compile(tree, str(path), 'exec')
        except SyntaxError as exc:
            errors.append(f'{path.relative_to(ROOT)}: {exc.msg}')
            continue
        if ROOT / 'src' in path.parents:
            for node in ast.walk(tree):
                if isinstance(node, ast.Pass) or (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and node.value.value is Ellipsis):
                    errors.append(f'{path.relative_to(ROOT)}:{node.lineno}: placeholder body')
                if isinstance(node, ast.Import):
                    modules = [alias.name.split('.')[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    modules = [(node.module or '').split('.')[0]]
                else:
                    modules = []
                for module in modules:
                    if module not in sys.stdlib_module_names and module != 'sigma_probe':
                        errors.append(f'{path.relative_to(ROOT)}:{node.lineno}: non-stdlib runtime import {module}')
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
    if project['project']['dependencies'] or project['build-system']['requires']:
        errors.append('Unexpected runtime or build dependency')
    sys.path.insert(0, str(ROOT))
    import build_backend
    build_backend._project()
    docs = [ROOT / 'README.md', ROOT / 'CONTRIBUTING.md', ROOT / 'SECURITY.md', ROOT / 'CHANGELOG.md', *sorted((ROOT / 'docs').glob('*.md'))]
    link_count = 0
    for path in docs:
        if not path.exists():
            errors.append(f'Missing {path.name}')
            continue
        source = re.sub(r'(?ms)^```[^\n]*\n.*?^```\s*$', '', path.read_text(encoding='utf-8'))
        for target in re.findall(r'\]\(([^)]+)\)', source):
            link = target.split(' "', 1)[0].strip()
            parts = urlsplit(link)
            if parts.scheme or parts.netloc or not parts.path:
                continue
            resolved = (path.parent / unquote(parts.path)).resolve()
            link_count += 1
            if not resolved.exists():
                errors.append(f'{path.relative_to(ROOT)}: broken local link {link}')
    result = {'python_files_checked': len(python_files), 'local_documentation_links_checked': link_count, 'runtime_dependencies': len(project['project']['dependencies']), 'build_dependencies': len(project['build-system']['requires']), 'errors': errors, 'scope': 'syntax, runtime imports, placeholders, version consistency, local links; not a full type checker or vulnerability scanner'}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
