"""Prepare AIT-LDS V2.1 Apache access-log actor labels for local evaluation."""
import argparse
import json
import zipfile
from pathlib import Path

ACCESS = 'intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.2'
HTTP_ATTACK = {'attacker_http', 'dirb', 'wpscan', 'webshell_cmd', 'webshell_upload'}


def prepare(archive: Path, output: Path) -> None:
    with zipfile.ZipFile(archive) as source:
        lines = source.read('gather/' + ACCESS).decode('utf-8').splitlines()
        records = [json.loads(row) for row in source.read('labels/' + ACCESS).splitlines()]
    if len(lines) != 8530 or len(records) != 7695:
        raise ValueError('unexpected AIT-LDS V2.1 access log or label count')
    indexes = {row['line'] for row in records}
    if len(indexes) != len(records) or min(indexes) < 0 or max(indexes) >= len(lines):
        raise ValueError('duplicate or out-of-range line labels')
    actors = {line.split()[0] for line in lines}
    policies = {'all_labels': set(), 'http_attack_only': set()}
    for row in records:
        actor = lines[row['line']].split()[0]
        policies['all_labels'].add(actor)
        if HTTP_ATTACK.intersection(row['labels']):
            policies['http_attack_only'].add(actor)

    # Apache 408 records with '-' have no HTTP request; none are labeled.
    dropped = [line for line in lines if ' "-" 408 ' in line]
    if len(dropped) != 14 or any(' "-" 408 ' in lines[row['line']] for row in records):
        raise ValueError('unexpected timeout records or labels')
    valid = [line for line in lines if ' "-" 408 ' not in line]
    output.mkdir(parents=True, exist_ok=True)
    (output / 'ait-intranet-requests.log').write_text('\n'.join(valid) + '\n', encoding='utf-8')
    for name, attacks in policies.items():
        manifest = {'schema_version': 1, 'dataset_kind': 'testbed', 'cases': [{
            'log': 'ait-intranet-requests.log',
            'labels': {actor: 'attack' if actor in attacks else 'benign' for actor in sorted(actors)},
        }]}
        (output / f'ait-{name}-labels.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(f'{len(valid)} valid requests; {len(dropped)} timeout records omitted; {len(actors)} actors')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path, help='downloaded russellmitchell_no-pcaps.zip')
    parser.add_argument('output', type=Path, help='private directory for derived logs and labels')
    args = parser.parse_args()
    prepare(args.archive, args.output)
