import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate import evaluate
from tests.helpers import ROOT


class EvaluationTests(unittest.TestCase):
    def test_synthetic_actor_metrics_and_complete_label_requirement(self):
        labels = {
            '203.0.113.10': 'attack', '203.0.113.11': 'attack', '192.0.2.60': 'attack',
            '192.0.2.44': 'benign', '198.51.100.20': 'benign',
            '198.51.100.21': 'benign', '2001:db8::21': 'benign',
        }
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / 'labels.json'
            data = {'schema_version': 1, 'dataset_kind': 'synthetic',
                    'cases': [{'log': str(ROOT / 'examples/access.log'), 'labels': labels}]}
            manifest.write_text(json.dumps(data), encoding='utf-8')
            result = evaluate(manifest)
            self.assertEqual(result['counts'], {'tp': 3, 'fp': 0, 'tn': 4, 'fn': 0, 'unknown': 0})
            self.assertEqual(result['coverage'], 1)
            self.assertEqual(result['cases'][0]['accepted_events'], 56)
            del labels['192.0.2.44']
            manifest.write_text(json.dumps(data), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'labels must cover every observed actor'):
                evaluate(manifest)

    def test_partial_input_is_not_reported_as_accuracy(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'access.log'
            valid = (ROOT / 'examples/access.log').read_text(encoding='utf-8')
            log.write_text(valid + '203.0.113.10 - - [01/Jan/2026:00:00:00 +0000] "-" 408 0 "-" "-"\n', encoding='utf-8')
            manifest = Path(directory) / 'labels.json'
            labels = json.loads((ROOT / 'examples/evaluation-labels.json').read_text(encoding='utf-8'))['cases'][0]['labels']
            manifest.write_text(json.dumps({'schema_version': 1, 'dataset_kind': 'testbed',
                                            'cases': [{'log': str(log), 'labels': labels}]}), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'partial ingestion'):
                evaluate(manifest)
