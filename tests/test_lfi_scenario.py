"""Executable end-to-end regressions; no skipped scenarios or missing fixtures."""
import io
import json
import os
import subprocess
import sys
import unittest
from dataclasses import replace
from unittest.mock import patch

from sigma_probe.config import LimitsConfig, Settings
from sigma_probe.main import AnalysisPipeline
from sigma_probe.validation import LimitExceeded
from tests.helpers import ROOT


class EndToEndTests(unittest.TestCase):
    def run_fixture(self, config=None):
        return AnalysisPipeline(config or Settings()).run(str(ROOT / 'tests/fixtures/lfi_scenario.log'), write_reports=False)

    def test_full_lfi_scenario_and_campaign(self):
        result = self.run_fixture()
        self.assertEqual(result.ingestion.total('accepted'), 56)
        self.assertEqual(len(result.actors), 7)
        attackers = [a for a in result.actors if a.ip_address in ('203.0.113.10', '203.0.113.11')]
        self.assertEqual(len(attackers), 2)
        for a in attackers:
            self.assertTrue({'LFI_RFI', 'AUTOMATED_SCAN', 'CORRELATED_ACTIVITY', 'MULTIPLE_SIGNALS'} <= a.tags)
            self.assertEqual(a.severity, 'high')
            self.assertTrue(any(e.references for e in a.evidence_trail))
            self.assertIn('T1190', {t['id'] for t in a.mitre_techniques})
        self.assertEqual(len(result.campaigns), 1)
        self.assertEqual(result.campaigns[0].threat_score, sum(a.threat_score for a in attackers) / 2)
        self.assertTrue(result.recommendations)

    def test_benign_health_php_and_redirect_stay_zero(self):
        result = self.run_fixture()
        for ip in ('198.51.100.20', '198.51.100.21', '2001:db8::21'):
            a = next(a for a in result.actors if a.ip_address == ip)
            self.assertEqual(a.threat_score, 0)
            self.assertEqual(a.tags, set())

    def test_reuse_has_no_stale_context(self):
        pipeline = AnalysisPipeline(Settings())
        pipeline.run(str(ROOT / 'examples/access.log'), write_reports=False)
        empty = pipeline.run('-', write_reports=False, stdin=io.BytesIO(b''))
        self.assertEqual(empty.report['summary']['actors'], 0)
        self.assertEqual(empty.campaigns, [])
        self.assertEqual(empty.ingestion.total('accepted'), 0)

    def test_no_network_access_in_full_run(self):
        with patch('socket.socket', side_effect=AssertionError('Network access is forbidden')):
            self.assertEqual(self.run_fixture().ingestion.total('accepted'), 56)

    def test_actor_budget_is_enforced(self):
        with self.assertRaises(LimitExceeded):
            self.run_fixture(replace(Settings(), limits=LimitsConfig(max_actors=1)))

    def test_allowlist_is_visible_and_excluded_from_groups(self):
        result = self.run_fixture(Settings(allowlist_cidrs=('203.0.113.0/24',)))
        self.assertEqual(result.report['summary']['suppressed'], 2)
        self.assertEqual(result.campaigns, [])
        for a in result.actors:
            if a.suppressed:
                self.assertEqual(a.threat_score, 0)
                self.assertTrue(a.evidence_trail)

    def test_jsonl_and_combined_equivalence(self):
        a = self.run_fixture()
        b = AnalysisPipeline(Settings()).run(str(ROOT / 'examples/access.jsonl'), write_reports=False)
        self.assertEqual([(x.ip_address, x.threat_score, x.tags) for x in a.actors], [(x.ip_address, x.threat_score, x.tags) for x in b.actors])

    def test_hash_seed_independence(self):
        command = [sys.executable, '-c', 'import json; from sigma_probe.main import AnalysisPipeline; from sigma_probe.config import Settings; r=AnalysisPipeline(Settings()).run("examples/access.log",write_reports=False).report; print(json.dumps({k:r[k] for k in ("actors","campaigns","recommendations","detectors")},sort_keys=True))']
        outputs = []
        for seed in ('1', '987'):
            env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONHASHSEED=seed)
            result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs.append(json.loads(result.stdout))
        self.assertEqual(outputs[0], outputs[1])
