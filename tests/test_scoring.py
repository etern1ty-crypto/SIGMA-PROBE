import unittest

from sigma_probe.config import ScoringConfig
from sigma_probe.models.core import ActorProfile, ThreatCampaign
from sigma_probe.pipeline.base import AnalysisContext
from sigma_probe.pipeline.rules_engine import ScoringRulesEngine
from sigma_probe.pipeline.scoring import ScoringEngine
from tests.helpers import actor


class ScoringTests(unittest.TestCase):
    def test_single_payload_base(self):
        a = actor('203.0.113.1', ['/read?f=../etc/passwd'])
        score, details = ScoringRulesEngine(ScoringConfig()).calculate_score(a)
        self.assertEqual(score, 45)
        self.assertEqual(details, {'LFI_RFI': 45})

    def test_repetition_and_additive_breakdown(self):
        a = actor('203.0.113.1', ['/read?f=../etc/passwd'] * 8)
        score, details = ScoringRulesEngine(ScoringConfig()).calculate_score(a)
        self.assertEqual(score, 54)
        self.assertEqual(sum(details.values()), score)

    def test_score_bounded_and_no_order_dependence(self):
        tags = ['LFI_RFI', 'SQL_INJECTION', 'COMMAND_INJECTION', 'XSS']
        a = ActorProfile('203.0.113.1', tags=set(tags))
        b = ActorProfile('203.0.113.2', tags=set(reversed(tags)))
        engine = ScoringRulesEngine(ScoringConfig())
        self.assertEqual(engine.calculate_score(a), engine.calculate_score(b))
        score, details = engine.calculate_score(a)
        self.assertEqual(score, 100)
        self.assertEqual(sum(details.values()), 100)
        self.assertLess(details['cap_adjustment'], 0)

    def test_allowlist_suppression_preserves_evidence(self):
        a = actor('203.0.113.1', ['/read?f=../etc/passwd'])
        a.suppressed = True
        context = AnalysisContext([a])
        ScoringEngine(ScoringConfig()).process(context)
        self.assertEqual((a.threat_score, a.severity), (0, 'info'))
        self.assertIn('LFI_RFI', a.tags)

    def test_all_weights_zero_disable_repetition(self):
        a = actor('203.0.113.1', ['/read?f=../etc/passwd'] * 100)
        engine = ScoringRulesEngine(ScoringConfig(weights={'LFI_RFI': 0}))
        self.assertEqual(engine.calculate_score(a), (0, {}))

    def test_custom_thresholds(self):
        engine = ScoringRulesEngine(ScoringConfig(medium_threshold=20, high_threshold=60))
        self.assertEqual([engine.severity(x) for x in (0, 19, 20, 59, 60, 100)], ['info', 'low', 'medium', 'medium', 'high', 'high'])

    def test_campaign_scored_after_final_actor_scores(self):
        a = actor('203.0.113.1', ['/read?f=../etc/passwd'])
        b = actor('203.0.113.2', ['/read?f=../etc/passwd'])
        a.tags.add('CORRELATED_ACTIVITY')
        b.tags.add('CORRELATED_ACTIVITY')
        context = AnalysisContext([a, b], [ThreatCampaign('group-test', [a, b])])
        engine = ScoringEngine(ScoringConfig())
        engine.process(context)
        self.assertEqual(context.campaigns[0].threat_score, 55)
        first = len(a.evidence_trail)
        engine.process(context)
        self.assertEqual(len(a.evidence_trail), first)

    def test_benign_population_does_not_amplify_other_actor(self):
        a = actor('203.0.113.1', ['/read?f=../etc/passwd'])
        context = AnalysisContext([a] + [ActorProfile(f'198.51.100.{i}') for i in range(1, 151)])
        ScoringEngine(ScoringConfig()).process(context)
        self.assertEqual(a.threat_score, 45)
