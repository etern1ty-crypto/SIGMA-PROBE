import unittest
from dataclasses import replace

from sigma_probe.config import DetectionConfig, LimitsConfig
from sigma_probe.pipeline.base import AnalysisContext
from sigma_probe.pipeline.detectors import BehaviorDetector, GraphDetector, TemporalDetector, cosine_similarity
from sigma_probe.pipeline.metadetector import MetaDetector
from sigma_probe.validation import LimitExceeded
from tests.helpers import actor


def probes(paths):
    return [path + '?file=../etc/passwd' for path in paths]


class DetectorTests(unittest.TestCase):
    def test_health_check_cadence_does_not_become_attack(self):
        a = actor('203.0.113.1', ['/health'] * 15, status=200, agent='curl/8.0')
        context = AnalysisContext([a])
        TemporalDetector(DetectionConfig()).process(context)
        self.assertNotIn('AUTOMATED_SCAN', a.tags)
        self.assertEqual(context.summary['temporal']['rhythmic_actors'], 1)

    def test_periodic_payload_attempts_have_evidence(self):
        a = actor('203.0.113.1', ['/read?f=../etc/passwd'] * 15)
        TemporalDetector(DetectionConfig()).process(AnalysisContext([a]))
        self.assertIn('AUTOMATED_SCAN', a.tags)
        self.assertTrue(any(e.kind == 'AUTOMATED_SCAN' and e.references for e in a.evidence_trail))

    def test_identical_timestamps_do_not_prove_rhythm(self):
        a = actor('203.0.113.1', ['/read?f=../etc/passwd'] * 15, interval=0)
        TemporalDetector(DetectionConfig()).process(AnalysisContext([a]))
        self.assertNotIn('AUTOMATED_SCAN', a.tags)

    def test_temporal_threshold_used(self):
        a = actor('203.0.113.1', ['/read?f=../etc/passwd'] * 5)
        TemporalDetector(replace(DetectionConfig(), temporal_min_events=4)).process(AnalysisContext([a]))
        self.assertIn('AUTOMATED_SCAN', a.tags)

    def test_enumeration_requires_distinct_error_paths(self):
        a = actor('203.0.113.1', [f'/not-found-{n}' for n in range(12)])
        b = actor('203.0.113.2', ['/health'] * 12, status=404)
        c = actor('203.0.113.3', [f'/product-{n}' for n in range(12)], status=200)
        BehaviorDetector(DetectionConfig()).process(AnalysisContext([a, b, c]))
        self.assertIn('ENUMERATION', a.tags)
        self.assertNotIn('ENUMERATION', b.tags)
        self.assertNotIn('ENUMERATION', c.tags)

    def test_auth_burst_is_windowed_and_path_specific(self):
        fast = actor('203.0.113.1', ['/login'] * 12, status=401)
        slow = actor('203.0.113.2', ['/login'] * 12, interval=400, status=401)
        wrong_path = actor('203.0.113.3', ['/private-image'] * 12, status=401)
        BehaviorDetector(DetectionConfig()).process(AnalysisContext([fast, slow, wrong_path]))
        self.assertIn('AUTH_FAILURE_BURST', fast.tags)
        self.assertNotIn('AUTH_FAILURE_BURST', slow.tags)
        self.assertNotIn('AUTH_FAILURE_BURST', wrong_path.tags)

    def test_error_burst_threshold(self):
        a = actor('203.0.113.1', ['/api'] * 31, status=503)
        BehaviorDetector(DetectionConfig()).process(AnalysisContext([a]))
        self.assertIn('ERROR_BURST', a.tags)

    def test_meta_does_not_invent_botnet_or_inflate_scores(self):
        a = actor('203.0.113.1', ['/read?f=../etc/passwd'] * 12)
        context = AnalysisContext([a])
        TemporalDetector(DetectionConfig()).process(context)
        MetaDetector().process(context)
        self.assertIn('MULTIPLE_SIGNALS', a.tags)
        self.assertFalse(any(tag.startswith('CONFIRMED') for tag in a.tags))


class CorrelationTests(unittest.TestCase):
    def run_graph(self, actors, detection=None, limits=None):
        context = AnalysisContext(actors)
        GraphDetector(detection or DetectionConfig(), limits or LimitsConfig()).process(context)
        return context

    def test_shared_suspicious_paths_form_group(self):
        a = actor('203.0.113.1', probes(['/a', '/b']))
        b = actor('203.0.113.2', probes(['/a', '/b']), start=1)
        context = self.run_graph([a, b])
        self.assertEqual(len(context.campaigns), 1)
        self.assertEqual({x.ip_address for x in context.campaigns[0].actors}, {'203.0.113.1', '203.0.113.2'})

    def test_unrelated_equal_shape_vectors_do_not_form_group(self):
        a = actor('203.0.113.1', probes(['/a', '/b']))
        b = actor('203.0.113.2', probes(['/x', '/y']))
        self.assertEqual(self.run_graph([a, b]).campaigns, [])
        self.assertEqual(cosine_similarity(a.get_behavioral_vector(), b.get_behavioral_vector()), 0)

    def test_time_separation_prevents_group(self):
        a = actor('203.0.113.1', probes(['/a', '/b']))
        b = actor('203.0.113.2', probes(['/a', '/b']), start=7200)
        self.assertEqual(self.run_graph([a, b]).campaigns, [])

    def test_normal_visitors_and_allowlist_not_correlated(self):
        a = actor('203.0.113.1', ['/', '/products'], status=200)
        b = actor('203.0.113.2', ['/', '/products'], status=200)
        self.assertEqual(self.run_graph([a, b]).campaigns, [])
        a, b = actor('203.0.113.1', probes(['/a', '/b'])), actor('203.0.113.2', probes(['/a', '/b']))
        b.suppressed = True
        self.assertEqual(self.run_graph([a, b]).campaigns, [])

    def test_no_transitive_campaign_chaining(self):
        a = actor('203.0.113.1', probes(['/x', '/y', '/z']))
        b = actor('203.0.113.2', probes(['/x', '/y', '/z', '/w']))
        c = actor('203.0.113.3', probes(['/y', '/z', '/w']))
        context = self.run_graph([c, a, b], replace(DetectionConfig(), correlation_similarity=0.8))
        self.assertEqual(len(context.campaigns), 1)
        self.assertEqual([a.ip_address for a in context.campaigns[0].actors], ['203.0.113.1', '203.0.113.2'])

    def test_order_invariance(self):
        def group(order):
            actors = [actor(f'203.0.113.{i}', probes(['/a', '/b'])) for i in order]
            return self.run_graph(actors).campaigns[0].campaign_id
        self.assertEqual(group([1, 2, 3]), group([3, 1, 2]))

    def test_disabled_and_pair_limits(self):
        actors = [actor(f'203.0.113.{i}', probes(['/a', '/b'])) for i in (1, 2, 3)]
        self.assertEqual(self.run_graph(actors, replace(DetectionConfig(), correlation_enabled=False)).campaigns, [])
        for limits in (LimitsConfig(max_candidate_pairs=1), LimitsConfig(max_pair_evaluations=1)):
            with self.assertRaises(LimitExceeded):
                self.run_graph(actors, limits=limits)

    def test_group_size_limit(self):
        actors = [actor(f'203.0.113.{i}', probes(['/a', '/b'])) for i in (1, 2, 3, 4)]
        context = self.run_graph(actors, replace(DetectionConfig(), correlation_max_cluster_size=2))
        self.assertEqual([len(c.actors) for c in context.campaigns], [2, 2])
