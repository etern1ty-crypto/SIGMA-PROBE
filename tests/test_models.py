import unittest
from datetime import datetime

from sigma_probe.models.core import ActorProfile, Evidence, LogEvent, ThreatCampaign
from sigma_probe.pipeline.enrichment import decoded_variants, normalized_path
from sigma_probe.validation import SigmaProbeError
from tests.helpers import BASE, actor, event


class ModelTests(unittest.TestCase):
    def test_ip_and_http_validation(self):
        for changes in ({'source_ip': 'not-ip'}, {'source_ip': 'fe80::1%eth0'}, {'status_code': 999}, {'status_code': True}, {'response_size': -1}, {'method': 'GET\nInjected'}, {'url': ''}):
            with self.subTest(changes=changes), self.assertRaises(SigmaProbeError):
                values = dict(timestamp=BASE, source_ip='203.0.113.1', method='GET', url='/', status_code=200)
                values.update(changes)
                LogEvent(**values)

    def test_timezone_required(self):
        with self.assertRaises(SigmaProbeError):
            LogEvent(timestamp=datetime(2026, 1, 1), source_ip='203.0.113.1', method='GET', url='/', status_code=200)

    def test_ipv6_normalization(self):
        self.assertEqual(event(ip='2001:0db8:0:0::1').source_ip, '2001:db8::1')

    def test_incremental_metrics(self):
        a = actor('203.0.113.1', ['/a', '/b', '/a'])
        self.assertEqual((a.total_requests, a.unique_urls), (3, 2))
        self.assertEqual(a.path_counts['/a'], 2)
        self.assertEqual(a.first_seen, BASE)
        self.assertAlmostEqual(sum(a.get_behavioral_vector().values()), 1)

    def test_different_paths_have_different_coordinates(self):
        a, b = actor('203.0.113.1', ['/a']), actor('203.0.113.2', ['/b'])
        self.assertNotEqual(a.get_behavioral_vector(), b.get_behavioral_vector())

    def test_campaign_average_uses_objects(self):
        a, b = actor('203.0.113.1', ['/a']), actor('203.0.113.2', ['/b'])
        a.threat_score, b.threat_score = 80, 60
        campaign = ThreatCampaign('group-test', [a, b])
        campaign.update_metrics()
        self.assertEqual(campaign.threat_score, 70)

    def test_evidence_idempotent(self):
        a = ActorProfile('203.0.113.1')
        a.add_evidence(Evidence('test', 'test', 'First'))
        a.add_evidence(Evidence('test', 'test', 'Second'))
        self.assertEqual(len(a.evidence_trail), 1)
        self.assertEqual(a.evidence_trail[0].details, 'Second')
        with self.assertRaises(SigmaProbeError):
            Evidence('test', 'test', 'Invalid', confidence=float('nan'))

    def test_enrichment_required_and_ip_isolated(self):
        a = ActorProfile('203.0.113.1')
        with self.assertRaises(SigmaProbeError):
            a.add_event(LogEvent(BASE, '203.0.113.1', '/', 'GET', 200))
        with self.assertRaises(SigmaProbeError):
            a.add_event(event(ip='203.0.113.2'))


class SignatureTests(unittest.TestCase):
    def test_encoded_and_double_encoded_traversal(self):
        for target in ('/read?f=../../etc/passwd', '/read?f=%2e%2e%2fetc%2fpasswd', '/read?f=%252e%252e%252fetc%252fpasswd', '/read?f=..\\etc\\passwd'):
            with self.subTest(target=target):
                self.assertIn('LFI_RFI', event(target).heuristic_flags)

    def test_sql_xss_and_command(self):
        for target, tag in (('/?id=1%20UNION%20SELECT%20x', 'SQL_INJECTION'), ('/?q=%3Cscript%3Ealert(1)%3C/script%3E', 'XSS'), ('/?q=%3Cimg+src=x+onerror=alert(1)%3E', 'XSS'), ('/?cmd=cat+/etc/passwd', 'COMMAND_INJECTION')):
            with self.subTest(tag=tag):
                self.assertIn(tag, event(target).heuristic_flags)

    def test_benign_urls_are_not_inherently_malicious(self):
        for target in ('/login.php', '/redirect?next=http://example.test/', '/api?option=value', '/search?onboarding=yes', '/assets/app.py', '/?nonce=abcdef1234567890', '/admin', '/health'):
            with self.subTest(target=target):
                self.assertEqual(event(target, agent='curl/8.0').heuristic_flags, set())

    def test_normal_googlebot_is_not_an_attack(self):
        self.assertEqual(event('/', agent='Googlebot/2.1').heuristic_flags, set())

    def test_scanner_agent_is_specific(self):
        self.assertEqual(event('/', agent='sqlmap/1.0').heuristic_flags, {'SCANNER_UA'})

    def test_sensitive_paths_with_boundaries(self):
        for target in ('/.env', '/.git/config', '/wp-config.php.bak'):
            self.assertIn('SENSITIVE_PATH', event(target).heuristic_flags)
        self.assertNotIn('SENSITIVE_PATH', event('/.environment').heuristic_flags)

    def test_query_plus_not_path_plus(self):
        self.assertEqual(decoded_variants('/a+b?q=a+b')[-1], '/a+b?q=a b')

    def test_absolute_url_and_double_slash_paths(self):
        self.assertEqual(normalized_path('https://example.test/a?q=1'), '/a')
        self.assertEqual(normalized_path('//a/b?q=1'), '//a/b')

    def test_signature_enrichment_idempotent(self):
        from sigma_probe.pipeline.enrichment import EnrichmentStage
        e = event('/?f=../etc/passwd')
        before = e.heuristic_flags.copy()
        EnrichmentStage().process(e)
        self.assertEqual(e.heuristic_flags, before)
