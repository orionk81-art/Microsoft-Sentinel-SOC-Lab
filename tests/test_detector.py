import unittest
from soc_detector import detect


def ev(time, event_id, account='test', ip='192.0.2.1', logon_type=3):
    return {'time': f'2026-11-20T{time}Z', 'event_id': event_id,
            'account': account, 'source_ip': ip, 'logon_type': logon_type}


class DetectionTests(unittest.TestCase):
    def test_five_failures_and_success(self):
        events = [ev(f'12:0{i}:00', 4625) for i in range(5)] + [ev('12:04:30', 4624)]
        self.assertEqual({f['rule'] for f in detect(events)},
                         {'BRUTE_FORCE_PATTERN', 'FAILURES_THEN_SUCCESS'})

    def test_failures_outside_window(self):
        events = [ev(f'12:{i*6:02d}:00', 4625) for i in range(5)]
        self.assertEqual(detect(events), [])

    def test_rdp_success(self):
        findings = detect([ev('12:00:00', 4624, logon_type=10)])
        self.assertEqual([f['rule'] for f in findings], ['RDP_LOGON_REVIEW'])

    def test_accounts_and_sources_not_mixed(self):
        events = [ev(f'12:0{i}:00', 4625, ip='192.0.2.1' if i % 2 else '192.0.2.2') for i in range(5)]
        self.assertEqual(detect(events), [])

    def test_timezone_required(self):
        with self.assertRaises(ValueError):
            detect([{'time':'2026-11-20T12:00:00','event_id':4624}])


if __name__ == '__main__':
    unittest.main()
