"""Run with: python -m unittest"""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from scan_delivery import RetryLater, deliver_scan, scan_to_report

SCAN_DOC = {
    '_id': 'abc123',
    'client_ip': '10.0.0.7',
    'status': 'received',
    'scan': {
        'hostname': 'ws-01',
        'os': 'Linux',
        'os_version': '6.8.0',
        'cpu_cores': 4,
        'memory_kb': 8000000,
        'interfaces': [
            {'name': 'lo', 'ip': '127.0.0.1'},
            {'name': 'eth0', 'ip': '10.0.0.7', 'mac': '02:42:0a:00:00:07'},
        ],
        'timestamp': '2026-10-13T19:00:00Z',
        'checksum': 'ignored',
    },
}


class ScanToReport(unittest.TestCase):
    def test_a_stored_scan_becomes_a_gateway_report(self):
        self.assertEqual(scan_to_report(SCAN_DOC), {
            'hostname': 'ws-01',
            'os': 'Linux',
            'os_version': '6.8.0',
            'cpu_cores': 4,
            'memory_kb': 8000000,
            'interfaces': [
                {'name': 'lo', 'ip_address': '127.0.0.1', 'mac_address': None},
                {'name': 'eth0', 'ip_address': '10.0.0.7', 'mac_address': '02:42:0a:00:00:07'},
            ],
            'timestamp': '2026-10-13T19:00:00Z',
            'reported_from': '10.0.0.7',
            'scan_id': 'abc123',
        })

    def test_a_document_that_is_not_a_scan_is_refused(self):
        for doc in ({}, {'scan': 'SCAN {...}'}, {'scan': {'hostname': 'ws-01', 'os': 'Linux'}}):
            with self.assertRaises(ValueError):
                scan_to_report(doc)


class Gateway(BaseHTTPRequestHandler):
    status = 200
    received = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        Gateway.received.append((self.path, self.headers['X-Internal-Token'], body))
        self.send_response(Gateway.status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'asset_id': 'a1', 'new_device': True}).encode())

    def log_message(self, *args):
        pass


class DeliverScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), Gateway)
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        Gateway.status = 200
        Gateway.received.clear()

    def test_the_report_is_posted_with_the_internal_token(self):
        report = scan_to_report(SCAN_DOC)
        self.assertEqual(deliver_scan(report, self.url, 'secret'), {'asset_id': 'a1', 'new_device': True})
        self.assertEqual(Gateway.received, [('/api/v1/scans/', 'secret', report)])

    def test_a_scan_the_gateway_rejects_is_not_retried(self):
        Gateway.status = 422
        with self.assertRaises(ValueError):
            deliver_scan(scan_to_report(SCAN_DOC), self.url, 'secret')

    def test_a_gateway_that_cannot_answer_now_is_retried(self):
        for status in (401, 503):
            Gateway.status = status
            with self.assertRaises(RetryLater):
                deliver_scan(scan_to_report(SCAN_DOC), self.url, 'secret')

    def test_an_unreachable_gateway_is_retried(self):
        with self.assertRaises(RetryLater):
            deliver_scan(scan_to_report(SCAN_DOC), 'http://127.0.0.1:1', 'secret', timeout=2)


if __name__ == '__main__':
    unittest.main()
