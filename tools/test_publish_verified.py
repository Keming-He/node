import base64
import json
import unittest
import urllib.parse
import yaml

from publish_verified import make_failure_files, make_files, prepare_proxy, share_uri


class SubscriptionExportTests(unittest.TestCase):
    def test_hy2_credentials_and_certificate_settings_survive_uri_encoding(self):
        p = prepare_proxy({"name": "香港 测试", "type": "hysteria2", "server": "2001:db8::1",
                           "port": 8443, "password": "a:b/@ ?&", "sni": "example.com",
                           "obfs": "salamander", "obfs-password": "x&y=z", "skip-cert-verify": True})
        uri = urllib.parse.urlsplit(share_uri(p))
        self.assertEqual(urllib.parse.unquote(uri.username), "a:b/@ ?&")
        self.assertEqual(uri.hostname, "2001:db8::1")
        self.assertEqual(uri.port, 8443)
        self.assertEqual(urllib.parse.unquote(uri.fragment), "香港 测试")
        self.assertEqual(urllib.parse.parse_qs(uri.query),
                         {"sni": ["example.com"], "insecure": ["0"],
                          "obfs": ["salamander"], "obfs-password": ["x&y=z"]})
        self.assertFalse(p["skip-cert-verify"])

    def test_ss_password_is_not_split_or_lost(self):
        uri = urllib.parse.urlsplit(share_uri({"name": "SS", "type": "ss", "server": "example.com",
                                               "port": 443, "cipher": "aes-256-gcm", "password": "x:y/@"}))
        encoded = uri.username
        self.assertEqual(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode(),
                         "aes-256-gcm:x:y/@")

    def test_failed_nodes_are_absent_from_both_outputs_with_matching_order(self):
        proxies = [{"name": name, "type": "hysteria2", "server": "example.com", "port": 443,
                    "password": "test", "skip-cert-verify": False} for name in ["slow", "dead", "fast"]]
        records = [{"name": "slow", "passed": True, "median_ms": 500},
                   {"name": "dead", "passed": False, "median_ms": None},
                   {"name": "fast", "passed": True, "median_ms": 100}]
        result = make_files(proxies, records, {})
        clash = yaml.safe_load(result["verified-clash.yaml"]["content"])["proxies"]
        uris = base64.b64decode(result["shadowrocket.txt"]["content"]).decode().splitlines()
        mobile_names = [urllib.parse.unquote(urllib.parse.urlsplit(uri).fragment) for uri in uris]
        self.assertEqual([p["name"] for p in clash], ["fast", "slow"])
        self.assertEqual(mobile_names, ["fast", "slow"])
        status = json.loads(result["verified-status.json"]["content"])
        self.assertEqual(status["status"], "ok")
        self.assertTrue(status["feeds_updated"])
        self.assertFalse(status["retained_previous_feeds"])

    def test_failure_updates_status_without_replacing_client_feeds(self):
        files = make_failure_files([], {"checked_at": "now"},
                                   {"available_count": 14, "checked_at": "last-good"})
        self.assertEqual(set(files), {"verified-status.json"})
        status = json.loads(files["verified-status.json"]["content"])
        self.assertEqual(status["available_count"], 0)
        self.assertEqual(status["status"], "unavailable")
        self.assertEqual(status["last_success_at"], "last-good")
        self.assertEqual(status["retained_node_count"], 14)
        self.assertFalse(status["feeds_updated"])

    def test_repeated_failure_preserves_original_success_time_and_retained_count(self):
        previous = {"status": "unavailable", "available_count": 0, "checked_at": "first-failure",
                    "last_success_at": "last-good", "retained_node_count": 14}
        files = make_failure_files([], {"checked_at": "next-failure"}, previous)
        status = json.loads(files["verified-status.json"]["content"])
        self.assertEqual(status["last_success_at"], "last-good")
        self.assertEqual(status["retained_node_count"], 14)
        self.assertTrue(status["retained_previous_feeds"])

    def test_zero_passes_cannot_produce_an_empty_replacement_subscription(self):
        with self.assertRaises(RuntimeError):
            make_files([], [], {})

    def test_unrepresentable_chains_and_plugins_are_rejected(self):
        for field in ["dialer-proxy", "plugin"]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                prepare_proxy({"name": "bad", "type": "ss", "server": "example.com",
                               "port": 443, "cipher": "aes-256-gcm", "password": "test", field: "value"})


if __name__ == "__main__":
    unittest.main()
