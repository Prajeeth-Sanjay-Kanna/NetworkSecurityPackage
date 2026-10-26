import unittest

from detector import detect_queries, entropy, registered_domain

class DetectorTests(unittest.TestCase):
    def test_normal_query_is_low(self):
        result = detect_queries([{"domain": "www.example.com"}])[0]
        self.assertEqual(result["severity"], "Low")
        self.assertEqual(result["risk_score"], 0)

    def test_long_query_triggers_rule(self):
        result = detect_queries([{"domain": "a" * 56 + ".example.com"}])[0]
        self.assertIn("long_query", result["triggered_rules"])

    def test_high_entropy_label_triggers_rule(self):
        result = detect_queries([{"domain": "x7q9m2z8k4p1v6n3.example.com"}])[0]
        self.assertIn("high_entropy", result["triggered_rules"])

    def test_encoded_looking_label_triggers_rule(self):
        result = detect_queries([{"domain": "abcdef0123456789abcdef.example.com"}])[0]
        self.assertIn("encoded_pattern", result["triggered_rules"])

    def test_repeated_domain_triggers_rule(self):
        rows = [{"domain": "www.example.net"} for _ in range(20)]
        results = detect_queries(rows)
        self.assertTrue(all("frequent_domain" in item["triggered_rules"] for item in results))

    def test_unique_subdomains_trigger_rule(self):
        rows = [{"domain": f"node{i}.example.net"} for i in range(15)]
        results = detect_queries(rows)
        self.assertTrue(all("many_unique_subdomains" in item["triggered_rules"] for item in results))

    def test_multiple_rules_can_trigger(self):
        result = detect_queries([{"domain": "a8f92bd71c04e6d7a21f9b8c4d2e6f80.example.com"}])[0]
        self.assertGreaterEqual(len(result["triggered_rules"]), 2)

    def test_empty_input_returns_empty(self):
        self.assertEqual(detect_queries([]), [])

    def test_score_is_bounded(self):
        result = detect_queries([{"domain": "a8f92bd71c04e6d7a21f9b8c4d2e6f80.b.c.d.e.f.example.com"}])[0]
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)

    def test_severity_assignment(self):
        self.assertEqual(detect_queries([{"domain": "www.example.com"}])[0]["severity"], "Low")
        medium = detect_queries([{"domain": "a" * 56 + ".example.com"}])[0]
        self.assertIn(medium["severity"], {"Medium", "High"})

    def test_entropy_empty(self):
        self.assertEqual(entropy(""), 0.0)

    def test_registered_domain_co_uk(self):
        self.assertEqual(registered_domain("a.b.example.co.uk"), "example.co.uk")

if __name__ == "__main__":
    unittest.main()
