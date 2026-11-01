import unittest
from backend.app.services.risk_engine import risk_engine

class TestRiskEngine(unittest.TestCase):
    def test_benign_low_risk(self):
        static_info = {"entropy": 4.5, "obfuscation_indicators": [], "imported_apis": [], "suspicious_strings": []}
        yara_matches = []
        ml_pred = {
            "is_malicious": False,
            "classification": "Benign",
            "model_name": "Random_Forest",
            "class_probabilities": {"Benign": 0.99, "Malicious": 0.01}
        }
        res = risk_engine.calculate_risk(static_info, yara_matches, ml_pred)
        self.assertLessEqual(res["risk_score"], 25)
        self.assertEqual(res["risk_level"], "Low")
        self.assertGreater(len(res["recommended_actions"]), 0)

    def test_critical_risk_with_yara_and_ml(self):
        static_info = {
            "entropy": 7.8,
            "obfuscation_indicators": ["Section UPX0 packed"],
            "imported_apis": ["VirtualAlloc [Process Injection]"],
            "suspicious_strings": ["vssadmin"]
        }
        yara_matches = [{
            "rule_name": "Ransomware_Vssadmin_ShadowCopy",
            "category": "Ransomware",
            "severity": "Critical",
            "description": "Shadow copy wiper"
        }]
        ml_pred = {
            "is_malicious": True,
            "classification": "Malicious",
            "model_name": "Random_Forest",
            "class_probabilities": {"Benign": 0.02, "Malicious": 0.98}
        }
        res = risk_engine.calculate_risk(static_info, yara_matches, ml_pred)
        self.assertGreaterEqual(res["risk_score"], 80)
        self.assertEqual(res["risk_level"], "Critical")
        self.assertTrue(any("Critical" in r for r in res["reasons"]))

if __name__ == "__main__":
    unittest.main()
