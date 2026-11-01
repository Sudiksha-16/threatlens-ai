import os
import unittest
import tempfile
from backend.app.services.yara_engine import yara_engine

class TestYaraEngine(unittest.TestCase):
    def test_rules_loaded(self):
        self.assertIsNotNone(yara_engine.rules)

    def test_ransomware_shadowcopy_rule(self):
        # Trigger Ransomware_Vssadmin_ShadowCopy rule
        payload = b"test header text vssadmin delete shadows /all /quiet test padding"
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(payload)
        tmp.close()

        try:
            matches = yara_engine.scan_file(tmp.name)
            rule_names = [m["rule_name"] for m in matches]
            self.assertIn("Ransomware_Vssadmin_ShadowCopy", rule_names)
            match_entry = next(m for m in matches if m["rule_name"] == "Ransomware_Vssadmin_ShadowCopy")
            self.assertEqual(match_entry["category"], "Ransomware")
            self.assertEqual(match_entry["severity"], "Critical")
        finally:
            if os.path.exists(tmp.name):
                os.remove(tmp.name)

    def test_clean_file_no_matches(self):
        payload = b"This is a completely normal text document with harmless content."
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(payload)
        tmp.close()

        try:
            matches = yara_engine.scan_file(tmp.name)
            self.assertEqual(len(matches), 0)
        finally:
            if os.path.exists(tmp.name):
                os.remove(tmp.name)

if __name__ == "__main__":
    unittest.main()
