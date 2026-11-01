import os
import unittest
import tempfile
from backend.app.services.file_analyzer import (
    calculate_hashes, calculate_entropy, extract_strings, perform_static_analysis
)

class TestFileAnalyzer(unittest.TestCase):
    def setUp(self):
        self.test_content = b"MZ\x90\x00\x03\x00\x00\x00http://malicious-command-control.onion/beacon\x00cmd.exe /c powershell -enc\x00192.168.1.100"
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.write(self.test_content)
        self.tmp.close()

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.remove(self.tmp.name)

    def test_calculate_hashes(self):
        sha256, md5 = calculate_hashes(self.tmp.name)
        self.assertEqual(len(sha256), 64)
        self.assertEqual(len(md5), 32)

    def test_calculate_entropy(self):
        entropy = calculate_entropy(self.test_content)
        self.assertGreaterEqual(entropy, 0.0)
        self.assertLessEqual(entropy, 8.0)

    def test_extract_strings(self):
        urls, ips, sus = extract_strings(self.tmp.name)
        self.assertTrue(any("onion" in u or "malicious" in u for u in urls))
        self.assertTrue("powershell" in sus or "cmd.exe" in sus)

    def test_perform_static_analysis(self):
        res = perform_static_analysis(self.tmp.name, scan_mode="standard")
        self.assertIn("file_name", res)
        self.assertIn("sha256", res)
        self.assertIn("entropy", res)
        self.assertIn("is_pe", res)

if __name__ == "__main__":
    unittest.main()
