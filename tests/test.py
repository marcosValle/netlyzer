import unittest

from netlyzer.main import *

class TestCfg(unittest.TestCase):

    def test_load(self):
        self.assertEqual(getApiKey('vt'), "<YOUR VT KEY>", "VT API Key mismatch")
        self.assertEqual(getApiKey('abuseIPDBKey'), "<YOUR ABUSEIPDB KEY>", "Abuse IP DB API Key mismatch")

    def test_checkDomains(self):
        self.assertEqual(checkDomains(["https://www.google.com"])[0]['response_code'],1,"Could not check VT")

if __name__ == '__main__':
    unittest.main()
