import unittest

from netlyzer.main import *

class TestCfg(unittest.TestCase):

    def test_load(self):
        self.assertEqual(getApiKey('vt'), "eae964a0e83abf0f8c07d06f67b3596de2c34e2ee7110d1446f870e56bf91c7a", "VT API Key mismatch")
        self.assertEqual(getApiKey('abuseIPDBKey'), "69591cf1e43d685e893f35625dcf482481983315057d542edec2239c89b1bd36d7149ba091c316d1", "Abuse IP DB API Key mismatch")

    def test_checkDomains(self):
        self.assertEqual(checkDomains(["https://www.google.com"])[0]['response_code'],1,"Could not check VT")

if __name__ == '__main__':
    unittest.main()
