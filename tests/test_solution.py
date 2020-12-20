"""
Palo Alto Networks Assignement - Kamal Qarain

Basic unit tests
"""

import unittest
import sys
import os.path

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from solution.scanner import request_data
from solution.helpers import is_valid_hash


SUCCESS_MSG = 'Scan finished, information embedded'


class TestValidation(unittest.TestCase):
    """
    Test case for testing the method that checks for valid file hash
    """
    def test_valid_md5(self):
        self.assertTrue(is_valid_hash('4371a61227f8b7a4536e91aeff4f9af9'))

    def test_valid_sha1(self):
        self.assertTrue(is_valid_hash('6E0B782A9B06834290B24C91C80B12D7AD3C3133'))

    def test_valid_sha256(self):
        self.assertTrue(is_valid_hash('E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'))

    def test_invalid_hash(self):
        self.assertFalse(is_valid_hash('randomstring123456789'))


class TestScannnerAPI(unittest.TestCase):
    """
    Test case for testing API response with a known malicious file
    """
    def test_known_file(self):
        msg, results = request_data('84c82835a5d21bbcf75a61706d8ab549')
        self.assertEqual(msg, SUCCESS_MSG, 'Known file should return result') 


if __name__ == '__main__':
    unittest.main()
