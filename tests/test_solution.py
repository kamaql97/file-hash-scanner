import unittest
import sys
import os.path

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from solution.scanner import FileScanner
from solution.exceptions import InvalidFileHashError


class TestValidation(unittest.TestCase):
    def test_valid_md5(self):
        try:
            FileScanner('4371a61227f8b7a4536e91aeff4f9af9')
        except InvalidFileHashError:
            self.fail('Wrongly raised exception for valid MD5')

    def test_valid_sha1(self):
        try:
            FileScanner('6E0B782A9B06834290B24C91C80B12D7AD3C3133')
        except InvalidFileHashError:
            self.fail('Wrongly raised exception for valid SHA1')

    def test_valid_sha256(self):
        try:
            FileScanner('E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855')
        except InvalidFileHashError:
            self.fail('Wrongly raised exception for valid SHA256')

    def test_no_args(self):
        self.assertRaises(InvalidFileHashError, FileScanner)

    def test_invalid_hash(self):
        self.assertRaises(InvalidFileHashError, FileScanner, 'randomstring123456789')


if __name__ == '__main__':
    unittest.main()
