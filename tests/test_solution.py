import unittest
import sys
import os.path

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from solution.scanner import FileScanner


class TestValidation(unittest.TestCase):
    pass
    # def test_sum(self):
    #     self.assertEqual(sum([1, 2, 3]), 6, "Should be 6")

    # def test_sum_tuple(self):
    #     self.assertEqual(sum((1, 2, 2)), 6, "Should be 6")


class TestRequestErrors(unittest.TestCase):
    pass

if __name__ == '__main__':
    unittest.main()