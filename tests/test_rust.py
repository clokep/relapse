from relapse.relapse_rust import sum_as_string

from tests import unittest


class RustTestCase(unittest.TestCase):
    """Basic tests to ensure that we can call into Rust code."""

    def test_basic(self) -> None:
        result = sum_as_string(1, 2)
        self.assertEqual("3", result)
