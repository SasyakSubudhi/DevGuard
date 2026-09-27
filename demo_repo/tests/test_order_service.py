import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from order_service import summarize_order


class OrderServiceTests(unittest.TestCase):
    def test_summarizes_priced_items(self):
        result = summarize_order("ORDER-1", [{"price": 10}, {"price": 20}])
        self.assertEqual(result["item_count"], 2)
        self.assertEqual(result["average_price"], 15.0)

    def test_empty_order_has_zero_average(self):
        result = summarize_order("ORDER-2", [])
        self.assertEqual(result["item_count"], 0)
        self.assertEqual(result["average_price"], 0.0)


if __name__ == "__main__":
    unittest.main()
