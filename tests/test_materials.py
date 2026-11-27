"""校对资料的编码、记录和引用。"""
import unittest

from materials import catalog, read_collection


class MaterialTests(unittest.TestCase):
    def test_catalog_matches_records_and_references(self):
        tables = {name: read_collection(name) for name in catalog()}
        indexes = {name: {row["id"] for row in rows} for name, rows in tables.items()}
        for name, spec in catalog().items():
            with self.subTest(collection=name):
                rows = tables[name]
                self.assertTrue(rows)
                self.assertEqual(len(indexes[name]), len(rows))
                for row in rows:
                    self.assertEqual(set(row), set(spec["fields"]))
                    self.assertIsInstance(row["id"], str)
                    self.assertTrue(row["id"])
                    for field, target in spec["references"].items():
                        self.assertIn(row[field], indexes[target])

    def test_unknown_collection_is_refused(self):
        with self.assertRaises(KeyError):
            read_collection("../README")


if __name__ == "__main__":
    unittest.main()
