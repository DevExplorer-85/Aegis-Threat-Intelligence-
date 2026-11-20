import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.lab11_sharding import (
    _explain,
    _per_shard_counts,
    evaluate_shard_keys,
    simulate_hotspot_distribution,
)


class FakeDatabase:
    def command(self, command, collection_name, **kwargs):
        if command == "collStats":
            return {
                "shards": {
                    "shardA": {"count": 10, "size": 1000},
                    "shardB": {"count": 12, "size": 1200},
                }
            }
        if command == "explain":
            return {
                "queryPlanner": {
                    "winningPlan": {
                        "stage": "SHARD_MERGE",
                        "shards": [
                            {"shardName": "shardA", "winningPlan": {"stage": "IXSCAN"}},
                            {"shardName": "shardB", "winningPlan": {"stage": "IXSCAN"}},
                        ],
                    }
                },
                "executionStats": {
                    "nReturned": 4,
                    "totalDocsExamined": 4,
                },
            }
        raise AssertionError(f"Unexpected command: {command}")


class Lab11ShardingTests(unittest.TestCase):
    def test_decision_matrix_covers_shard_key_properties_and_resharding(self):
        result = evaluate_shard_keys()

        self.assertEqual(
            [row["candidate"] for row in result["decision_matrix"]],
            [
                "user_id / customer_id (hashed)",
                "order_id (hashed)",
                "category_id",
                "created_at (range)",
                "order_id (range)",
                "customer_id (range)",
                "order_date (range)",
            ],
        )
        self.assertEqual(
            [concept["property"] for concept in result["concepts"]],
            ["Cardinality", "Distribution", "Query targeting", "Monotonicity"],
        )
        self.assertIn("Recommended", result["decision_matrix"][0]["verdict"])
        self.assertIn("Monotonically increasing", result["decision_matrix"][3]["monotonicity"])
        self.assertIn("Avoid", result["decision_matrix"][3]["verdict"])
        self.assertTrue(result["resharding"]["steps"])
        self.assertTrue(result["resharding"]["limitations"])

    def test_hotspot_distribution_simulation_is_deterministic(self):
        result = simulate_hotspot_distribution(document_count=10_000, shard_count=5)

        monotonic_counts = [
            row["documents"] for row in result["monotonic_range_key"]["shard_counts"]
        ]
        self.assertEqual(monotonic_counts, [0, 0, 0, 0, 10_000])
        hashed_counts = [
            row["documents"] for row in result["hashed_same_timestamp_key"]["shard_counts"]
        ]
        self.assertEqual(sum(hashed_counts), 10_000)
        self.assertLess(max(hashed_counts), 2_300)
        self.assertGreater(min(hashed_counts), 1_700)
        self.assertIn("same monotonically increasing timestamp", result["candidate_key"])
        self.assertTrue(result["simulated"])

    def test_hotspot_simulation_rejects_invalid_dimensions(self):
        with self.assertRaises(ValueError):
            simulate_hotspot_distribution(document_count=0)
        with self.assertRaises(ValueError):
            simulate_hotspot_distribution(shard_count=1)

    def test_per_shard_counts_and_explain_targets_are_extracted(self):
        database = FakeDatabase()

        counts = _per_shard_counts(database, "orders")
        explain = _explain(database, "orders", {"customer_id": "customer-1"}, 2)

        self.assertEqual([row["shard"] for row in counts], ["shardA", "shardB"])
        self.assertEqual(explain["targeted_shards"], ["shardA", "shardB"])
        self.assertEqual(explain["targeted_shard_count"], 2)
        self.assertEqual(explain["total_shard_count"], 2)


if __name__ == "__main__":
    unittest.main()
