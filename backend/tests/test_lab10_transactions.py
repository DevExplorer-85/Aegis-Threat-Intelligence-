import copy
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.lab10_transactions import (
    InsufficientFundsError,
    InsufficientStockError,
    _run_transaction,
    reserve_inventory,
    transfer,
)


class FakeClient:
    def __init__(self):
        self.collections = {}

    def start_session(self):
        return FakeSession(self)


class FakeSession:
    def __init__(self, client):
        self.client = client

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def start_transaction(self):
        return FakeTransaction(self.client)


class FakeTransaction:
    def __init__(self, client):
        self.client = client
        self.snapshot = None

    def __enter__(self):
        self.snapshot = copy.deepcopy(self.client.collections)
        return self

    def __exit__(self, exc_type, _exc, _traceback):
        if exc_type is not None:
            for name, documents in self.snapshot.items():
                self.client.collections[name][:] = documents
        return False


class FakeDatabase:
    def __init__(self, client):
        self.client = client


class FakeCollection:
    def __init__(self, client, name, documents=None):
        self.database = FakeDatabase(client)
        self.name = name
        self.documents = documents if documents is not None else []
        client.collections[name] = self.documents

    def find_one(self, query, session=None):
        for document in self.documents:
            if all(document.get(key) == value for key, value in query.items()):
                return document
        return None

    def update_one(self, query, update, session=None):
        for document in self.documents:
            if any(
                document.get(key) != value
                for key, value in query.items()
                if not isinstance(value, dict)
            ):
                continue
            if any(
                document.get(key, 0) < condition["$gte"]
                for key, condition in query.items()
                if isinstance(condition, dict) and "$gte" in condition
            ):
                continue
            for key, amount in update["$inc"].items():
                document[key] = document.get(key, 0) + amount
            return SimpleNamespace(matched_count=1)
        return SimpleNamespace(matched_count=0)

    def insert_one(self, document, session=None):
        self.documents.append(document.copy())


class Lab10TransactionTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()

    def test_transfer_updates_both_accounts_and_inserts_history(self):
        accounts = FakeCollection(
            self.client,
            "accounts",
            [
                {"account_id": "source", "balance": 20, "version": 0},
                {"account_id": "destination", "balance": 10, "version": 0},
            ],
        )
        history = FakeCollection(self.client, "history")

        transfer_id = transfer(accounts, history, "source", "destination", 7)

        self.assertEqual(accounts.find_one({"account_id": "source"})["balance"], 13)
        self.assertEqual(
            accounts.find_one({"account_id": "destination"})["balance"], 17
        )
        self.assertEqual(len(history.documents), 1)
        self.assertEqual(history.documents[0]["_id"], transfer_id)

    def test_insufficient_funds_rolls_back_and_does_not_add_history(self):
        accounts = FakeCollection(
            self.client,
            "accounts",
            [
                {"account_id": "source", "balance": 5, "version": 0},
                {"account_id": "destination", "balance": 10, "version": 0},
            ],
        )
        history = FakeCollection(self.client, "history")

        with self.assertRaises(InsufficientFundsError):
            transfer(accounts, history, "source", "destination", 6)

        self.assertEqual(accounts.find_one({"account_id": "source"})["balance"], 5)
        self.assertEqual(
            accounts.find_one({"account_id": "destination"})["balance"], 10
        )
        self.assertEqual(history.documents, [])

    def test_retry_uses_exponential_backoff_for_transient_transaction_errors(self):
        from pymongo.errors import PyMongoError

        delays = []
        calls = 0

        def operation(_session):
            nonlocal calls
            calls += 1
            if calls < 3:
                raise PyMongoError(
                    "temporary write conflict",
                    error_labels=["TransientTransactionError"],
                )
            return "committed"

        with patch("scripts.lab10_transactions.random.uniform", return_value=1.0):
            result = _run_transaction(
                self.client,
                operation,
                max_attempts=3,
                backoff_base=0.1,
                sleep=delays.append,
            )

        self.assertEqual(result, "committed")
        self.assertEqual(calls, 3)
        self.assertEqual(delays, [0.1, 0.2])

    def test_unavailable_item_rolls_back_prior_stock_decrements(self):
        inventory = FakeCollection(
            self.client,
            "inventory",
            [
                {"product_id": "available", "stock": 3, "version": 0},
                {"product_id": "empty", "stock": 0, "version": 0},
            ],
        )
        orders = FakeCollection(self.client, "orders")

        with self.assertRaises(InsufficientStockError):
            reserve_inventory(
                inventory,
                orders,
                "order-1",
                "customer-1",
                [
                    {"product_id": "available", "qty": 1, "price": 2.0},
                    {"product_id": "empty", "qty": 1, "price": 3.0},
                ],
            )

        self.assertEqual(
            inventory.find_one({"product_id": "available"})["stock"], 3
        )
        self.assertEqual(orders.documents, [])

    def test_reservation_decrements_stock_and_creates_pending_order(self):
        inventory = FakeCollection(
            self.client,
            "inventory",
            [{"product_id": "item-1", "stock": 4, "version": 0}],
        )
        orders = FakeCollection(self.client, "orders")

        order = reserve_inventory(
            inventory,
            orders,
            "order-2",
            "customer-2",
            [{"product_id": "item-1", "qty": 2, "price": 4.5}],
        )

        self.assertEqual(inventory.find_one({"product_id": "item-1"})["stock"], 2)
        self.assertEqual(orders.documents, [order])
        self.assertEqual(order["status"], "pending")
        self.assertEqual(order["total"], 9.0)


if __name__ == "__main__":
    unittest.main()
