import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

import app.lab_api as lab_api
from app.lab_api import get_cluster, get_sharding_cluster, get_transaction_cluster


class FakeAdmin:
    def command(self, name):
        responses = {
            "ping": {"ok": 1},
            "hello": {"me": "mongo1:27017"},
            "buildInfo": {"version": "7.0.0"},
        }
        return responses[name]


class FakeMongoClient:
    admin = FakeAdmin()

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeTransactionAdmin:
    def command(self, name):
        if name != "hello":
            raise AssertionError(f"Unexpected MongoDB command: {name}")
        return {"setName": "rs0", "isWritablePrimary": True}


class FakeShardingAdmin:
    def command(self, name):
        if name == "hello":
            return {"msg": "isdbgrid"}
        if name == "listShards":
            return {
                "shards": [
                    {"_id": "shard11aRS", "host": "shard11aRS/shard11a:27018"},
                    {"_id": "shard11bRS", "host": "shard11bRS/shard11b:27018"},
                ]
            }
        raise AssertionError(f"Unexpected MongoDB command: {name}")


class FakeTransactionMongoClient:
    admin = FakeTransactionAdmin()

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeShardingMongoClient:
    admin = FakeShardingAdmin()

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeProcess:
    def poll(self):
        return None


class LabClusterApiTests(unittest.TestCase):
    @patch("app.lab_api.MongoClient", FakeMongoClient)
    def test_reports_one_standalone_mongodb_server(self):
        result = get_cluster()

        self.assertEqual(result["deployment"], "standalone")
        self.assertTrue(result["connected"])
        self.assertEqual(len(result["members"]), 1)
        self.assertEqual(result["members"][0]["state"], "STANDALONE")
        self.assertEqual(result["members"][0]["name"], "mongo1:27017")
        self.assertNotIn("replica_set", result)

    @patch("app.lab_api.MongoClient", side_effect=RuntimeError("mongodb://user:secret@host"))
    def test_database_error_does_not_expose_connection_details(self, _client):
        result = get_cluster()

        self.assertFalse(result["connected"])
        self.assertNotIn("secret", result["error"])
        self.assertIn("RuntimeError", result["error"])

    @patch.object(lab_api, "MONGO_URI_CH10", None)
    def test_transaction_cluster_reports_missing_configuration(self):
        result = get_transaction_cluster()

        self.assertFalse(result["configured"])
        self.assertFalse(result["connected"])
        self.assertIn("MONGO_URI_CH10", result["error"])

    @patch.object(lab_api, "MONGO_URI_CH10", "mongodb://mongo10:27017/?replicaSet=rs0")
    @patch("app.lab_api.MongoClient", FakeTransactionMongoClient)
    def test_transaction_cluster_reports_replica_set_primary(self):
        result = get_transaction_cluster()

        self.assertTrue(result["configured"])
        self.assertTrue(result["connected"])
        self.assertEqual(result["replica_set"], "rs0")
        self.assertTrue(result["primary"])

    @patch.object(lab_api, "MONGO_URI_CH11", None)
    def test_sharding_cluster_reports_missing_configuration(self):
        result = get_sharding_cluster()

        self.assertFalse(result["configured"])
        self.assertFalse(result["connected"])
        self.assertIn("MONGO_URI_CH11", result["error"])

    @patch.object(lab_api, "MONGO_URI_CH11", "mongodb://mongos:27017")
    @patch("app.lab_api.MongoClient", FakeShardingMongoClient)
    def test_sharding_cluster_reports_router_and_shards(self):
        result = get_sharding_cluster()

        self.assertTrue(result["connected"])
        self.assertTrue(result["router"])
        self.assertEqual(len(result["shards"]), 2)

    @patch.object(lab_api, "MONGO_URI_CH10", None)
    def test_transaction_job_requires_replica_set_configuration(self):
        with self.assertRaises(HTTPException) as raised:
            lab_api.start_job(lab_api.JobRequest(lab="10.1"))

        self.assertEqual(raised.exception.status_code, 503)

    @patch.object(lab_api, "MONGO_URI_CH10", "mongodb://mongo10:27017/?replicaSet=rs0")
    def test_transaction_job_uses_dedicated_replica_set_uri(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            with (
                patch.object(lab_api, "OUTPUT_DIR", temporary_path),
                patch.object(lab_api, "JOBS_DIR", temporary_path),
                patch("app.lab_api.subprocess.Popen", return_value=FakeProcess()) as popen,
                patch.dict(os.environ, {"MONGO_URI": "mongodb://mongo1:27017"}),
            ):
                result = lab_api.start_job(lab_api.JobRequest(lab="10.2"))

        self.assertEqual(result["lab"], "10.2")
        self.assertEqual(
            popen.call_args.kwargs["env"]["MONGO_URI"],
            "mongodb://mongo10:27017/?replicaSet=rs0",
        )
        lab_api._jobs.clear()

    @patch.object(lab_api, "MONGO_URI_CH11", None)
    def test_live_sharding_job_requires_router_configuration(self):
        with self.assertRaises(HTTPException) as raised:
            lab_api.start_job(lab_api.JobRequest(lab="11.2"))

        self.assertEqual(raised.exception.status_code, 503)

    @patch.object(lab_api, "MONGO_URI_CH11", "mongodb://mongos:27017/?retryWrites=false")
    def test_live_sharding_job_uses_mongos_uri(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            with (
                patch.object(lab_api, "OUTPUT_DIR", temporary_path),
                patch.object(lab_api, "JOBS_DIR", temporary_path),
                patch("app.lab_api.subprocess.Popen", return_value=FakeProcess()) as popen,
                patch.dict(os.environ, {"MONGO_URI": "mongodb://mongo1:27017"}),
            ):
                result = lab_api.start_job(lab_api.JobRequest(lab="11.2"))

        self.assertEqual(result["lab"], "11.2")
        self.assertEqual(
            popen.call_args.kwargs["env"]["MONGO_URI"],
            "mongodb://mongos:27017/?retryWrites=false",
        )
        lab_api._jobs.clear()


if __name__ == "__main__":
    unittest.main()
