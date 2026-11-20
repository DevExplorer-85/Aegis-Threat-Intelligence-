import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

import lab


class FakeCollection:
    def __init__(self, populated=False):
        self.populated = populated

    def count_documents(self, query, limit=None):
        return int(self.populated)


class FakeDatabase:
    def list_collection_names(self):
        return ["lab_ch81_replication_check", "security_reports", "security_report_passages"]

    def __getitem__(self, name):
        return FakeCollection(populated=name == "lab_ch81_replication_check")


class FakeContainer:
    def __init__(self):
        self.command = None

    def exec_run(self, command, workdir):
        self.command = command
        return SimpleNamespace(exit_code=0, output=b"")


class Chapter7RestoreTests(unittest.TestCase):
    @patch.object(lab.Path, "is_file", return_value=True)
    @patch.object(lab, "mongo", return_value=(None, FakeDatabase()))
    @patch.object(lab, "docker_client")
    def test_lab_collections_do_not_block_restore_and_are_excluded(
        self, docker_client, _mongo, _archive_exists
    ):
        container = FakeContainer()
        docker_client.return_value.containers.get.return_value = container

        result = lab.load_ch7_backup()

        self.assertTrue(result["restored"])
        self.assertIn(
            f"--nsExclude={lab.DATABASE_NAME}.lab_*",
            container.command,
        )
        self.assertNotIn("--drop", container.command)


if __name__ == "__main__":
    unittest.main()
