import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.lab12_security import (
    EMPLOYEES,
    SAFE_VIEW_PIPELINE,
    evaluate_permission,
    inspect_tls_files,
    run_field_redaction_demo,
    run_rbac_setup,
    run_rbac_verification,
    run_tls_setup,
    run_tls_verification,
)


class Lab12SecurityTests(unittest.TestCase):
    def test_rbac_permission_evaluation(self):
        # Analyst can read bookstore, cannot write nosql_labs
        self.assertTrue(evaluate_permission("analyst", "bookstore", "books", "find"))
        self.assertFalse(evaluate_permission("analyst", "nosql_labs", "rbac_probe", "insert"))

        # app_writer can write nosql_labs, cannot read bookstore
        self.assertTrue(evaluate_permission("app_writer", "nosql_labs", "rbac_probe", "insert"))
        self.assertFalse(evaluate_permission("app_writer", "bookstore", "books", "find"))

        # log_writer can insert/update logs, cannot write outside logs or delete
        self.assertTrue(evaluate_permission("log_writer", "nosql_labs", "logs", "insert"))
        self.assertTrue(evaluate_permission("log_writer", "nosql_labs", "logs", "update"))
        self.assertFalse(evaluate_permission("log_writer", "nosql_labs", "rbac_probe", "insert"))
        self.assertFalse(evaluate_permission("log_writer", "nosql_labs", "logs", "delete"))

    def test_rbac_setup_roles_and_users(self):
        result = run_rbac_setup(None)
        self.assertEqual(result["chapter"], 12)
        self.assertEqual(result["lab"], "12.1")
        self.assertTrue(len(result["roles"]) >= 2)
        self.assertTrue(len(result["users"]) >= 3)

        role_names = [r["role"] for r in result["roles"]]
        self.assertIn("limitedLogWriter", role_names)
        self.assertIn("employeeSafeViewReader", role_names)

        usernames = [u["user"] for u in result["users"]]
        self.assertIn("analyst", usernames)
        self.assertIn("app_writer", usernames)
        self.assertIn("log_writer", usernames)
        self.assertIn("safe_viewer", usernames)
        self.assertIn("hr_user", usernames)

    def test_rbac_verification_boundaries(self):
        result = run_rbac_verification(None)
        self.assertEqual(result["chapter"], 12)
        self.assertEqual(result["lab"], "12.1-try")
        self.assertTrue(result["all_checks_passed"])
        self.assertEqual(result["total_checks"], 8)

        deny_checks = [c for c in result["results"] if "DENY" in c["expected"]]
        self.assertEqual(len(deny_checks), 4)

    def test_tls_files_and_setup(self):
        tls_dir = PROJECT_ROOT.parent / "tls"
        info = inspect_tls_files(tls_dir)
        self.assertTrue(info["all_files_present"])
        self.assertEqual(info["ca_common_name"], "MongoDB-Lab-CA")
        self.assertEqual(info["server_common_name"], "localhost")
        self.assertIn("DNS.1 = localhost", info["subject_alternative_names"])
        self.assertIn("IP.1 = 127.0.0.1", info["subject_alternative_names"])

        setup_result = run_tls_setup(tls_dir)
        self.assertEqual(setup_result["chapter"], 12)
        self.assertEqual(setup_result["lab"], "12.2")
        self.assertTrue(setup_result["tls_ready"])
        self.assertIn("requireTLS", setup_result["server_startup_command"])
        self.assertIn("server.pem", setup_result["server_startup_command"])
        self.assertIn("ca.crt", setup_result["server_startup_command"])

    def test_tls_verification(self):
        tls_dir = PROJECT_ROOT.parent / "tls"
        result = run_tls_verification(tls_dir=tls_dir)
        self.assertEqual(result["chapter"], 12)
        self.assertEqual(result["lab"], "12.2-try")
        self.assertEqual(len(result["verification_results"]), 3)
        self.assertEqual(result["verification_results"][0]["expected_outcome"], "REJECTED (TLS Handshake Required / Connection Dropped)")
        self.assertIn("ca.crt", result["pymongo_sample_code"])
        self.assertIn("client.pem", result["pymongo_sample_code"])

    def test_field_redaction_pipeline_and_checks(self):
        result = run_field_redaction_demo(None)
        self.assertEqual(result["chapter"], 12)
        self.assertEqual(result["lab"], "12.3")
        self.assertEqual(len(result["checks"]), 4)
        for check in result["checks"]:
            self.assertEqual(check["result"], "PASSED")

        # Verify redacted records
        for record in result["redacted_records_sample"]:
            self.assertNotIn("salary", record)
            self.assertTrue(record["ssn"].startswith("***-**-"))
            self.assertEqual(len(record["ssn"]), 11)
            self.assertIn("username", record)
            self.assertIn("email", record)
            self.assertIn("role", record)

        # Verify comparison
        self.assertEqual(len(result["comparison"]), len(EMPLOYEES))
        for comp in result["comparison"]:
            self.assertEqual(comp["redacted_salary"], "[REMOVED]")
            self.assertTrue(comp["redacted_ssn"].startswith("***-**-"))


if __name__ == "__main__":
    unittest.main()
