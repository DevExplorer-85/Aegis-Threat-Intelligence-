"""Demonstrate field redaction through a MongoDB view and scoped RBAC."""

from __future__ import annotations

import getpass
import os
import re
from pprint import pprint
from typing import Any

from pymongo import MongoClient
from pymongo.errors import OperationFailure

DATABASE_NAME = "chapter12_security_lab"
SOURCE_COLLECTION = "employees"
SAFE_VIEW = "employees_safe"
SAFE_VIEW_ROLE = "employeeSafeViewReader"

EMPLOYEES: list[dict[str, Any]] = [
    {
        "_id": "employee-001",
        "username": "alice",
        "email": "alice@example.test",
        "role": "engineer",
        "ssn": "123-45-6789",
        "salary": 125000,
    },
    {
        "_id": "employee-002",
        "username": "bob",
        "email": "bob@example.test",
        "role": "designer",
        "ssn": "234-56-7890",
        "salary": 110000,
    },
    {
        "_id": "employee-003",
        "username": "carol",
        "email": "carol@example.test",
        "role": "manager",
        "ssn": "345-67-8901",
        "salary": 145000,
    },
]


def create_or_update_view_role(database: Any) -> None:
    try:
        role_info = database.command({"rolesInfo": SAFE_VIEW_ROLE}).get("roles", [])
    except OperationFailure as error:
        if error.code != 31:
            raise
        role_info = []
    definition = {
        "privileges": [
            {
                "resource": {"db": DATABASE_NAME, "collection": SAFE_VIEW},
                "actions": ["find"],
            }
        ],
        "roles": [],
    }
    if role_info:
        database.command("updateRole", SAFE_VIEW_ROLE, **definition)
    else:
        database.command("createRole", role=SAFE_VIEW_ROLE, **definition)


def create_or_update_user(
    database: Any, username: str, password: str, roles: list[dict[str, str]]
) -> None:
    users = database.command({"usersInfo": username}).get("users", [])
    if users:
        database.command("updateUser", username, pwd=password, roles=roles)
    else:
        database.command("createUser", username, pwd=password, roles=roles)


def expect_unauthorized(action: Any, description: str) -> None:
    try:
        action()
    except OperationFailure as error:
        if error.code != 13:
            raise
        print(f"[OK] {description} was correctly rejected.")
    else:
        raise RuntimeError(f"{description} unexpectedly succeeded.")


def main() -> None:
    admin_uri = os.environ.get(
        "MONGODB_ADMIN_URI",
        "mongodb://127.0.0.1:27017/?directConnection=true",
    )
    with MongoClient(admin_uri, serverSelectionTimeoutMS=5000) as admin_client:
        admin_client.admin.command("ping")
        database = admin_client[DATABASE_NAME]

        for employee in EMPLOYEES:
            database[SOURCE_COLLECTION].replace_one(
                {"_id": employee["_id"]}, employee, upsert=True
            )

        existing_view = next(
            database.list_collections(filter={"name": SAFE_VIEW}), None
        )
        if existing_view:
            if existing_view.get("type") != "view":
                raise RuntimeError(
                    f"{SAFE_VIEW!r} exists but is not a view; refusing to replace it."
                )
            database.command("drop", SAFE_VIEW)

        database.command(
            "create",
            SAFE_VIEW,
            viewOn=SOURCE_COLLECTION,
            pipeline=[
                {
                    "$project": {
                        "username": 1,
                        "email": 1,
                        "role": 1,
                        "ssn": {
                            "$concat": [
                                "***-**-",
                                {"$substrBytes": ["$ssn", 7, 4]},
                            ]
                        },
                        "salary": "$$REMOVE",
                    }
                }
            ],
        )

        safe_password = getpass.getpass("Password for safe_viewer: ")
        hr_password = getpass.getpass("Password for hr_user: ")
        create_or_update_view_role(database)
        create_or_update_user(
            database,
            "safe_viewer",
            safe_password,
            [{"role": SAFE_VIEW_ROLE, "db": DATABASE_NAME}],
        )
        create_or_update_user(
            database,
            "hr_user",
            hr_password,
            [{"role": "read", "db": DATABASE_NAME}],
        )

        print("\nAdministrator view (sensitive fields included):")
        pprint(list(database[SOURCE_COLLECTION].find({}, {"_id": 0})))

        if admin_client.address is None:
            raise RuntimeError("Could not determine the connected MongoDB server address.")
        host, port = admin_client.address
        with MongoClient(
            host=host,
            port=port,
            username="safe_viewer",
            password=safe_password,
            authSource=DATABASE_NAME,
            serverSelectionTimeoutMS=5000,
        ) as safe_client:
            safe_database = safe_client[DATABASE_NAME]
            safe_records = list(safe_database[SAFE_VIEW].find({}, {"_id": 0}))
            if len(safe_records) != len(EMPLOYEES):
                raise RuntimeError("The safe view did not return all seeded records.")
            for record in safe_records:
                if not {"username", "email", "role", "ssn"}.issubset(record):
                    raise RuntimeError("The safe view omitted a required public field.")
                if "salary" in record:
                    raise RuntimeError("The safe view exposed a salary field.")
                if not re.fullmatch(r"\*\*\*-\*\*-\d{4}", record["ssn"]):
                    raise RuntimeError("The safe view did not mask an SSN correctly.")

            print("\nsafe_viewer output:")
            pprint(safe_records)
            expect_unauthorized(
                lambda: safe_database[SOURCE_COLLECTION].find_one(),
                "safe_viewer access to the source collection",
            )

        with MongoClient(
            host=host,
            port=port,
            username="hr_user",
            password=hr_password,
            authSource=DATABASE_NAME,
            serverSelectionTimeoutMS=5000,
        ) as hr_client:
            hr_record = hr_client[DATABASE_NAME][SOURCE_COLLECTION].find_one()
            if not hr_record or "salary" not in hr_record or "ssn" not in hr_record:
                raise RuntimeError("hr_user could not read the full employee record.")
            print("\n[OK] hr_user can read the underlying employee collection.")


if __name__ == "__main__":
    main()
