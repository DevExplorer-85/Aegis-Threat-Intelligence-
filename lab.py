#!/usr/bin/env python3
"""Run the Chapter 7-13 MongoDB labs and save logs, results, and wire commands."""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

OUTPUT = Path(os.getenv("OUTPUT_DIR", str(ROOT / "output")))
RESULTS = OUTPUT / "results"
REPLICA_URI = os.getenv(
    "MONGO_URI",
    "mongodb://mongo1:27017/?directConnection=true",
)
DATABASE_NAME = os.getenv("DATABASE_NAME", "cyber_threat_intelligence")
LABS = (
    "7.1", "7.1-try", "7.2", "7.2-try",
    "8.1", "8.1-try", "8.2", "8.2-try",
    "9.1", "9.1-try", "9.2",
    "10.1", "10.1-try", "10.2", "10.2-try",
    "11.1", "11.1-try", "11.2",
    "12.1", "12.1-try", "12.2", "12.2-try", "12.3",
    "13.1", "13.2",
)
CTI_DATA_COLLECTIONS = {
    "feed_events",
    "indicators",
    "sources",
    "intelligence_feeds",
    "threat_reports",
    "threat_actors",
    "threat_classifications",
    "security_reports",
    "security_report_passages",
    "vt_cache",
    "working_set_test",
}
OUTPUT.mkdir(parents=True, exist_ok=True)
RESULTS.mkdir(parents=True, exist_ok=True)


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, text):
        for stream in self.streams:
            stream.write(text)
            stream.flush()
        return len(text)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def now_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def mongo():
    from app.database import client, db

    return client, db


def wait_for_primary(timeout=90):
    from pymongo import MongoClient

    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            with MongoClient(
                REPLICA_URI,
                serverSelectionTimeoutMS=2500,
                connectTimeoutMS=2500,
            ) as client:
                hello = client.admin.command("hello")
                if hello.get("isWritablePrimary"):
                    return hello.get("me") or hello.get("primary")
        except Exception as error:
            last_error = error
        time.sleep(2)
    raise RuntimeError(f"Replica-set primary was not elected within {timeout}s: {last_error}")


def direct_client(host, timeout=3000):
    from pymongo import MongoClient
    from app.mongo_command_log import command_listeners_from_environment

    return MongoClient(
        f"mongodb://{host}/?directConnection=true&readPreference=secondaryPreferred",
        serverSelectionTimeoutMS=timeout,
        connectTimeoutMS=timeout,
        event_listeners=command_listeners_from_environment(),
    )


def setup_replica_set():
    from pymongo import MongoClient
    from pymongo.errors import OperationFailure
    from app.mongo_command_log import command_listeners_from_environment

    print("Connecting to mongo1 and initializing replica set rs0...")
    direct = MongoClient(
        "mongodb://mongo1:27017/?directConnection=true",
        serverSelectionTimeoutMS=5000,
        event_listeners=command_listeners_from_environment(),
    )
    try:
        direct.admin.command("ping")
        try:
            direct.admin.command({
                "replSetInitiate": {
                    "_id": "rs0",
                    "members": [
                        {"_id": index, "host": host}
                        for index, host in enumerate(MEMBERS)
                    ],
                }
            })
            print("Replica set initialization requested.")
        except OperationFailure as error:
            if error.code == 23 or "already initialized" in str(error).lower():
                print("Replica set rs0 is already initialized; leaving its data intact.")
            else:
                raise
    finally:
        direct.close()
    primary = wait_for_primary()
    print(f"PRIMARY elected: {primary}")
    return {"replica_set": "rs0", "primary": primary, "members": list(MEMBERS)}


def status():
    from pymongo import MongoClient

    observed = []
    primary_name = None
    with MongoClient(
        REPLICA_URI,
        serverSelectionTimeoutMS=2500,
        connectTimeoutMS=2500,
    ) as client:
        try:
            status_doc = client.admin.command("replSetGetStatus")
        except Exception:
            status_doc = None
        if status_doc:
            primary_name = next(
                (member.get("name") for member in status_doc.get("members", [])
                 if member.get("stateStr") == "PRIMARY"),
                None,
            )
            newest_optime = max(
                (member.get("optimeDate") for member in status_doc.get("members", [])
                 if member.get("optimeDate") is not None),
                default=None,
            )
            for member in status_doc.get("members", []):
                optime = member.get("optimeDate")
                lag = (
                    max(0.0, (newest_optime - optime).total_seconds())
                    if newest_optime is not None and optime is not None
                    else None
                )
                observed.append({
                    "name": member.get("name"),
                    "state": member.get("stateStr", "UNKNOWN"),
                    "health": member.get("health", 0),
                    "lag_seconds": round(lag, 3) if lag is not None else None,
                    "arbiter": member.get("stateStr") == "ARBITER",
                    "reachable": True,
                    "last_heartbeat_message": member.get("lastHeartbeatMessage"),
                })
    if not observed:
        for host in MEMBERS:
            try:
                with direct_client(host) as direct:
                    member_status = direct.admin.command("replSetGetStatus")
                    for member in member_status.get("members", []):
                        if member.get("name") == host:
                            observed.append({
                                "name": host,
                                "state": member.get("stateStr", "UNKNOWN"),
                                "health": member.get("health", 0),
                                "lag_seconds": None,
                                "arbiter": member.get("stateStr") == "ARBITER",
                                "reachable": True,
                                "last_heartbeat_message": member.get("lastHeartbeatMessage"),
                            })
                            if member.get("stateStr") == "PRIMARY":
                                primary_name = host
            except Exception as error:
                observed.append({
                    "name": host,
                    "state": "UNREACHABLE",
                    "health": 0,
                    "lag_seconds": None,
                    "arbiter": False,
                    "reachable": False,
                    "last_heartbeat_message": str(error),
                })
    for member in observed:
        print(
            f"{member['name']}: {member['state']} | health={member['health']} "
            f"| lag={member['lag_seconds'] if member['lag_seconds'] is not None else 'n/a'}s"
        )
    if not primary_name:
        print("NO PRIMARY")
    return {
        "replica_set": "rs0",
        "primary": primary_name,
        "no_primary": primary_name is None,
        "members": observed,
    }


def status_ch7():
    _, database = mongo()
    important = (
        "feed_events", "indicators", "threat_actors", "threat_reports",
        "sources", "intelligence_feeds", "security_reports",
        "security_report_passages", "vt_cache", "working_set_test",
        "lab_ch72_working_set",
    )
    counts = {
        name: database[name].count_documents({})
        for name in important
        if name in database.list_collection_names()
    }
    print(f"Database: {DATABASE_NAME}")
    for name, count in sorted(counts.items()):
        print(f"{name}: {count:,}")
    return {"database": DATABASE_NAME, "collections": counts}


def setup_database():
    client, database = mongo()
    client.admin.command("ping")
    server = client.admin.command("serverStatus")
    print(
        f"MongoDB connected: version {server.get('version', 'unknown')} "
        f"| database {DATABASE_NAME} | standalone server"
    )
    return {
        "connected": True,
        "database": DATABASE_NAME,
        "mongodb_version": server.get("version"),
        "deployment": "standalone",
    }


def standalone_status():
    client, database = mongo()
    server = client.admin.command("serverStatus")
    counts = {
        name: database[name].count_documents({})
        for name in sorted(database.list_collection_names())
        if not name.startswith("system.")
    }
    print(
        f"MongoDB standalone: connected | version {server.get('version')} "
        f"| database {DATABASE_NAME}"
    )
    for name, count in counts.items():
        print(f"{name}: {count:,}")
    return {
        "deployment": "standalone",
        "connected": True,
        "database": DATABASE_NAME,
        "mongodb_version": server.get("version"),
        "collections": counts,
    }


def chapter8_schema_inventory():
    _, database = mongo()
    rows = []
    for name in ("feed_events", "indicators", "threat_reports", "threat_actors", "sources"):
        if name not in database.list_collection_names():
            continue
        sample = database[name].find_one()
        if sample is None:
            rows.append({"collection": name, "documents": 0, "sample_fields": []})
            continue
        fields = sorted(sample.keys())
        references = [
            field for field in fields
            if field.endswith(("_id", "_uuid", "_ref")) and field != "_id"
        ]
        embedded = [
            field for field, value in sample.items()
            if field != "_id" and isinstance(value, (dict, list))
        ]
        rows.append({
            "collection": name,
            "documents": database[name].count_documents({}),
            "sample_fields": fields,
            "reference_fields": references,
            "embedded_fields": embedded,
        })
    if not rows:
        raise RuntimeError("No Chapter 7 CTI collections found. Restore your Chapter 7 data first.")
    print("Chapter 8 · CTI document structure (Chapter 7 data)")
    for row in rows:
        print(
            f"{row['collection']}: {row['documents']:,} documents | "
            f"references={row.get('reference_fields', [])} | "
            f"embedded={row.get('embedded_fields', [])}"
        )
    return {
        "chapter": 8,
        "database": DATABASE_NAME,
        "collections": rows,
        "note": "Examines the real Chapter 7 CTI database; no replica set is used.",
    }


def chapter8_query_benchmark():
    _, database = mongo()
    source = database["indicators"]
    sample = list(source.find(
        {"value": {"$type": "string", "$ne": ""}},
        {"_id": 1, "value": 1, "type": 1, "feed_id": 1, "event_uuid": 1},
    ).limit(5000))
    if not sample:
        raise RuntimeError("No Chapter 7 indicators found. Restore Chapter 7 data first.")
    target_name = "lab_ch8_indicator_copy"
    target = database[target_name]
    target.drop()
    target.insert_many(sample, ordered=False)
    search_value = sample[len(sample) // 2]["value"]

    def measure():
        started = time.perf_counter()
        matches = list(target.find({"value": search_value}, {"_id": 1, "value": 1}))
        return round((time.perf_counter() - started) * 1000, 4), len(matches)

    unindexed_time, unindexed_count = measure()
    target.create_index("value", name="lab_value_lookup")
    indexed_time, indexed_count = measure()
    result = {
        "source_collection": "indicators",
        "lab_collection": target_name,
        "copied_real_documents": len(sample),
        "query_target": "sampled indicator value (redacted)",
        "unindexed_ms": unindexed_time,
        "indexed_ms": indexed_time,
        "unindexed_matches": unindexed_count,
        "indexed_matches": indexed_count,
        "indexes": list(target.index_information()),
    }
    print(
        f"Copied {len(sample):,} real indicators into {target_name}. "
        f"Lookup without index: {unindexed_time}ms; with index: {indexed_time}ms."
    )
    return result


def chapter8_relationship_check():
    _, database = mongo()
    indicators = database["indicators"]
    events = database["feed_events"]
    total = indicators.count_documents({})
    linked = indicators.count_documents({
        "event_uuid": {"$exists": True, "$nin": [None, ""]}
    })
    examples = list(indicators.aggregate([
        {"$match": {"event_uuid": {"$exists": True, "$nin": [None, ""]}}},
        {"$limit": 500},
        {"$lookup": {
            "from": "feed_events",
            "let": {"event_uuid": "$event_uuid", "feed_id": "$feed_id"},
            "pipeline": [{"$match": {"$expr": {"$and": [
                {"$eq": ["$event_uuid", "$$event_uuid"]},
                {"$eq": ["$feed_id", "$$feed_id"]},
            ]}}}, {"$project": {"_id": 1}}],
            "as": "event_match",
        }},
        {"$project": {
            "_id": 1, "event_uuid": 1, "feed_id": 1,
            "event_found": {"$gt": [{"$size": "$event_match"}, 0]},
        }},
    ]))
    result = {
        "indicator_count": total,
        "with_event_reference": linked,
        "sampled_links": len(examples),
        "sampled_linked_events_found": sum(bool(row["event_found"]) for row in examples),
        "sampled_orphan_references": sum(not row["event_found"] for row in examples),
        "event_collection_count": events.count_documents({}),
        "database": DATABASE_NAME,
    }
    print(
        f"Verified {result['sampled_linked_events_found']}/{len(examples)} sampled "
        "indicator-to-event references against Chapter 7 data."
    )
    return result


def chapter8_query_plan():
    _, database = mongo()
    indicator = database["indicators"].find_one(
        {"value": {"$type": "string", "$ne": ""}},
        {"_id": 0, "value": 1},
    )
    if not indicator:
        raise RuntimeError("No Chapter 7 indicators found. Restore Chapter 7 data first.")
    explain = database.command(
        "explain",
        {
            "find": "indicators",
            "filter": {"value": indicator["value"]},
            "projection": {"_id": 1},
        },
        verbosity="executionStats",
    )
    query_planner = explain.get("queryPlanner", {})
    execution_stats = explain.get("executionStats", {})
    result = {
        "database": DATABASE_NAME,
        "collection": "indicators",
        "query_target": "sampled indicator value (redacted)",
        "existing_indexes": list(database["indicators"].index_information()),
        "winning_plan": query_planner.get("winningPlan"),
        "execution_stats": {
            key: execution_stats.get(key)
            for key in ("nReturned", "totalKeysExamined", "totalDocsExamined", "executionTimeMillis")
        },
        "note": "Read-only explain() against the real Chapter 7 indicator collection.",
    }
    print(
        "Existing indicator query plan: "
        f"{result['execution_stats'].get('totalDocsExamined')} documents examined, "
        f"{result['execution_stats'].get('totalKeysExamined')} index keys examined."
    )
    return result


def chapter9_write_benchmark(journal_values):
    from pymongo import WriteConcern

    _, database = mongo()
    results = []
    for journal in journal_values:
        collection_name = f"lab_ch9_write_j{int(journal)}"
        collection = database[collection_name]
        collection.drop()
        guarded = collection.with_options(
            write_concern=WriteConcern(w=1, j=journal)
        )
        started = time.perf_counter()
        completed = 0
        for index in range(1000):
            guarded.insert_one({
                "_id": index,
                "indicator_sample": index % 100,
                "database": DATABASE_NAME,
                "experiment": "chapter-9",
                "journal": journal,
            })
            completed += 1
        elapsed = (time.perf_counter() - started) * 1000
        row = {
            "journal": journal,
            "write_concern": "w:1",
            "completed_writes": completed,
            "elapsed_ms": round(elapsed, 3),
            "average_latency_ms": round(elapsed / completed, 5),
            "collection": collection_name,
        }
        results.append(row)
        print(
            f"Standalone w:1, j:{str(journal).lower()}: 1000 writes in "
            f"{row['elapsed_ms']}ms ({row['average_latency_ms']}ms/write)"
        )
    return {
        "chapter": 9,
        "deployment": "standalone",
        "database": DATABASE_NAME,
        "results": results,
        "unsupported": {
            "majority": "Requires a replica set; not available in this standalone setup.",
            "all": "Requires multiple replica-set members; not available in this standalone setup.",
            "failover_and_partition": "Require a replica set; not performed in this simplified setup.",
        },
        "note": "Measurements are isolated in lab_ch9_write_j* collections; CTI source data is read-only.",
    }


def chapter9_data_audit():
    _, database = mongo()
    total = database["indicators"].count_documents({})
    if total == 0:
        raise RuntimeError("No Chapter 7 indicators found. Restore Chapter 7 data first.")
    rows = list(database["indicators"].aggregate([
        {"$sample": {"size": min(total, 500)}},
        {"$lookup": {
            "from": "feed_events",
            "let": {"event_uuid": "$event_uuid", "feed_id": "$feed_id"},
            "pipeline": [{"$match": {"$expr": {"$and": [
                {"$eq": ["$event_uuid", "$$event_uuid"]},
                {"$eq": ["$feed_id", "$$feed_id"]},
            ]}}}, {"$limit": 1}],
            "as": "matching_events",
        }},
        {"$project": {
            "_id": 1,
            "value": 1,
            "type": 1,
            "has_event_reference": {"$and": [
                {"$ne": [{"$ifNull": ["$event_uuid", None]}, None]},
                {"$ne": [{"$ifNull": ["$feed_id", None]}, None]},
            ]},
            "event_found": {"$gt": [{"$size": "$matching_events"}, 0]},
        }},
    ]))
    result = {
        "sampled_indicators": len(rows),
        "valid_event_links": sum(bool(row["event_found"]) for row in rows),
        "orphaned_event_links": sum(
            bool(row["has_event_reference"]) and not row["event_found"] for row in rows
        ),
        "indicators_without_event_reference": sum(
            not row["has_event_reference"] for row in rows
        ),
        "data_collection": "indicators",
        "database": DATABASE_NAME,
    }
    print(
        f"Chapter 7 data audit: {result['valid_event_links']} valid links, "
        f"{result['orphaned_event_links']} orphaned links across "
        f"{result['sampled_indicators']} sampled indicators."
    )
    return result


def chapter10_transfer_demo(retry_attempts=5):
    from scripts.lab10_transactions import run_transfer_demo

    _, database = mongo()
    result = run_transfer_demo(
        database,
        max_attempts=retry_attempts,
        backoff_base=0.1,
    )
    result.update({
        "chapter": 10,
        "lab": "10.1",
        "retry_attempts": retry_attempts,
        "retry_policy": "TransientTransactionError with exponential backoff",
    })
    print(
        "Bank transfer completed; insufficient-funds rollback "
        f"verified={result['rollback_verified']}."
    )
    return result


def chapter10_inventory_demo(retry_attempts=5):
    from scripts.lab10_transactions import run_inventory_demo

    _, database = mongo()
    result = run_inventory_demo(database, max_attempts=retry_attempts)
    result.update({
        "chapter": 10,
        "lab": "10.2",
        "retry_attempts": retry_attempts,
        "retry_policy": "TransientTransactionError with exponential backoff",
    })
    print(
        "Concurrent inventory reservations: "
        f"{result['contention']['succeeded']} succeeded, "
        f"{result['contention']['insufficient_stock']} correctly rejected."
    )
    for row in result["throughput"]:
        print(
            f"{row['concurrency']} workers: "
            f"{row['throughput_per_second']} reservations/s "
            f"({row['successful_reservations']}/{row['requests']} succeeded)"
        )
    return result


def chapter11_shard_key_evaluation():
    from scripts.lab11_sharding import evaluate_shard_keys, format_decision_matrix

    result = evaluate_shard_keys()
    result.update({"chapter": 11, "lab": "11.1"})
    print(format_decision_matrix(result))
    return result


def chapter11_resharding_activity():
    from scripts.lab11_sharding import RESHARDING_LIMITATIONS, RESHARDING_STEPS

    result = {
        "chapter": 11,
        "lab": "11.1-try",
        "mongodb_version": "5.0+",
        "steps": RESHARDING_STEPS,
        "limitations": RESHARDING_LIMITATIONS,
        "documentation": (
            "https://www.mongodb.com/docs/manual/core/sharding-reshard-a-collection/"
        ),
    }
    print("Chapter 11.1 activity · MongoDB collection resharding")
    for index, step in enumerate(result["steps"], start=1):
        print(f"{index}. {step}")
    print("Limitations:")
    for limitation in result["limitations"]:
        print(f"- {limitation}")
    print(f"Official documentation: {result['documentation']}")
    return result


def chapter11_hotspot_demo():
    from scripts.lab11_sharding import format_hotspot_report, run_hotspot_demo

    result = run_hotspot_demo(REPLICA_URI)
    print(format_hotspot_report(result))
    return result


def chapter12_rbac_setup():
    from scripts.lab12_security import run_rbac_setup

    try:
        client, database = mongo()
    except Exception:
        client, database = None, None
    result = run_rbac_setup(client)
    print("Chapter 12 · Activity 1: Least-Privilege RBAC Setup")
    for role in result["roles"]:
        print(f"Role: {role['role']} ({role['db']}) - {role['description']}")
    for user in result["users"]:
        print(f"User: {user['user']} ({user['auth_db']}) - {user['description']}")
    return result


def chapter12_rbac_verification():
    from scripts.lab12_security import run_rbac_verification

    try:
        client, database = mongo()
    except Exception:
        client, database = None, None
    result = run_rbac_verification(client)
    print("Chapter 12 · Activity 1: RBAC Permission Boundary Verification")
    for check in result["results"]:
        print(f"{check['user']} -> {check['target']} ({check['action']}): {check['expected']} [{check['status']}]")
    return result


def chapter12_tls_setup():
    from scripts.lab12_security import run_tls_setup

    result = run_tls_setup()
    print("Chapter 12 · Activity 2: TLS Setup & Transit Encryption")
    print(f"TLS Directory: {result['tls_directory']}")
    print(f"TLS Ready: {result['tls_ready']}")
    print(f"Server Startup Command:\n  {result['server_startup_command']}")
    print(f"Verification Command:\n  {result['verification_command']}")
    return result


def chapter12_tls_verification():
    from scripts.lab12_security import run_tls_verification

    result = run_tls_verification()
    print("Chapter 12 · Activity 2: TLS Connection Verification")
    for row in result["verification_results"]:
        print(f"{row['channel']}: {row['expected_outcome']} [{row['status']}]")
    return result


def chapter12_field_redaction():
    from scripts.lab12_security import run_field_redaction_demo

    try:
        client, database = mongo()
    except Exception:
        client, database = None, None
    result = run_field_redaction_demo(client)
    print("Chapter 12 · Activity 3: Field-Level Redaction with employees_safe View")
    for check in result["checks"]:
        print(f"{check['check']}: {check['result']}")
    print("\nComparison:")
    for comp in result["comparison"]:
        print(
            f"  {comp['employee']}: SSN {comp['source_ssn']} -> {comp['redacted_ssn']} | "
            f"Salary {comp['source_salary']} -> {comp['redacted_salary']}"
        )
    return result


def load_ch7_backup():
    _, database = mongo()
    backup = Path(os.getenv("CTI_BACKUP_ARCHIVE", "/app/backup/ch7.archive"))
    if not backup.is_file():
        raise FileNotFoundError(
            f"Chapter 7 backup not supplied: {backup}. Put your own mongodump "
            "archive at .\\backup\\ch7.archive and run 7-load again. No sample "
            "or third-party dataset is substituted."
        )
    existing = database.list_collection_names()
    populated = [
        name for name in existing
        if name in CTI_DATA_COLLECTIONS
        if database[name].count_documents({}, limit=1) > 0
    ]
    if populated:
        print(
            f"Database {DATABASE_NAME} already has populated collections "
            f"({', '.join(populated[:5])}); "
            "skipping restore to protect existing data."
        )
        return {"restored": False, "reason": "target database has data", "populated_collections": populated}
    print(f"Restoring the supplied archive into {DATABASE_NAME} without --drop...")
    print("Running the official mongorestore binary inside the mongo1 container.")
    api = docker_client()
    mongo1 = api.containers.get("mongo1")
    command = [
        "mongorestore",
        f"--uri={REPLICA_URI}",
        "--archive=/backup/ch7.archive",
        "--gzip",
        f"--nsInclude={DATABASE_NAME}.*",
        f"--nsExclude={DATABASE_NAME}.lab_*",
    ]
    process = mongo1.exec_run(command, workdir="/")
    output = process.output
    if isinstance(output, tuple):
        stdout, stderr = output
        if stdout:
            print(stdout.decode("utf-8", errors="replace"), end="")
        if stderr:
            print(stderr.decode("utf-8", errors="replace"), file=sys.stderr, end="")
    elif output:
        print(output.decode("utf-8", errors="replace"), end="")
    if process.exit_code:
        raise RuntimeError(f"mongorestore exited with status {process.exit_code}")
    return {
        "restored": True,
        "archive": str(backup),
        "mongorestore_exit_code": process.exit_code,
        "collections": database.list_collection_names(),
    }


def ch71_analysis():
    _, database = mongo()
    rows = []
    for name in sorted(database.list_collection_names()):
        if name.startswith("system."):
            continue
        aggregate = list(database[name].aggregate([
            {"$group": {
                "_id": None,
                "count": {"$sum": 1},
                "average_bytes": {"$avg": {"$bsonSize": "$$ROOT"}},
                "maximum_bytes": {"$max": {"$bsonSize": "$$ROOT"}},
                "minimum_bytes": {"$min": {"$bsonSize": "$$ROOT"}},
            }}
        ]))
        sample = database[name].find_one()
        reference_fields = []
        if sample:
            reference_fields = [
                key for key in sample
                if key.endswith(("_id", "_uuid", "_ref"))
                and key != "_id"
                and not isinstance(sample[key], (dict, list))
            ]
        row = aggregate[0] if aggregate else {}
        rows.append({
            "collection": name,
            "count": row.get("count", 0),
            "average_bytes": round(row.get("average_bytes") or 0, 2),
            "minimum_bytes": row.get("minimum_bytes", 0),
            "maximum_bytes": row.get("maximum_bytes", 0),
            "limit_bytes": 16 * 1024 * 1024,
            "reference_fields_sample": reference_fields,
            "sample_document_has_embedded_values": bool(sample and any(
                isinstance(value, (dict, list))
                for key, value in sample.items() if key != "_id"
            )),
        })
    print("Chapter 7 real database BSON/schema analysis")
    print("References: indicators.event_uuid/feed_id link attributes to feed events.")
    print("Embedding: MISP tags and nested report/event fields remain with their owner.")
    print("Embedding alternative: materialize IOC sightings by normalized type/value.")
    print("Updates/large fan-out favor references; bounded, read-together data can embed.")
    print(f"{'Collection':32} {'Docs':>10} {'Avg B':>12} {'Max B':>12} {'16 MiB':>10}")
    for row in rows:
        print(
            f"{row['collection'][:32]:32} {row['count']:>10,} "
            f"{row['average_bytes']:>12,.2f} {row['maximum_bytes']:>12,} "
            f"{'SAFE' if row['maximum_bytes'] < row['limit_bytes'] else 'CHECK':>10}"
        )
    return {
        "collections": rows,
        "relationships": [
            {
                "relationship": "indicators to feed_events",
                "design": "referenced by event_uuid and feed_id",
                "reason": "events group many indicators and are synchronized independently",
                "embedded_alternative": "a separate materialized sightings document per IOC",
            },
            {
                "relationship": "MISP tags and event fields",
                "design": "embedded in their owning documents",
                "reason": "small source metadata is usually read with its event/indicator",
            },
        ],
    }


def ch71_try():
    _, database = mongo()
    target = "lab_ch71_embedded_sightings"
    pipeline = [
        {"$project": {
            "_id": 0,
            "type": 1,
            "value": 1,
            "sighting": {
                "feed_id": "$feed_id",
                "event_uuid": "$event_uuid",
                "category": "$category",
                "timestamp": "$timestamp",
            },
        }},
        {"$unionWith": {
            "coll": "feed_events",
            "pipeline": [
                {"$match": {"indicator_value": {"$type": "string", "$ne": ""}}},
                {"$project": {
                    "_id": 0,
                    "type": {"$ifNull": ["$indicator_type", "$event_type"]},
                    "value": "$indicator_value",
                    "sighting": {
                        "feed_id": "$feed_id",
                        "event_uuid": "$event_uuid",
                        "category": "event summary",
                        "timestamp": "$published_at",
                    },
                }},
            ],
        }},
        {"$project": {
            "type": 1,
            "value": 1,
            "normalized_value": {"$toLower": {"$trim": {"input": "$value"}}},
            "sighting": 1,
        }},
        {"$match": {"normalized_value": {"$nin": ["", None]}}},
        {"$group": {
            "_id": {"type": "$type", "value": "$normalized_value"},
            "display_value": {"$first": "$value"},
            "sightings": {"$addToSet": "$sighting"},
            "sighting_count": {"$sum": 1},
        }},
        {"$out": target},
    ]
    database["indicators"].aggregate(pipeline, allowDiskUse=True)
    embedded = database[target]
    count = embedded.count_documents({})
    if count == 0:
        raise RuntimeError("No real indicator documents were available to build sightings.")
    samples = list(embedded.find({}, {"_id": 1}).limit(100))
    values = [sample["_id"]["value"] for sample in samples]
    referenced_times, embedded_times = [], []
    for value in values:
        start = time.perf_counter()
        source = list(database["indicators"].find(
            {"value": {"$regex": f"^{re.escape(value)}$", "$options": "i"}},
            {"_id": 1, "event_uuid": 1, "feed_id": 1},
        ).limit(100))
        for sighting in source:
            database["feed_events"].find_one(
                {"event_uuid": sighting.get("event_uuid"), "feed_id": sighting.get("feed_id")},
                {"_id": 1, "title": 1},
            )
        referenced_times.append((time.perf_counter() - start) * 1000)
        start = time.perf_counter()
        embedded.find_one({"_id.value": value}, {"_id": 1, "sightings": 1})
        embedded_times.append((time.perf_counter() - start) * 1000)
    result = {
        "new_collection": target,
        "embedded_documents": count,
        "benchmark_values": len(values),
        "referenced_mean_ms": round(sum(referenced_times) / len(referenced_times), 4) if values else None,
        "embedded_mean_ms": round(sum(embedded_times) / len(embedded_times), 4) if values else None,
        "referenced_queries": len(values) * 2,
        "embedded_reads": len(values),
    }
    print(f"Built {count:,} real IOC sightings in {target}; source collections unchanged.")
    print(
        f"Referenced mean query pair: {result['referenced_mean_ms']} ms; "
        f"one embedded read: {result['embedded_mean_ms']} ms."
    )
    return result


def cache_snapshot(database):
    cache = database.command("serverStatus").get("wiredTiger", {}).get("cache", {})
    return {
        "maximum_bytes": cache.get("maximum bytes configured"),
        "current_bytes": cache.get("bytes currently in the cache"),
        "pages_read": cache.get("pages read into cache"),
        "pages_requested": cache.get("pages requested from the cache"),
    }


def configure_cache(database, setting):
    result = database.command({
        "setParameter": 1,
        "wiredTigerEngineRuntimeConfig": f"cache_size={setting}",
    })
    if result.get("ok") != 1:
        raise RuntimeError(f"MongoDB refused cache setting {setting}: {result}")
    print(f"WiredTiger runtime cache set to {setting}.")


def make_working_set(database, document_count=100_000):
    from bson import BSON
    from pymongo import InsertOne

    source = database["indicators"]
    seeds = list(source.find(
        {"value": {"$exists": True, "$ne": ""}},
        {"_id": 1, "value": 1, "type": 1, "event_uuid": 1, "feed_id": 1,
         "category": 1, "tags": 1},
    ).limit(2000))
    if not seeds:
        raise RuntimeError(
            "No real indicators are loaded. Supply your own Chapter 7 mongodump "
            "and run 7-load before building the 7.2 working set."
        )
    events, malware, reports = {}, {}, {}
    for seed in seeds:
        event_uuid = seed.get("event_uuid")
        if event_uuid and event_uuid not in events:
            events[event_uuid] = database["feed_events"].find_one(
                {"event_uuid": event_uuid, "feed_id": seed.get("feed_id")},
                {"_id": 0, "event_uuid": 1, "title": 1, "description": 1,
                 "classification": 1, "severity": 1, "tags": 1},
            )
        if event_uuid and event_uuid not in reports:
            reports[event_uuid] = database["threat_reports"].find_one(
                {"event_uuid": event_uuid},
                {"_id": 0, "title": 1, "summary": 1, "description": 1, "text": 1},
            )
        value = seed.get("value")
        if value and value not in malware and "malware_samples" in database.list_collection_names():
            malware[value] = database["malware_samples"].find_one(
                {"$or": [{"indicator": value}, {"value": value}]},
                {"_id": 0},
            )
    target_name = "lab_ch72_working_set"
    staging_name = "lab_ch72_working_set_staging"
    database.drop_collection(staging_name)
    collection = database[staging_name]
    operations = []
    for index in range(document_count):
        seed = seeds[index % len(seeds)]
        value = seed["value"]
        event_uuid = seed.get("event_uuid")
        item = {
            "_id": index,
            "source_indicator_id": seed.get("_id"),
            "value": value,
            "type": seed.get("type"),
            "feed_id": seed.get("feed_id"),
            "event_uuid": event_uuid,
            "event": events.get(event_uuid),
            "malware_sample": malware.get(value),
            "report": reports.get(event_uuid),
            "tags": seed.get("tags") or [],
            "experiment": "chapter-7.2",
            "padding": "",
        }
        base_size = len(BSON.encode(item))
        item["padding"] = "x" * max(0, 2048 - base_size)
        actual_size = len(BSON.encode(item))
        if actual_size > 2112:
            raise RuntimeError(f"Generated test record is unexpectedly large: {actual_size} bytes")
        operations.append(InsertOne(item))
        if len(operations) >= 1000:
            collection.bulk_write(operations, ordered=False)
            operations.clear()
            if index % 10_000 == 9_999:
                print(f"Built {index + 1:,}/{document_count:,} records...", flush=True)
    if operations:
        collection.bulk_write(operations, ordered=False)
    collection.create_index([("value", 1)])
    database.drop_collection(target_name)
    collection.rename(target_name)
    size_check = list(database[target_name].aggregate([
        {"$group": {
            "_id": None,
            "count": {"$sum": 1},
            "average_bytes": {"$avg": {"$bsonSize": "$$ROOT"}},
            "minimum_bytes": {"$min": {"$bsonSize": "$$ROOT"}},
            "maximum_bytes": {"$max": {"$bsonSize": "$$ROOT"}},
        }}
    ]))
    measured = size_check[0] if size_check else {"count": 0}
    average_bytes = measured.get("average_bytes") or 0
    if measured.get("count") != document_count or not 2000 <= average_bytes <= 2112:
        raise RuntimeError(
            f"Working-set validation failed: {measured.get('count')} docs, "
            f"average BSON size {average_bytes} bytes."
        )
    return measured


def random_read_round(database, reads=1000):
    collection = database["lab_ch72_working_set"]
    count = collection.count_documents({})
    if count == 0:
        raise RuntimeError("Run 7.2 first to build lab_ch72_working_set.")
    before = cache_snapshot(database)
    ids = [row["_id"] for row in collection.aggregate([
        {"$sample": {"size": min(reads, count)}}, {"$project": {"_id": 1}},
    ])]
    if not ids:
        raise RuntimeError("No random-read sample could be selected.")
    import random
    started = time.perf_counter()
    for index in range(reads):
        collection.find_one({"_id": random.choice(ids)})
    elapsed_ms = (time.perf_counter() - started) * 1000
    after = cache_snapshot(database)
    requested = (
        after["pages_requested"] - before["pages_requested"]
        if after["pages_requested"] is not None and before["pages_requested"] is not None
        else None
    )
    pages_read = (
        after["pages_read"] - before["pages_read"]
        if after["pages_read"] is not None and before["pages_read"] is not None
        else None
    )
    ratio = 1 - pages_read / requested if requested else None
    return {
        "reads": reads,
        "elapsed_ms": round(elapsed_ms, 3),
        "average_read_ms": round(elapsed_ms / reads, 5),
        "pages_requested_delta": requested,
        "pages_read_delta": pages_read,
        "hit_ratio": round(max(0, min(1, ratio)), 6) if ratio is not None else None,
        "cache_after": after,
    }


def ch72():
    _, database = mongo()
    size = make_working_set(database)
    rounds = []
    original = cache_snapshot(database)
    original_capacity = original.get("maximum_bytes")
    if not original_capacity:
        raise RuntimeError("WiredTiger did not report its configured cache size.")
    restore_setting = f"{max(1, round(original_capacity / (1024 * 1024)))}M"
    try:
        configure_cache(database, "256M")
        for round_number in range(1, 4):
            result = random_read_round(database, 1000)
            result["round"] = round_number
            rounds.append(result)
            ratio = result["hit_ratio"]
            print(
                f"Round {round_number}: {result['reads']} random reads in "
                f"{result['elapsed_ms']} ms; hit ratio "
                f"{ratio * 100:.2f}%" if ratio is not None else
                f"Round {round_number}: cache hit ratio unavailable"
            )
    finally:
        configure_cache(database, restore_setting)
        print(
            f"Restored WiredTiger runtime cache (reported original capacity "
            f"{original.get('maximum_bytes')} bytes)."
        )
    return {
        "collection": "lab_ch72_working_set",
        "document_size_check": size,
        "cache_before": original,
        "cache_restored_to": restore_setting,
        "random_read_rounds": rounds,
        "working_set_isolated_from_cti_data": True,
    }


def ch72_try():
    _, database = mongo()
    if database["lab_ch72_working_set"].count_documents({}) != 100_000:
        raise RuntimeError("Run 7.2 first; expected 100,000 lab_ch72_working_set documents.")
    duration = int(os.getenv("LAB_MONITOR_SECONDS", "30"))
    stop = threading.Event()
    errors = []
    reads_done = [0]

    def load_reads():
        import random
        collection = database["lab_ch72_working_set"]
        while not stop.is_set():
            try:
                row = collection.aggregate([
                    {"$sample": {"size": 500}}, {"$project": {"_id": 1}},
                ])
                ids = [item["_id"] for item in row]
                for _ in range(500):
                    if stop.is_set():
                        break
                    collection.find_one({"_id": random.choice(ids)})
                    reads_done[0] += 1
            except Exception as error:
                errors.append(str(error))
                stop.set()

    worker = threading.Thread(target=load_reads, daemon=True)
    worker.start()
    samples = []
    started = time.monotonic()
    try:
        while time.monotonic() - started < duration:
            time.sleep(min(10, max(0, duration - (time.monotonic() - started))))
            if stop.is_set():
                break
            sample = cache_snapshot(database)
            sample["elapsed_seconds"] = round(time.monotonic() - started, 1)
            samples.append(sample)
            print(
                f"Cache sample at {sample['elapsed_seconds']}s: "
                f"current={sample['current_bytes']} bytes; "
                f"pages_read={sample['pages_read']}; "
                f"reads completed={reads_done[0]}"
            )
    except KeyboardInterrupt:
        print("Stopping cache observer and background reads...")
    finally:
        stop.set()
        worker.join(timeout=15)
    if errors:
        raise RuntimeError("Background cache reads failed: " + errors[0])
    return {
        "duration_seconds": round(time.monotonic() - started, 1),
        "sampling_interval_seconds": 10,
        "reads_completed": reads_done[0],
        "samples": samples,
    }


def status_details(database):
    return database.command("replSetGetStatus")


def ch81():
    _, database = mongo()
    primary = wait_for_primary()
    check = database["lab_ch81_replication_check"]
    result = check.insert_one({
        "created_at": datetime.now(timezone.utc),
        "source": "Lab 8.1 primary replication check",
    })
    verified = {}
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        for host in MEMBERS:
            member_host = host.split(":")[0]
            try:
                with direct_client(host) as direct:
                    hello = direct.admin.command("hello")
                    document = direct[DATABASE_NAME]["lab_ch81_replication_check"].find_one(
                        {"_id": result.inserted_id},
                        {"_id": 1, "source": 1},
                    )
                    verified[member_host] = {
                        "state": "PRIMARY" if hello.get("isWritablePrimary") else "SECONDARY",
                        "has_document": document is not None,
                    }
            except Exception as error:
                verified[member_host] = {"state": "UNREACHABLE", "error": str(error)}
        if len(verified) == len(MEMBERS) and all(
            member.get("has_document") for member in verified.values()
        ):
            break
        time.sleep(1)
    print(f"Inserted test document on primary {primary}; member checks: {verified}")
    if not all(member.get("has_document") for member in verified.values()):
        raise RuntimeError(
            "The replication marker did not reach every configured data-bearing member "
            "within 20 seconds."
        )
    report = status_details(database)
    return {
        "primary": primary,
        "inserted_id": str(result.inserted_id),
        "member_reads": verified,
        "replica_members": [
            {"name": member.get("name"), "state": member.get("stateStr"), "health": member.get("health")}
            for member in report.get("members", [])
        ],
    }


def docker_client():
    import docker

    return docker.from_env()


def docker_network_for_container(docker_api, container):
    network_names = list((container.attrs.get("NetworkSettings", {}).get("Networks") or {}).keys())
    for name in network_names:
        try:
            return docker_api.networks.get(name)
        except docker.errors.NotFound:
            continue
    raise RuntimeError(f"Container {container.name} is not attached to a Docker network.")


def ensure_arbiter_container():
    import docker

    api = docker_client()
    try:
        arbiter = api.containers.get("cti-mongo-arbiter")
        if arbiter.status != "running":
            arbiter.start()
        return api, arbiter
    except docker.errors.NotFound:
        mongo1 = api.containers.get("mongo1")
        network = docker_network_for_container(api, mongo1)
        arbiter = api.containers.run(
            "mongo:7.0",
            command=["mongod", "--replSet", "rs0", "--bind_ip_all", "--wiredTigerCacheSizeGB", "1"],
            name="cti-mongo-arbiter",
            detach=True,
            labels={"mongodb-labs.managed": "true"},
            network=network.name,
        )
        try:
            network.connect(arbiter, aliases=["mongo-arbiter"])
        except docker.errors.APIError as error:
            if "already exists" not in str(error).lower():
                raise
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                with direct_client("mongo-arbiter:27017") as client:
                    client.admin.command("ping")
                return api, arbiter
            except Exception:
                time.sleep(2)
        raise RuntimeError("New arbiter container did not become reachable.")


def add_arbiter():
    from pymongo.errors import OperationFailure

    api, arbiter = ensure_arbiter_container()
    _, database = mongo()
    config = database.admin.command("replSetGetConfig")["config"]
    if any(member.get("host") == "mongo-arbiter:27017" for member in config["members"]):
        print("Arbiter is already in rs0.")
        return {"arbiter": "mongo-arbiter:27017", "already_configured": True}
    config["version"] += 1
    next_id = max(member["_id"] for member in config["members"]) + 1
    config["members"].append({
        "_id": next_id,
        "host": "mongo-arbiter:27017",
        "arbiterOnly": True,
        "priority": 0,
        "votes": 1,
    })
    try:
        database.admin.command({"replSetReconfig": config})
    except OperationFailure as error:
        raise RuntimeError(f"Could not add arbiter to rs0: {error}") from error
    print("Added mongo-arbiter:27017. An arbiter votes but stores no replicated data.")
    print(
        "Note: rs0 already has three voting data-bearing members. Adding a fourth "
        "member makes four voters; an arbiter is most useful to break a tie in a "
        "two-data-member set, not to improve this already-odd three-member set."
    )
    return {
        "arbiter": "mongo-arbiter:27017",
        "container": arbiter.name,
        "member_count": len(config["members"]),
        "voter_count": sum(member.get("votes", 1) for member in config["members"]),
        "explanation": "Arbiters vote in elections but do not replicate or store data.",
        "caveat": "Three data-bearing voters are already odd; the fourth voter changes this to an even count.",
    }


def reset_replica_set():
    import docker

    _, database = mongo()
    changed = False
    try:
        original = database.admin.command("replSetGetConfig")["config"]
        config = original.copy()
        config["members"] = [dict(member) for member in original["members"]]
        config["members"] = [
            member for member in config["members"]
            if member.get("host") != "mongo-arbiter:27017"
        ]
        for member in config["members"]:
            member["priority"] = 1
            member.pop("tags", None)
        changed = (
            len(config["members"]) != len(original["members"])
            or any(
                original_member.get("priority", 1) != 1
                or original_member.get("tags")
                for original_member in original["members"]
                if original_member.get("host") != "mongo-arbiter:27017"
            )
        )
        if changed:
            config["version"] += 1
            database.admin.command({"replSetReconfig": config})
    except Exception as error:
        raise RuntimeError(f"Could not reset replica-set configuration: {error}") from error

    primary = wait_for_primary(timeout=30)
    try:
        api = docker_client()
        try:
            arbiter = api.containers.get("cti-mongo-arbiter")
            arbiter.remove(force=True)
        except docker.errors.NotFound:
            pass
    except Exception as error:
        raise RuntimeError(f"Reset config succeeded but arbiter container cleanup failed: {error}") from error
    print("rs0 reset: arbiter removed from configuration and all priorities set to 1.")
    return {"reset": True, "configuration_changed": changed, "primary": primary}


def observe_failover(database, seconds=15):
    samples = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            hello = database.client.admin.command("hello")
            document = database["lab_ch82_read_observer"].find_one(
                {"_id": "observer"}, {"_id": 1}
            )
            samples.append({
                "time": datetime.now(timezone.utc).isoformat(),
                "primary": hello.get("primary"),
                "connected_member": hello.get("me"),
                "is_primary": hello.get("isWritablePrimary", False),
                "read_succeeded": document is not None,
                "error": None,
            })
        except Exception as error:
            samples.append({
                "time": datetime.now(timezone.utc).isoformat(),
                "primary": None,
                "connected_member": None,
                "is_primary": False,
                "read_succeeded": False,
                "error": str(error),
            })
        time.sleep(1)
    return samples


def force_stepdown(database, seconds=10):
    from pymongo.errors import PyMongoError

    try:
        database.client.admin.command({"replSetStepDown": seconds, "force": True})
        return {"command_returned": True, "note": "stepDown returned normally"}
    except PyMongoError as error:
        print(f"Primary connection changed during stepDown (expected): {error}")
        return {"command_returned": False, "expected_connection_change": str(error)}


def ch82():
    _, database = mongo()
    database["lab_ch82_read_observer"].update_one(
        {"_id": "observer"},
        {"$set": {"updated_at": datetime.now(timezone.utc)}},
        upsert=True,
    )
    before = status()
    print("Sampling primary selection while issuing stepDown...")
    step_result = force_stepdown(database, 10)
    samples = observe_failover(database, 15)
    after = status()
    return {
        "primary_before": before.get("primary"),
        "stepdown": step_result,
        "observer_samples": samples,
        "primary_after": after.get("primary"),
    }


def set_priorities_and_stepdown():
    _, database = mongo()
    config = database.admin.command("replSetGetConfig")["config"]
    current_primary = status().get("primary")
    secondaries = [
        member for member in config["members"]
        if not member.get("arbiterOnly") and member["host"] != current_primary
    ]
    if len(secondaries) < 2:
        raise RuntimeError("Priority experiment needs two data-bearing secondaries.")
    priority_by_host = {member["host"]: 1 for member in config["members"]}
    priority_by_host[secondaries[0]["host"]] = 3
    priority_by_host[secondaries[1]["host"]] = 2
    for member in config["members"]:
        if member.get("arbiterOnly"):
            member["priority"] = 0
        else:
            member["priority"] = priority_by_host[member["host"]]
    config["version"] += 1
    database.admin.command({"replSetReconfig": config})
    predicted = secondaries[0]["host"]
    print(
        f"Priority prediction: {predicted} has priority 3, above "
        f"{secondaries[1]['host']} (priority 2)."
    )
    time.sleep(5)
    step_result = force_stepdown(database, 10)
    samples = observe_failover(database, 15)
    actual = status().get("primary")
    return {
        "priorities": priority_by_host,
        "predicted_primary": predicted,
        "actual_primary": actual,
        "prediction_correct": actual == predicted,
        "stepdown": step_result,
        "observer_samples": samples,
    }


def latency_test(database, journal_values=(None,), test_label="9.1"):
    from pymongo import WriteConcern

    rows = []
    for concern_name, concern in (("w:1", 1), ("w:majority", "majority"), ("w:all (w:3)", 3)):
        for journal in journal_values:
            collection_name = (
                f"lab_{test_label.replace('.', '').replace('-', '_')}_"
                f"{concern_name.split()[0].replace(':', '')}_"
                f"{'default' if journal is None else 'jtrue' if journal else 'jfalse'}"
            )
            collection = database[collection_name]
            collection.drop()
            options = {"w": concern, "wtimeout": 15000}
            if journal is not None:
                options["j"] = journal
            guarded = collection.with_options(write_concern=WriteConcern(**options))
            start = time.perf_counter()
            completed = 0
            error_text = None
            for index in range(1000):
                try:
                    guarded.insert_one({
                        "_id": index,
                        "sequence": index,
                        "created_at": datetime.now(timezone.utc),
                        "payload": "cti-write-concern-benchmark",
                    })
                    completed += 1
                except Exception as error:
                    error_text = str(error)
                    break
            elapsed_ms = (time.perf_counter() - start) * 1000
            row = {
                "write_concern": concern_name,
                "journal": journal,
                "completed_writes": completed,
                "total_writes": 1000,
                "elapsed_ms": round(elapsed_ms, 3),
                "average_latency_ms": round(elapsed_ms / completed, 5) if completed else None,
                "collection": collection_name,
                "error": error_text,
            }
            rows.append(row)
            print(
                f"{concern_name}, j={journal}: {completed}/1000 writes; "
                f"{elapsed_ms:.2f}ms total; {row['average_latency_ms']}ms/write"
            )
    return {
        "results": rows,
        "all_members_note": "MongoDB uses w:3 here for all three data-bearing members; literal w:'all' is not a built-in replica-set write concern.",
        "journal_note": "j:true requests journal acknowledgment; j:false does not request it explicitly.",
    }


def ch91(with_journal=False):
    _, database = mongo()
    if with_journal:
        return latency_test(database, (False, True), "9.1-try")
    return latency_test(database, (None,), "9.1")


def partition_write(database, write_concern):
    from pymongo import WriteConcern

    collection = database["lab_ch92_partition_writes"].with_options(
        write_concern=WriteConcern(w=write_concern, wtimeout=5000)
    )
    key = f"{write_concern}-{time.time_ns()}"
    try:
        result = collection.insert_one({
            "_id": key,
            "write_concern": write_concern,
            "written_at": datetime.now(timezone.utc),
        })
        return {"write_concern": write_concern, "acknowledged": result.acknowledged, "id": key}
    except Exception as error:
        return {"write_concern": write_concern, "acknowledged": False, "error": str(error), "id": key}


def ch92():
    import docker

    _, database = mongo()
    api = docker_client()
    network = api.networks.get("mongodb-labs-net")
    connected = []
    partition_timeline = []
    writes = []
    observer = []
    try:
        primary_name = (status().get("primary") or "").split(":")[0]
        if not primary_name:
            raise RuntimeError("Cannot partition secondaries while rs0 has no primary.")
        data_members = ("mongo1", "mongo2", "mongo3")
        first_secondary = next(name for name in data_members if name != primary_name)
        for name in (first_secondary,):
            container = api.containers.get(name)
            network.disconnect(container)
            connected.append(container)
            partition_timeline.append({
                "at": datetime.now(timezone.utc).isoformat(),
                "action": "disconnected one secondary",
                "container": name,
            })
        print("One secondary partitioned for 30 seconds. Testing w:1 and w:majority...")
        writes.append(partition_write(database, 1))
        writes.append(partition_write(database, "majority"))
        observer = []
        started = time.monotonic()
        while time.monotonic() - started < 30:
            try:
                replica_status = database.admin.command("replSetGetStatus")
                observer.append({
                    "at": datetime.now(timezone.utc).isoformat(),
                    "primary": next(
                        (member.get("name") for member in replica_status.get("members", [])
                         if member.get("stateStr") == "PRIMARY"),
                        None,
                    ),
                    "members": [
                        {"name": member.get("name"), "state": member.get("stateStr"),
                         "health": member.get("health")}
                        for member in replica_status.get("members", [])
                    ],
                })
            except Exception as error:
                observer.append({"at": datetime.now(timezone.utc).isoformat(), "error": str(error)})
            time.sleep(3)
        network.connect(connected[0], aliases=["mongo2"])
        partition_timeline.append({
            "at": datetime.now(timezone.utc).isoformat(),
            "action": "reconnected one secondary",
            "container": connected[0].name,
        })
        connected.clear()
        time.sleep(5)

        # Isolate both secondaries briefly to show the difference between w:1 and majority.
        current_primary = (status().get("primary") or "").split(":")[0]
        if not current_primary:
            raise RuntimeError("No primary after reconnecting the first secondary.")
        remaining_secondaries = [
            name for name in data_members if name != current_primary
        ]
        for name in remaining_secondaries:
            container = api.containers.get(name)
            network.disconnect(container)
            connected.append(container)
        partition_timeline.append({
            "at": datetime.now(timezone.utc).isoformat(),
            "action": "disconnected both secondaries",
            "containers": [container.name for container in connected],
        })
        writes.append(partition_write(database, 1))
        writes.append(partition_write(database, "majority"))
        time.sleep(5)
    finally:
        for container in connected:
            try:
                network.connect(container, aliases=[container.name])
            except docker.errors.APIError as error:
                if "already exists" not in str(error).lower():
                    print(f"Warning: could not reconnect {container.name}: {error}", file=sys.stderr)
        print("Partition cleanup complete; secondaries have been reconnected.")
    try:
        wait_for_primary(timeout=30)
        survivors = {
            row["id"]: bool(
                database["lab_ch92_partition_writes"].find_one(
                    {"_id": row["id"]}, {"_id": 1}
                )
            )
            for row in writes
        }
    except Exception as error:
        survivors = {"verification_error": str(error)}
    return {
        "timeline": partition_timeline,
        "writes": writes,
        "surviving_write_ids": survivors,
        "observer_samples": observer,
        "cleanup": "All intentionally disconnected secondaries were reconnected in finally.",
        "interpretation": (
            "With one of three data-bearing members isolated, primary+w:1 and "
            "majority writes can still succeed via the other secondary. With both "
            "secondaries isolated, w:1 may succeed while majority times out."
        ),
    }


def run_one(lab):
    if lab == "setup":
        return setup_database()
    if lab == "status":
        return standalone_status()
    if lab == "reset":
        return {
            "deployment": "standalone",
            "message": "No replica-set configuration to reset. Lab collections are isolated; MongoDB data was left unchanged.",
        }
    if lab == "7-load":
        return load_ch7_backup()
    if lab == "7-status":
        return status_ch7()
    if lab == "7.1":
        return ch71_analysis()
    if lab == "7.1-try":
        return ch71_try()
    if lab == "7.2":
        return ch72()
    if lab == "7.2-try":
        return ch72_try()
    if lab == "8.1":
        return chapter8_schema_inventory()
    if lab == "8.1-try":
        return chapter8_query_benchmark()
    if lab == "8.2":
        return chapter8_relationship_check()
    if lab == "8.2-try":
        return chapter8_query_plan()
    if lab == "9.1":
        return chapter9_write_benchmark((False,))
    if lab == "9.1-try":
        return chapter9_write_benchmark((False, True))
    if lab == "9.2":
        return chapter9_data_audit()
    if lab == "10.1":
        return chapter10_transfer_demo(retry_attempts=1)
    if lab == "10.1-try":
        return chapter10_transfer_demo(retry_attempts=5)
    if lab == "10.2":
        return chapter10_inventory_demo(retry_attempts=8)
    if lab == "10.2-try":
        return chapter10_inventory_demo(retry_attempts=10)
    if lab == "11.1":
        return chapter11_shard_key_evaluation()
    if lab == "11.1-try":
        return chapter11_resharding_activity()
    if lab == "11.2":
        return chapter11_hotspot_demo()
    if lab == "12.1":
        return chapter12_rbac_setup()
    if lab == "12.1-try":
        return chapter12_rbac_verification()
    if lab == "12.2":
        return chapter12_tls_setup()
    if lab == "12.2-try":
        return chapter12_tls_verification()
    if lab == "12.3":
        return chapter12_field_redaction()
    # ── Chapter 13 ───────────────────────────────────────────────────────────
    if lab == "13.1":
        return chapter13_replica_set()
    if lab == "13.2":
        return chapter13_kubernetes()
    if lab == "results":
        files = sorted(path.name for path in RESULTS.glob("*.json"))
        for name in files:
            print(name)
        return {"files": files}
    raise ValueError(f"Unsupported lab command: {lab}")


# ── Chapter 13 helper functions ───────────────────────────────────────────────

def chapter13_replica_set():
    """Lab 13.1: 3-Node Replica Set with Docker Compose & KeyFile Auth."""
    import importlib.util, time
    spec = importlib.util.spec_from_file_location(
        "lab13_cloud",
        str(BACKEND / "scripts" / "lab13_cloud.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.run_lab13_1()


def chapter13_kubernetes():
    """Lab 13.2: Kubernetes StatefulSet for MongoDB."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "lab13_cloud",
        str(BACKEND / "scripts" / "lab13_cloud.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.run_lab13_2()


def run_group(name, labs):
    outputs = {}
    for lab in labs:
        print(f"\n{'=' * 70}\nRunning {lab}\n{'=' * 70}")
        outputs[lab] = run_one(lab)
        save_result(lab, outputs[lab])
    return {"group": name, "experiments": outputs}


def save_result(lab, result):
    timestamp = now_stamp()
    record = {
        "lab": lab,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "result": result,
    }
    latest = RESULTS / f"{lab}.json"
    history = RESULTS / f"{lab}-{timestamp}.json"
    for path in (latest, history):
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(record, indent=2, default=str, ensure_ascii=False),
            encoding="utf-8",
        )
        temporary.replace(path)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "setup", "status", "reset", "7-load", "7-status",
            *LABS, "7-all", "8-all", "9-all", "10-all", "11-all", "12-all", "13-all",
            "all", "results", "compose",
        ),
    )
    args = parser.parse_args()
    command = args.command
    allowed_chapters = os.getenv("LAB_ALLOWED_CHAPTERS")
    if allowed_chapters:
        allowed = set(allowed_chapters.split(","))
        command_chapter = (
            "7" if command in ("7-load", "7-status", "7-all")
            else "8" if command == "8-all"
            else "9" if command == "9-all"
            else "10" if command == "10-all"
            else "11" if command == "11-all"
            else "12" if command == "12-all"
            else "13" if command == "13-all"
            else command.split(".", 1)[0] if command in LABS
            else None
        )
        if "all" not in allowed and command_chapter and command_chapter not in allowed:
            parser.error(
                f"Command {command} is not enabled in the Chapter "
                f"{allowed_chapters} runner."
            )
    if command == "compose":
        print((ROOT / "docker-compose.yml").read_text(encoding="utf-8"), end="")
        return 0
    stamp = now_stamp()
    safe_command = command.replace(".", "").replace("-", "_")
    log_path = OUTPUT / f"{safe_command}-{stamp}.log"
    command_log_path = OUTPUT / f"{safe_command}-{stamp}-commands.jsonl"
    os.environ["MONGO_COMMAND_LOG"] = str(command_log_path)
    command_log_path.touch(exist_ok=True)
    with log_path.open("a", encoding="utf-8") as logfile:
        original_stdout, original_stderr = sys.stdout, sys.stderr
        sys.stdout = Tee(original_stdout, logfile)
        sys.stderr = Tee(original_stderr, logfile)
        try:
            if command == "7-all":
                result = run_group(command, ("7.1", "7.1-try", "7.2", "7.2-try"))
            elif command == "8-all":
                result = run_group(command, ("8.1", "8.1-try", "8.2", "8.2-try"))
            elif command == "9-all":
                result = run_group(command, ("9.1", "9.1-try", "9.2"))
            elif command == "10-all":
                result = run_group(command, ("10.1", "10.1-try", "10.2", "10.2-try"))
            elif command == "11-all":
                result = run_group(command, ("11.1", "11.1-try", "11.2"))
            elif command == "12-all":
                result = run_group(command, ("12.1", "12.1-try", "12.2", "12.2-try", "12.3"))
            elif command == "13-all":
                result = run_group(command, ("13.1", "13.2"))
            elif command == "all":
                first = run_group("7-all", ("7.1", "7.1-try", "7.2", "7.2-try"))
                second = run_group("8-all", ("8.1", "8.1-try", "8.2", "8.2-try"))
                third = run_group("9-all", ("9.1", "9.1-try", "9.2"))
                fourth = run_group("10-all", ("10.1", "10.1-try", "10.2", "10.2-try"))
                fifth = run_group("11-all", ("11.1", "11.1-try", "11.2"))
                sixth = run_group("12-all", ("12.1", "12.1-try", "12.2", "12.2-try", "12.3"))
                result = {"groups": [first, second, third, fourth, fifth, sixth]}
            else:
                result = run_one(command)
            if command not in ("compose", "results"):
                record = save_result(command, result)
                print(json.dumps(record, indent=2, default=str, ensure_ascii=False))
            print(f"\nSaved console output: {log_path}")
            print(f"Saved MongoDB commands/replies: {command_log_path}")
            print(f"Frontend: http://localhost:8000/experiment.html?lab={command}")
            return 0
        except KeyboardInterrupt:
            print("\nInterrupted by Ctrl+C; experiment cleanup has run where required.")
            return 130
        except Exception as error:
            print(f"ERROR: {error}", file=sys.stderr)
            traceback.print_exc()
            return 1
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr


if __name__ == "__main__":
    raise SystemExit(main())
