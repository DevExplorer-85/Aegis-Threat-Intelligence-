"""Shard-key evaluation and live sharding demonstrations for Chapter 11."""

import hashlib
import json
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from pymongo import MongoClient


RESHARDING_STEPS = [
    "Review workload patterns, choose the new shard key, and confirm the application can tolerate increased latency and a brief write-blocking period.",
    "Check cluster health, available disk on every recipient shard, CPU and I/O headroom, active index builds, and unique-index compatibility.",
    "Run the reshardCollection command against one collection at a time; MongoDB builds the new shard-key index and copies data while tracking ongoing writes.",
    "Monitor resharding progress and resource use, then verify the new key, chunk placement, and application query plans after completion.",
    "Keep a recovery plan: resharding is resource-intensive, can grow the oplog, and should be scheduled for a lower-traffic window.",
]

RESHARDING_LIMITATIONS = [
    "Only one collection can be resharded at a time.",
    "Applications must tolerate a short write-blocking period (currently documented as about two seconds) and increased latency during the operation.",
    "Each recipient shard needs free space of at least twice the collection data plus index size, divided by the shard count; insufficient resources can degrade service or exhaust disk.",
    "CPU and I/O headroom are operational requirements; MongoDB recommends keeping CPU below 80% and I/O below 50% during planning.",
    "Existing unique indexes must satisfy the new shard-key prefix requirements.",
    "Resharding increases write and oplog load. Search indexes and certain commands on the collection may be unavailable or restricted during the operation.",
    "MongoDB 8.0 added same-key resharding for redistribution using forceRedistribution; time-series resharding requires MongoDB 8.0.10 or later.",
]


def evaluate_shard_keys():
    return {
        "workload": (
            "E-commerce orders with customer-scoped lookups, order-ID lookups, "
            "and time-based reporting."
        ),
        "concepts": [
            {
                "property": "Cardinality",
                "meaning": (
                    "The number of distinct shard-key values. Low cardinality "
                    "limits useful partitioning; a hot value cannot be split "
                    "across shards by that key alone."
                ),
            },
            {
                "property": "Distribution",
                "meaning": (
                    "How evenly documents and write load map to key values and "
                    "shards. High cardinality does not prevent skew from very "
                    "popular customers or categories."
                ),
            },
            {
                "property": "Query targeting",
                "meaning": (
                    "Queries containing the shard key can target relevant "
                    "shards; queries without it may scatter to every shard."
                ),
            },
            {
                "property": "Monotonicity",
                "meaning": (
                    "A steadily increasing range key places new writes in the "
                    "highest-key chunk, creating a write hotspot."
                ),
            },
        ],
        "prediction_prompt": (
            "Before reading the matrix, predict each candidate's verdict and "
            "identify which of the four properties is decisive."
        ),
        "decision_matrix": [
            {
                "candidate": "user_id / customer_id (hashed)",
                "key_pattern": {"user_id": "hashed"},
                "cardinality": "High when user IDs are distinct",
                "distribution": (
                    "Hashing distinct user IDs spreads key values; uneven order "
                    "volume per user can still make load skewed."
                ),
                "query_targeting": (
                    "Targets equality lookups by user_id; ranges on user_id "
                    "cannot use contiguous hashed-key ranges."
                ),
                "monotonicity": "Hashing removes insertion-order monotonicity.",
                "hotspot_risk": (
                    "Low for sequential user IDs; a single high-volume user "
                    "still maps to one shard."
                ),
                "verdict": (
                    "Recommended when user-scoped equality queries dominate "
                    "and activity skew is acceptable."
                ),
            },
            {
                "candidate": "order_id (hashed)",
                "key_pattern": {"order_id": "hashed"},
                "cardinality": "High when order IDs are unique",
                "distribution": (
                    "Hashing distributes distinct IDs, including sequential "
                    "IDs, across the hashed key space."
                ),
                "query_targeting": (
                    "Targets equality lookups by order_id; customer-scoped "
                    "queries scatter."
                ),
                "monotonicity": "Hashing removes insertion-order monotonicity.",
                "hotspot_risk": (
                    "Low for unique IDs; does not colocate a customer's orders."
                ),
                "verdict": (
                    "Good when order-ID lookups dominate; weak for "
                    "customer-scoped access."
                ),
            },
            {
                "candidate": "category_id",
                "key_pattern": {"category_id": 1},
                "cardinality": "Low when the catalog has few categories",
                "distribution": (
                    "Usually uneven because categories have different order "
                    "volumes; one category's values cannot be split by this key."
                ),
                "query_targeting": (
                    "Targets category queries, but queries by order, customer, "
                    "or date scatter."
                ),
                "monotonicity": "Not inherently monotonic.",
                "hotspot_risk": (
                    "High when cardinality is low or category popularity is skewed."
                ),
                "verdict": (
                    "Avoid as a sole key when there are few or unevenly used "
                    "categories."
                ),
            },
            {
                "candidate": "created_at (range)",
                "key_pattern": {"created_at": 1},
                "cardinality": "High",
                "distribution": (
                    "Historical values span the range, but new inserts always "
                    "arrive at the highest end."
                ),
                "query_targeting": (
                    "Good for time-range reports; customer and order-ID queries "
                    "scatter."
                ),
                "monotonicity": "Monotonically increasing for new orders.",
                "hotspot_risk": (
                    "High for insert-heavy workloads while the active chunk "
                    "receives new writes."
                ),
                "verdict": (
                    "Avoid as a sole key for insert-heavy workloads; use a "
                    "different key or a suitable compound design."
                ),
            },
            {
                "candidate": "order_id (range)",
                "key_pattern": {"order_id": 1},
                "cardinality": "High",
                "distribution": (
                    "Can distribute historical ranges, but sequential order IDs "
                    "concentrate new inserts at the high end."
                ),
                "query_targeting": "Good for order-ID lookups; customer queries scatter.",
                "monotonicity": "Monotonic if order IDs are sequential.",
                "hotspot_risk": "High for sequential ID generation.",
                "verdict": (
                    "Good targeting only if IDs are non-monotonic; otherwise "
                    "avoid for insert-heavy workloads."
                ),
            },
            {
                "candidate": "customer_id (range)",
                "key_pattern": {"customer_id": 1},
                "cardinality": "Usually high",
                "distribution": (
                    "Skewed if some customers generate many more orders; a hot "
                    "customer remains one shard-key value."
                ),
                "query_targeting": "Good for customer equality and customer-scoped ranges.",
                "monotonicity": "Depends on customer-ID generation.",
                "hotspot_risk": "Medium to high for highly active customers.",
                "verdict": (
                    "Customer targeting is good, but validate customer-activity "
                    "skew and ID monotonicity."
                ),
            },
            {
                "candidate": "order_date (range)",
                "key_pattern": {"order_date": 1},
                "cardinality": "High",
                "distribution": (
                    "Historical dates span the range; current writes accumulate "
                    "at the latest date."
                ),
                "query_targeting": "Good for date-range reports; customer queries scatter.",
                "monotonicity": "Monotonically increasing for new orders.",
                "hotspot_risk": "High for insert-heavy workloads.",
                "verdict": "Avoid as a sole key for insert-heavy workloads.",
            },
        ],
        "recommendation": (
            "A hashed user/customer identifier is a strong starting point when "
            "equality lookups by that identifier dominate. Validate real query "
            "frequency, value cardinality, and activity skew: hashing distributes "
            "distinct key values, but does not split one hot value. If order-ID "
            "lookups dominate, hashed order_id may fit better; if date ranges "
            "dominate, test an appropriate compound key rather than assuming a "
            "monotonic date range will scale writes."
        ),
        "additional_properties": [
            "Non-monotonicity is assessed separately from cardinality and distribution: a date field can have high cardinality and still hotspot new writes.",
            "The best key depends on the real workload; a shard key is not a universal ranking.",
        ],
        "resharding": {
            "documented_for_mongodb": "5.0 and later",
            "steps": RESHARDING_STEPS,
            "limitations": RESHARDING_LIMITATIONS,
            "documentation": "https://www.mongodb.com/docs/manual/core/sharding-reshard-a-collection/",
        },
    }


def _simulated_bucket(value, bucket_count):
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % bucket_count


def simulate_hotspot_distribution(document_count=10_000, shard_count=5):
    if not isinstance(document_count, int) or isinstance(document_count, bool) or document_count < 1:
        raise ValueError("document_count must be a positive integer")
    if not isinstance(shard_count, int) or isinstance(shard_count, bool) or shard_count < 2:
        raise ValueError("shard_count must be an integer of at least 2")

    monotonic = [0] * shard_count
    hashed = [0] * shard_count
    timestamp_origin = datetime(2025, 1, 1, tzinfo=timezone.utc)
    for sequence in range(document_count):
        timestamp_key = (
            timestamp_origin + timedelta(milliseconds=sequence)
        ).isoformat(timespec="microseconds")
        monotonic[-1] += 1
        hashed[_simulated_bucket(timestamp_key, shard_count)] += 1

    def summary(counts):
        return {
            "shard_counts": [
                {"shard": f"shard{index + 1}", "documents": count}
                for index, count in enumerate(counts)
            ],
            "max_shard_share_percent": round(max(counts) / document_count * 100, 2),
        }

    return {
        "mode": "deterministic_bucket_simulation",
        "simulated": True,
        "documents": document_count,
        "shard_count": shard_count,
        "candidate_key": "the same monotonically increasing timestamp values",
        "hashing": "SHA-256 modulo bucket count (educational proxy)",
        "monotonic_range_key": summary(monotonic),
        "hashed_same_timestamp_key": summary(hashed),
        "note": (
            "This deterministic bucket model sends an increasing range key to "
            "the current high-end bucket and hashes those same timestamp values "
            "with SHA-256 for comparison. This educational mapping is not "
            "MongoDB's hashed-index algorithm, chunk map, balancer, collStats, "
            "or explain behavior."
        ),
    }


def _shards_in_explain(document):
    names = set()
    if isinstance(document, dict):
        shard_name = document.get("shardName")
        if isinstance(shard_name, str):
            names.add(shard_name)
        shards = document.get("shards")
        if isinstance(shards, dict):
            names.update(shards.keys())
        for value in document.values():
            names.update(_shards_in_explain(value))
    elif isinstance(document, list):
        for value in document:
            names.update(_shards_in_explain(value))
    return sorted(names)


def _per_shard_counts(database, collection_name):
    result = database.command("collStats", collection_name)
    shard_stats = result.get("shards", {})
    if not shard_stats:
        raise RuntimeError(
            f"collStats for {collection_name!r} did not return per-shard statistics."
        )
    return [
        {
            "shard": shard_name,
            "documents": stats.get("count", 0),
            "size_bytes": stats.get("size", 0),
        }
        for shard_name, stats in sorted(shard_stats.items())
    ]


def _explain(database, collection_name, query, total_shard_count):
    result = database.command(
        "explain",
        {"find": collection_name, "filter": query},
        verbosity="executionStats",
    )
    plan = result.get("queryPlanner", {}).get("winningPlan", {})
    shards = _shards_in_explain(plan)
    if not shards:
        shards = _shards_in_explain(result.get("executionStats", {}))
    if not shards:
        raise RuntimeError(
            f"Explain for {collection_name!r} did not identify participating shards."
        )
    return {
        "targeted_shards": shards,
        "targeted_shard_count": len(shards),
        "total_shard_count": total_shard_count,
        "n_returned": result.get("executionStats", {}).get("nReturned"),
        "total_docs_examined": result.get("executionStats", {}).get("totalDocsExamined"),
        "winning_plan": plan,
    }


def run_hotspot_demo(uri, document_count=10_000, shard_count=2):
    if not isinstance(uri, str) or not uri:
        raise ValueError("A mongos connection URI is required.")
    if not isinstance(document_count, int) or isinstance(document_count, bool) or document_count < 1:
        raise ValueError("document_count must be a positive integer.")
    if shard_count != 2:
        raise ValueError("The live Chapter 11 demo requires exactly two shards.")

    database_name = "lab11_sharding"
    timestamp_name = "lab11_timestamp"
    hashed_name = "lab11_hashed_customer"
    with MongoClient(
        uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        retryWrites=False,
    ) as client:
        hello = client.admin.command("hello")
        if hello.get("msg") != "isdbgrid":
            raise RuntimeError(
                "Lab 11.2 requires a mongos router; the configured server is not mongos."
            )
        shards = client.admin.command("listShards").get("shards", [])
        if len(shards) < shard_count:
            raise RuntimeError(
                f"Lab 11.2 requires {shard_count} shards; found {len(shards)}."
            )

        database = client[database_name]
        for name in (timestamp_name, hashed_name):
            database.drop_collection(name)
        client.admin.command("enableSharding", database_name)

        timestamp_collection = database[timestamp_name]
        hashed_collection = database[hashed_name]
        timestamp_collection.create_index("ts")
        hashed_collection.create_index([("user_id", "hashed")])
        client.admin.command(
            "shardCollection",
            f"{database_name}.{timestamp_name}",
            key={"ts": 1},
        )
        client.admin.command(
            "shardCollection",
            f"{database_name}.{hashed_name}",
            key={"user_id": "hashed"},
            numInitialChunks=shard_count,
        )

        started_at = datetime.now(timezone.utc)
        timestamp_documents = [
            {
                "_id": ObjectId(),
                "ts": started_at + timedelta(milliseconds=sequence),
                "sequence": sequence,
                "payload": f"order-{sequence}",
            }
            for sequence in range(document_count)
        ]
        hashed_documents = [
            {
                "_id": ObjectId(),
                "user_id": ObjectId(),
                "sequence": sequence,
                "payload": f"order-{sequence}",
            }
            for sequence in range(document_count)
        ]
        for offset in range(0, document_count, 1000):
            timestamp_collection.insert_many(
                timestamp_documents[offset:offset + 1000], ordered=True
            )
            hashed_collection.insert_many(
                hashed_documents[offset:offset + 1000], ordered=True
            )

        range_start = started_at + timedelta(milliseconds=document_count // 4)
        range_end = started_at + timedelta(milliseconds=(document_count * 3) // 4)
        timestamp_query = {"ts": {"$gte": range_start, "$lt": range_end}}
        hashed_values = [document["user_id"] for document in hashed_documents]
        hashed_query = {
            "user_id": {
                "$gte": min(hashed_values),
                "$lt": max(hashed_values),
            }
        }
        timestamp_explain = _explain(
            database, timestamp_name, timestamp_query, len(shards)
        )
        hashed_explain = _explain(
            database, hashed_name, hashed_query, len(shards)
        )
        timestamp_counts = _per_shard_counts(database, timestamp_name)
        hashed_counts = _per_shard_counts(database, hashed_name)

    return {
        "chapter": 11,
        "lab": "11.2",
        "mode": "live_sharded_cluster",
        "simulated": False,
        "database": database_name,
        "shards": [
            {"id": shard["_id"], "host": shard["host"]}
            for shard in shards
        ],
        "documents_per_collection": document_count,
        "bucket_simulation": simulate_hotspot_distribution(document_count),
        "timestamp_key": {
            "pattern": {"ts": 1},
            "per_shard": timestamp_counts,
            "range_query": timestamp_explain,
            "interpretation": (
                "A monotonically increasing range key directs new writes to the "
                "chunk containing the current maximum key."
            ),
        },
        "hashed_customer_key": {
            "pattern": {"user_id": "hashed"},
            "per_shard": hashed_counts,
            "range_query": hashed_explain,
            "interpretation": (
                "A range predicate on the original field of a hashed key cannot "
                "target a contiguous hashed-key range and normally scatters to "
                "the shards."
            ),
        },
        "report": (
            "Compare the measured per-shard counts and explain plans. Monotonic "
            "range keys concentrate writes at the active high-end chunk. Hashed "
            "keys improve distribution of distinct values but sacrifice efficient "
            "range targeting, and a single hot customer still maps to one shard."
        ),
        "collections": [timestamp_name, hashed_name],
    }


def format_decision_matrix(result):
    lines = [
        "Chapter 11.1 · Shard-key decision matrix",
        f"Workload: {result['workload']}",
        "",
    ]
    for concept in result["concepts"]:
        lines.append(f"{concept['property']}: {concept['meaning']}")
    lines.extend(["", result["prediction_prompt"], ""])
    for row in result["decision_matrix"]:
        lines.extend(
            [
                f"{row['candidate']} · {row['verdict']}",
                f"  Cardinality: {row['cardinality']}",
                f"  Distribution: {row['distribution']}",
                f"  Query targeting: {row['query_targeting']}",
                f"  Monotonicity: {row['monotonicity']}",
                f"  Hotspot risk: {row['hotspot_risk']}",
            ]
        )
    lines.extend(["", f"Recommendation: {result['recommendation']}", ""])
    return "\n".join(lines)


def format_hotspot_report(result):
    timestamp = result["timestamp_key"]
    hashed = result["hashed_customer_key"]
    simulation = result["bucket_simulation"]
    return "\n".join(
        [
            "Chapter 11.2 · Live shard-key hotspot results",
            f"MongoDB mode: {result['mode']}; simulated={result['simulated']}",
            f"Documents per collection: {result['documents_per_collection']}",
            f"Shards: {', '.join(shard['id'] for shard in result['shards'])}",
            "",
            "Timestamp range key per-shard counts:",
            json.dumps(timestamp["per_shard"], indent=2),
            f"Timestamp range query targeted: {timestamp['range_query']['targeted_shards']}",
            "",
            "Hashed customer key per-shard counts:",
            json.dumps(hashed["per_shard"], indent=2),
            f"Hashed-field range query targeted: {hashed['range_query']['targeted_shards']}",
            "",
            "Same-timestamp-key bucket simulation (instructional, not MongoDB stats):",
            "Raw increasing range key:",
            json.dumps(simulation["monotonic_range_key"]["shard_counts"], indent=2),
            "Hashed same timestamp values:",
            json.dumps(simulation["hashed_same_timestamp_key"]["shard_counts"], indent=2),
            simulation["note"],
            "",
            result["report"],
        ]
    )
