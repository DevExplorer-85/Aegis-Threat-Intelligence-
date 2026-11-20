import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import db

collection = db["working_set_test"]
reads_per_interval = 100
interval_seconds = 10

total_documents = collection.count_documents({})

print("===================================")
print("RANDOM READ / WORKING SET TEST")
print("===================================")
print("Collection        : working_set_test (Lab 7.2 directly fetched records)")
print("Source            : CIRCL, Botvrij.eu and ThreatFox MISP feeds")
print("Total Documents   :", f"{total_documents:,}")
print("Interval          :", interval_seconds, "seconds")
print("Press Ctrl+C to stop")
print("===================================")

if total_documents != 100_000:
    raise SystemExit(
        "Lab 7.2 requires exactly 100,000 source-backed records; run "
        "scripts.fetch_working_set first."
    )

read_count = 0
previous_counters = None

try:
    while True:
        start = time.perf_counter()

        sampled = list(collection.aggregate([
            {"$sample": {"size": min(total_documents, reads_per_interval)}},
            {"$project": {"_id": 1}},
        ]))
        random_ids = random.choices(
            [document["_id"] for document in sampled],
            k=reads_per_interval,
        )
        for random_id in random_ids:
            collection.find_one(
                {"_id": random_id},
                {
                    "_id": 1,
                    "event_uuid": 1,
                    "type": 1,
                    "value": 1,
                }
            )

            read_count += 1

        elapsed = time.perf_counter() - start
        cache = db.command("serverStatus").get("wiredTiger", {}).get("cache", {})
        requested = cache.get("pages requested from the cache")
        pages_read = cache.get("pages read into cache")
        hit_ratio = None

        if requested is not None and pages_read is not None:
            current_counters = (requested, pages_read)
            if previous_counters is not None:
                requested_delta = requested - previous_counters[0]
                pages_read_delta = pages_read - previous_counters[1]
                if requested_delta > 0:
                    hit_ratio = max(
                        0,
                        1 - (pages_read_delta / requested_delta)
                    ) * 100
            previous_counters = current_counters

        hit_ratio_text = (
            f"{hit_ratio:.2f}%" if hit_ratio is not None else "unavailable"
        )

        print(
            f"[{time.strftime('%H:%M:%S')}] "
            f"Reads: {read_count} | "
            f"Last {reads_per_interval} reads: {elapsed:.3f}s | "
            f"Interval cache hit ratio: {hit_ratio_text}"
        )

        time.sleep(interval_seconds)

except KeyboardInterrupt:
    print("\n===================================")
    print("Monitoring stopped.")
    print("Total random reads:", read_count)
    print("===================================")