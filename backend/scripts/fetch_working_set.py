"""Fetch the Lab 7.2 working set directly from public MISP OSINT feeds."""
import argparse
import concurrent.futures as cf
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pymongo import InsertOne

from app.cross_source import mark_analysis_stale
from app.database import db
from scripts.sync_feeds import FEEDS, attributes_of, fetch

TARGET_COLLECTION = "working_set_test"
STAGING_COLLECTION = "working_set_test_staging"
DEFAULT_DOCUMENT_COUNT = 100_000
INSERT_BATCH_SIZE = 1_000
DEFAULT_WORKERS = 8


def source_attribute_document(feed_id, feed_url, event_uuid, attribute):
    """Preserve the fetched MISP attribute payload and attach source provenance."""
    attribute_uuid = attribute.get("uuid")
    value = attribute.get("value")
    if not attribute_uuid or not attribute.get("type") or not value:
        return None

    tags = [
        tag.get("name") if isinstance(tag, dict) else tag
        for tag in (attribute.get("Tag") or [])
    ]
    return {
        "_id": f"{feed_id}:{attribute_uuid}",
        "misp_attribute_uuid": attribute_uuid,
        "misp_attribute": attribute,
        "event_uuid": event_uuid,
        "feed_id": feed_id,
        "source": feed_id,
        "source_feed_url": feed_url,
        "type": attribute["type"],
        "value": value,
        "category": attribute.get("category"),
        "to_ids": bool(attribute.get("to_ids")),
        "comment": attribute.get("comment"),
        "tags": [tag for tag in tags if isinstance(tag, str) and tag],
        "timestamp": attribute.get("timestamp"),
        "lab_dataset": "Fetched directly from public MISP feeds for Lab 7.2",
    }


def fetch_manifest_events(feed_id, config, workers=DEFAULT_WORKERS):
    """Yield one feed's events with no more than workers requests in flight."""
    manifest = fetch(f"{config['url']}/manifest.json")
    print(
        f"{config['name']}: {len(manifest):,} manifest events",
        flush=True,
    )
    ordered = sorted(
        manifest.items(),
        key=lambda item: int((item[1] or {}).get("timestamp", 0) or 0),
        reverse=True,
    )
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        task_iter = iter(event_uuid for event_uuid, _ in ordered)
        futures = {}

        def submit_next():
            try:
                event_uuid = next(task_iter)
            except StopIteration:
                return
            future = pool.submit(fetch, f"{config['url']}/{event_uuid}.json")
            futures[future] = event_uuid

        for _ in range(min(workers, len(ordered))):
            submit_next()

        while futures:
            completed, _ = cf.wait(futures, return_when=cf.FIRST_COMPLETED)
            for future in completed:
                event_uuid = futures.pop(future)
                submit_next()
                yield event_uuid, future


def fetch_working_set(document_count, workers=DEFAULT_WORKERS, database=db):
    if document_count < 1:
        raise ValueError("document_count must be at least 1")
    if workers < 1:
        raise ValueError("workers must be at least 1")

    database.drop_collection(STAGING_COLLECTION)
    staging = database[STAGING_COLLECTION]
    operations = []
    fetched_events = fetch_failures = inserted_count = 0
    selected_attribute_uuids = set()
    feed_quotas = {
        feed_id: document_count // len(FEEDS)
        + (1 if index < document_count % len(FEEDS) else 0)
        for index, feed_id in enumerate(FEEDS)
    }
    quota_shortfall = 0

    try:
        for feed_id, config in FEEDS.items():
            feed_url = config["url"]
            feed_quota = feed_quotas[feed_id] + quota_shortfall
            quota_shortfall = 0
            if feed_quota == 0:
                continue
            feed_inserted = 0
            for expected_uuid, future in fetch_manifest_events(
                feed_id, config, workers
            ):
                try:
                    payload = future.result()
                except Exception as exc:
                    fetch_failures += 1
                    print(
                        f"Fetch failed for {feed_id}/{expected_uuid}: {exc}",
                        flush=True,
                    )
                    continue
                event = payload.get("Event", payload) if isinstance(payload, dict) else None
                if not isinstance(event, dict) or event.get("uuid") != expected_uuid:
                    fetch_failures += 1
                    print(
                        f"Invalid MISP event payload or UUID mismatch: {feed_id}/{expected_uuid}",
                        flush=True,
                    )
                    continue

                fetched_events += 1
                for attribute in attributes_of(event):
                    document = source_attribute_document(
                        feed_id,
                        feed_url,
                        expected_uuid,
                        attribute,
                    )
                    if document is None:
                        continue
                    source_uuid = (feed_id, document["misp_attribute_uuid"])
                    if source_uuid in selected_attribute_uuids:
                        continue

                    selected_attribute_uuids.add(source_uuid)
                    operations.append(InsertOne(document))
                    feed_inserted += 1
                    if len(operations) >= INSERT_BATCH_SIZE:
                        staging.bulk_write(operations, ordered=False)
                        inserted_count += len(operations)
                        operations.clear()
                        if inserted_count % 10_000 == 0:
                            print(
                                f"Fetched {inserted_count:,}/{document_count:,} "
                                f"original MISP attributes...",
                                flush=True,
                            )
                    if feed_inserted >= feed_quota:
                        break

                if feed_inserted >= feed_quota:
                    break

            print(
                f"{config['name']}: fetched {feed_inserted:,}/"
                f"{feed_quota:,} attributes",
                flush=True,
            )
            quota_shortfall = max(0, feed_quota - feed_inserted)

        if operations:
            remaining = document_count - inserted_count
            batch = operations[:remaining]
            staging.bulk_write(batch, ordered=False)
            inserted_count += len(batch)

        if inserted_count != document_count:
            raise RuntimeError(
                f"Fetched only {inserted_count:,}/{document_count:,} original "
                f"MISP attributes after {fetched_events:,} events; "
                f"{fetch_failures:,} event fetches failed. Existing {TARGET_COLLECTION} "
                "was left unchanged."
            )

        staging.create_index([("event_uuid", 1), ("feed_id", 1)])
        staging.create_index([("type", 1), ("value", 1)])
        staging.create_index("misp_attribute_uuid")
        actual = staging.count_documents({})
        missing_provenance = staging.count_documents({
            "$or": [
                {"misp_attribute_uuid": {"$exists": False}},
                {"event_uuid": {"$exists": False}},
                {"feed_id": {"$exists": False}},
                {"source_feed_url": {"$exists": False}},
            ]
        })
        if actual != document_count or missing_provenance:
            raise RuntimeError(
                f"Staging verification failed: {actual:,} documents and "
                f"{missing_provenance:,} records missing provenance."
            )

        staging.rename(TARGET_COLLECTION, dropTarget=True)
        mark_analysis_stale(database)
        print(
            f"Installed {actual:,} original attributes fetched from public MISP feeds; "
            f"{fetched_events:,} events downloaded and {fetch_failures:,} fetch failures.",
            flush=True,
        )
        return actual, fetched_events, fetch_failures
    except Exception:
        database.drop_collection(STAGING_COLLECTION)
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Fetch original MISP attributes for the Lab 7.2 working set."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_DOCUMENT_COUNT,
        help=f"Number of original MISP attributes to fetch (default: {DEFAULT_DOCUMENT_COUNT:,}).",
    )
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be at least 1")
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    fetch_working_set(args.count, workers=args.workers)


if __name__ == "__main__":
    main()
