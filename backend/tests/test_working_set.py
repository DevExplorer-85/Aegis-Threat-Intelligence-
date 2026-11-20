import concurrent.futures
import unittest
from unittest.mock import patch

from scripts.fetch_working_set import (
    DEFAULT_DOCUMENT_COUNT,
    TARGET_COLLECTION,
    fetch_manifest_events,
    fetch_working_set,
    source_attribute_document,
)


class FakeCollection:
    def __init__(self, database, name):
        self.database = database
        self.name = name
        self.documents = {}

    def bulk_write(self, operations, ordered):
        for operation in operations:
            document = operation._doc
            self.documents[document["_id"]] = document

    def count_documents(self, query):
        if "$or" in query:
            return sum(
                1 for document in self.documents.values()
                if (
                    "misp_attribute_uuid" not in document
                    or "event_uuid" not in document
                    or "feed_id" not in document
                    or "source_feed_url" not in document
                )
            )
        return len(self.documents)

    def create_index(self, index):
        pass

    def update_one(self, query, update, upsert=False):
        pass

    def rename(self, name, dropTarget):
        if dropTarget:
            self.database.collections.pop(name, None)
        self.database.collections[name] = self
        self.database.collections.pop(self.name, None)
        self.name = name


class FakeDatabase:
    def __init__(self):
        self.collections = {}

    def __getitem__(self, name):
        return self.collections.setdefault(name, FakeCollection(self, name))

    def drop_collection(self, name):
        self.collections.pop(name, None)


class WorkingSetTests(unittest.TestCase):
    def test_default_count_is_one_hundred_thousand(self):
        self.assertEqual(DEFAULT_DOCUMENT_COUNT, 100_000)
        self.assertEqual(TARGET_COLLECTION, "working_set_test")

    def test_attribute_document_preserves_original_misp_payload_and_provenance(self):
        attribute = {
            "uuid": "misp-attribute-uuid",
            "type": "domain",
            "value": "c2.example.invalid",
            "category": "Network activity",
            "to_ids": True,
            "comment": "source comment",
        }

        document = source_attribute_document(
            "circl",
            "https://www.circl.lu/doc/misp/feed-osint",
            "misp-event-uuid",
            attribute,
        )

        self.assertEqual(document["type"], attribute["type"])
        self.assertEqual(document["value"], attribute["value"])
        self.assertEqual(document["comment"], attribute["comment"])
        self.assertEqual(document["misp_attribute"], attribute)
        self.assertEqual(document["misp_attribute_uuid"], attribute["uuid"])
        self.assertEqual(document["event_uuid"], "misp-event-uuid")
        self.assertEqual(document["source_feed_url"], "https://www.circl.lu/doc/misp/feed-osint")
        self.assertIsNone(source_attribute_document("circl", "https://feed.example", "event", {
            "type": "domain",
            "value": "without-uuid.example",
        }))

    def test_manifest_fetch_downloads_events_from_the_feed_url(self):
        def fake_fetch(url):
            if url.endswith("/manifest.json"):
                return {"event-id": {"timestamp": 12}}
            return {"Event": {"uuid": "event-id"}}

        with patch("scripts.fetch_working_set.fetch", side_effect=fake_fetch):
            events = list(fetch_manifest_events(
                "circl",
                {"name": "CIRCL", "url": "https://feed.example"},
                workers=1,
            ))

        self.assertEqual(len(events), 1)
        event_uuid, future = events[0]
        self.assertEqual(event_uuid, "event-id")
        self.assertEqual(future.result()["Event"]["uuid"], "event-id")

    def test_direct_feed_fetch_installs_exact_count_without_copying_indicators(self):
        def fake_feed_events(feed_id, config, workers):
            event_uuid = f"event-from-{feed_id}"
            future = concurrent.futures.Future()
            attribute_count = 1 if feed_id == "botvrij" else 4
            future.set_result({
                "Event": {
                    "uuid": event_uuid,
                    "Attribute": [
                        {
                            "uuid": f"{feed_id}-attribute-{index}",
                            "type": "domain",
                            "value": f"{feed_id}-{index}.example.invalid",
                            "to_ids": True,
                        }
                        for index in range(attribute_count)
                    ],
                }
            })
            yield event_uuid, future

        database = FakeDatabase()

        with patch(
            "scripts.fetch_working_set.fetch_manifest_events",
            side_effect=fake_feed_events,
        ):
            result = fetch_working_set(4, workers=1, database=database)

        self.assertEqual(result, (4, 3, 0))
        fetched = database[TARGET_COLLECTION].documents
        self.assertEqual(len(fetched), 4)
        self.assertEqual(
            {document["feed_id"] for document in fetched.values()},
            {"circl", "botvrij", "threatfox"},
        )
        self.assertEqual(
            sum(1 for document in fetched.values() if document["feed_id"] == "circl"),
            2,
        )
        self.assertEqual(
            sum(1 for document in fetched.values() if document["feed_id"] == "botvrij"),
            1,
        )
        self.assertTrue(all(document["misp_attribute"] for document in fetched.values()))
        self.assertNotIn("working_set_test_staging", database.collections)

    def test_short_feed_quota_is_carried_forward_to_the_next_feed(self):
        def fake_feed_events(feed_id, config, workers):
            event_uuid = f"event-from-{feed_id}"
            future = concurrent.futures.Future()
            attribute_count = 1 if feed_id == "botvrij" else 4
            future.set_result({
                "Event": {
                    "uuid": event_uuid,
                    "Attribute": [
                        {
                            "uuid": f"{feed_id}-attribute-{index}",
                            "type": "domain",
                            "value": f"{feed_id}-{index}.example.invalid",
                        }
                        for index in range(attribute_count)
                    ],
                }
            })
            yield event_uuid, future

        database = FakeDatabase()
        with patch(
            "scripts.fetch_working_set.fetch_manifest_events",
            side_effect=fake_feed_events,
        ):
            result = fetch_working_set(6, workers=1, database=database)

        counts = {}
        for document in database[TARGET_COLLECTION].documents.values():
            counts[document["feed_id"]] = counts.get(document["feed_id"], 0) + 1
        self.assertEqual(result, (6, 3, 0))
        self.assertEqual(counts, {"circl": 2, "botvrij": 1, "threatfox": 3})


if __name__ == "__main__":
    unittest.main()
