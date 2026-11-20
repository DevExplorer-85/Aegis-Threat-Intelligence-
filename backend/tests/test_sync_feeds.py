import unittest
from unittest.mock import patch

from scripts.sync_feeds import (
    build_documents,
    events_to_sync,
    extract_threat_names,
    prepare_threat_name_matcher,
    sync_feed,
)


class FakeCollection:
    def __init__(self):
        self.bulk_write_batches = []

    def find_one(self, query):
        return None

    def find(self, query, projection):
        return []

    def bulk_write(self, operations, ordered):
        self.bulk_write_batches.append(len(operations))

    def delete_many(self, query):
        pass

    def update_one(self, query, update, upsert):
        pass


class FakeDatabase:
    def __init__(self):
        self.collections = {}

    def __getitem__(self, name):
        return self.collections.setdefault(name, FakeCollection())


class SyncFeedTests(unittest.TestCase):
    def test_incremental_sync_selects_only_newer_or_unknown_events(self):
        manifest = {
            "unchanged": {"timestamp": 10},
            "changed": {"timestamp": "12"},
            "new": {"timestamp": 1},
        }

        selected = events_to_sync(
            manifest,
            {"unchanged": 10, "changed": 11},
        )

        self.assertEqual([event[0] for event in selected], ["changed", "new"])

    def test_event_and_indicator_keep_feed_provenance_and_truthful_ids_verdict(self):
        event = {
            "uuid": "event-uuid",
            "info": "Public feed event",
            "date": "2026-10-04",
            "timestamp": "123",
            "threat_level_id": "1",
            "Attribute": [{
                "uuid": "attribute-uuid",
                "type": "domain",
                "value": "example.invalid",
                "category": "Network activity",
                "to_ids": True,
            }],
        }

        document, indicators = build_documents(
            "circl",
            "https://www.circl.lu/doc/misp/feed-osint",
            event,
        )

        self.assertEqual(document["event_uuid"], "event-uuid")
        self.assertEqual(document["misp_uuid"], "event-uuid")
        self.assertEqual(
            document["source_feed_url"],
            "https://www.circl.lu/doc/misp/feed-osint",
        )
        self.assertEqual(document["severity"], "High")
        self.assertEqual(document["verdict"], "IDS candidate")
        self.assertNotIn("status", document)
        self.assertEqual(indicators[0]["event_uuid"], "event-uuid")
        self.assertEqual(indicators[0]["value"], "example.invalid")
        self.assertTrue(indicators[0]["to_ids"])

    def test_galaxy_extraction_blocks_common_words_and_requires_title_case(self):
        galaxy = {
            "north korea": {
                "value": "North Korea",
                "synonyms": ["do not", "Explorer"],
                "description": "",
                "cluster": "threat-actor",
            },
            "play": {
                "value": "PLAY",
                "synonyms": [],
                "description": "",
                "cluster": "malpedia",
            },
        }
        matcher = prepare_threat_name_matcher(galaxy)

        self.assertIn("north korea", extract_threat_names(["North Korea activity"], galaxy))
        self.assertIn(
            "north korea",
            extract_threat_names(["North Korea activity"], galaxy, matcher),
        )
        self.assertNotIn("north korea", extract_threat_names(["north korea activity"], galaxy))
        self.assertEqual(extract_threat_names(["open the Explorer window"], galaxy), {})
        self.assertEqual(extract_threat_names(["do not run this command"], galaxy), {})
        self.assertEqual(
            extract_threat_names(["Google Play apps are infected"], galaxy),
            {},
        )

    def test_sync_writes_events_in_bounded_batches(self):
        manifest = {
            f"event-{index}": {"timestamp": index}
            for index in range(101)
        }

        def fake_fetch(url):
            if url.endswith("/manifest.json"):
                return manifest
            uuid = url.rsplit("/", 1)[-1].removesuffix(".json")
            return {"Event": {"uuid": uuid, "info": uuid, "Attribute": []}}

        db = FakeDatabase()
        with patch("scripts.sync_feeds.fetch", side_effect=fake_fetch):
            counts = sync_feed(
                db,
                "circl",
                {"name": "CIRCL", "url": "https://feed.example"},
                max_events=0,
                full=False,
                workers=4,
            )

        self.assertEqual(counts, (101, 0, 0))
        self.assertEqual(db["feed_events"].bulk_write_batches, [100, 1])


if __name__ == "__main__":
    unittest.main()
