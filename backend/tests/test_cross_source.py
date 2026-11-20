import unittest

from app.cross_source import extract_entities, iter_match_documents


class CrossSourceExtractionTests(unittest.TestCase):
    def test_cve_matching_is_case_insensitive_but_value_specific(self):
        entities = extract_entities(
            {
                "type": "vulnerability",
                "value": "cve-2025-0411 affects this software",
            }
        )
        self.assertIn(
            ("cve", "CVE-2025-0411"),
            {(entity["entity_type"], entity["normalized_value"]) for entity in entities},
        )
        self.assertNotIn(
            "CVE-2025-0412",
            {entity["normalized_value"] for entity in entities},
        )

    def test_iocs_use_conservative_type_appropriate_normalization(self):
        domain = extract_entities({"type": "domain", "value": "Example.COM."})[0]
        file_hash = extract_entities(
            {
                "type": "sha256",
                "value": "E9130B26CD5D24909F16818FD14FFEE5C9D593AD6EF4FAC66A87DEEA66C0297E",
            }
        )[0]
        same_url = extract_entities(
            {"type": "url", "value": "HTTPS://Example.COM:443/path#fragment"}
        )[0]
        different_url = extract_entities(
            {"type": "url", "value": "https://example.com/other"}
        )[0]
        self.assertEqual(domain["normalized_value"], "example.com")
        self.assertEqual(
            file_hash["normalized_value"],
            "e9130b26cd5d24909f16818fd14ffee5c9d593ad6ef4fac66a87deea66c0297e",
        )
        self.assertEqual(same_url["normalized_value"], "https://example.com/path")
        self.assertNotEqual(
            same_url["normalized_value"], different_url["normalized_value"]
        )

    def test_galaxy_clusters_are_classified_only_from_explicit_taxonomy(self):
        entities = extract_entities(
            {"tags": ['misp-galaxy:malpedia="FrostyGoop"', "FrostyGoop"]}
        )
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0]["entity_type"], "malware")
        self.assertEqual(entities[0]["display_value"], "FrostyGoop")

    def test_event_galaxy_tags_and_cves_are_included_with_source_field_paths(self):
        entities = extract_entities(
            {"value": "unclassified text", "type": "text"},
            {
                "title": "CVE-2025-0411 incident",
                "tags": ['misp-galaxy:threat-actor="SideWinder"'],
            },
        )
        by_key = {
            (entity["entity_type"], entity["normalized_value"]): entity
            for entity in entities
        }
        self.assertIn(("cve", "CVE-2025-0411"), by_key)
        self.assertEqual(
            by_key[("actor", "sidewinder")]["field"],
            "feed_events.tags[0]",
        )


class CrossSourceGroupingTests(unittest.TestCase):
    @staticmethod
    def source_row(source, record_count):
        return {
            "_id": {
                "entity_type": "cve",
                "subtype": "CVE",
                "normalized_value": "CVE-2025-0411",
                "source": source,
            },
            "display_value": "CVE-2025-0411",
            "source_label": source,
            "source_feed_url": f"https://{source}.example/feed",
            "record_count": record_count,
            "sample": {"record_id": source},
        }

    def test_multiple_records_from_one_feed_do_not_become_common_data(self):
        matches = list(
            iter_match_documents([self.source_row("circl", 3)], "2026-01-01")
        )
        self.assertEqual(matches, [])

    def test_common_match_counts_distinct_sources_and_all_records(self):
        matches = list(
            iter_match_documents(
                [
                    self.source_row("botvrij", 2),
                    self.source_row("circl", 3),
                ],
                "2026-01-01",
            )
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["source_count"], 2)
        self.assertEqual(matches[0]["record_count"], 5)
        self.assertEqual(
            {source["source"] for source in matches[0]["sources"]},
            {"botvrij", "circl"},
        )


if __name__ == "__main__":
    unittest.main()
