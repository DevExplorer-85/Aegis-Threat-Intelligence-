import hashlib
import ipaddress
import logging
import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

MATCHES_COLLECTION = "cross_source_matches"
STATE_COLLECTION = "cross_source_analysis_state"
STAGING_COLLECTION = "cross_source_records_build"
ALGORITHM_VERSION = "v1"
logger = logging.getLogger(__name__)

SOURCE_LABELS = {
    "circl": "CIRCL MISP",
    "botvrij": "Botvrij.eu",
    "threatfox": "ThreatFox",
}
SOURCE_FEED_URLS = {
    "circl": "https://www.circl.lu/doc/misp/feed-osint",
    "botvrij": "https://www.botvrij.eu/data/feed-osint",
    "threatfox": "https://threatfox.abuse.ch/downloads/misp",
}

_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_GALAXY_PATTERN = re.compile(
    r"""^misp-galaxy:([^=]+)=(?:"([^"]+)"|'([^']+)')$""",
    re.IGNORECASE,
)
_HASH_TYPES = {"md5", "sha1", "sha256", "sha512"}


def display_source(source: str, source_feed_url: str | None = None) -> str:
    lowered = source.lower()
    if lowered in SOURCE_LABELS:
        return SOURCE_LABELS[lowered]
    if source_feed_url:
        if "circl.lu" in source_feed_url:
            return SOURCE_LABELS["circl"]
        if "botvrij.eu" in source_feed_url:
            return SOURCE_LABELS["botvrij"]
        if "threatfox.abuse.ch" in source_feed_url:
            return SOURCE_LABELS["threatfox"]
    return source or "Unknown source"


def _entity(
    entity_type: str,
    subtype: str,
    value: str,
    field: str,
    normalization: str,
) -> dict[str, str]:
    normalized = value.strip()
    if not normalized:
        return {}
    return {
        "entity_type": entity_type,
        "subtype": subtype,
        "normalized_value": normalized,
        "display_value": normalized,
        "field": field,
        "normalization": normalization,
    }


def _normalize_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _normalize_ip(value: str) -> str | None:
    candidate = value.strip()
    if "|" in candidate:
        candidate = candidate.split("|", 1)[0]
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return None


def _normalize_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value.strip())
        host = parsed.hostname
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            return None
        normalized_host = _normalize_domain(host)
        try:
            address = ipaddress.ip_address(normalized_host)
            normalized_host = (
                f"[{address.compressed}]" if address.version == 6 else address.compressed
            )
        except ValueError:
            pass
        user_info = ""
        if "@" in parsed.netloc:
            user_info = parsed.netloc.rsplit("@", 1)[0] + "@"
        try:
            port = parsed.port
        except ValueError:
            return None
        default_port = (parsed.scheme.lower() == "http" and port == 80) or (
            parsed.scheme.lower() == "https" and port == 443
        )
        port_suffix = f":{port}" if port and not default_port else ""
        netloc = f"{user_info}{normalized_host}{port_suffix}"
        return urlunsplit(
            (parsed.scheme.lower(), netloc, parsed.path, parsed.query, "")
        )
    except ValueError:
        return None


def _ioc_entity(record_type: str, value: str, field: str) -> dict[str, str] | None:
    normalized_type = record_type.lower().strip()
    if normalized_type in {"domain", "hostname", "domain|ip"}:
        candidate = value.split("|", 1)[0].strip()
        if not candidate or any(char.isspace() for char in candidate):
            return None
        return _entity("ioc", "Domain", _normalize_domain(candidate), field, "lowercase; remove trailing dot")

    if normalized_type in {"ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "ip"}:
        candidate = _normalize_ip(value)
        return _entity("ioc", "IP address", candidate, field, "canonical IP address") if candidate else None

    if normalized_type in {"url", "uri", "link"}:
        candidate = _normalize_url(value)
        return _entity("ioc", "URL", candidate, field, "lowercase scheme/host; remove default port and fragment") if candidate else None

    if normalized_type in _HASH_TYPES:
        candidate = value.strip().lower()
        required_length = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}[normalized_type]
        if re.fullmatch(rf"[0-9a-f]{{{required_length}}}", candidate):
            return _entity("ioc", "File hash", candidate, field, "lowercase hexadecimal")
    return None


def extract_entities(record: dict, event: dict | None = None) -> list[dict[str, str]]:
    record_type = str(record.get("type") or "")
    entities: dict[tuple[str, str, str], dict[str, str]] = {}

    def add(entity: dict[str, str] | None) -> None:
        if entity:
            key = (
                entity["entity_type"],
                entity["subtype"],
                entity["normalized_value"],
            )
            entities.setdefault(key, entity)

    value = record.get("value")
    if isinstance(value, str):
        add(_ioc_entity(record_type, value, "value"))
        if record_type.lower().strip() == "domain|ip" and "|" in value:
            candidate = _normalize_ip(value.split("|", 1)[1])
            if candidate:
                add(
                    _entity(
                        "ioc",
                        "IP address",
                        candidate,
                        "value",
                        "canonical IP address",
                    )
                )
        for match in _CVE_PATTERN.finditer(value):
            add(_entity("cve", "CVE", match.group(0).upper(), "value", "uppercase CVE identifier"))

    text_fields = [
        ("comment", record.get("comment")),
        ("feed_events.title", (event or {}).get("title")),
        ("feed_events.description", (event or {}).get("description")),
        ("feed_events.classification", (event or {}).get("classification")),
    ]
    for field, text in text_fields:
        if isinstance(text, str):
            for match in _CVE_PATTERN.finditer(text):
                add(
                    _entity(
                        "cve",
                        "CVE",
                        match.group(0).upper(),
                        field,
                        "uppercase CVE identifier",
                    )
                )

    tags = [
        (tag, f"tags[{index}]")
        for index, tag in enumerate(record.get("tags") or [])
    ]
    tags.extend(
        (tag, f"feed_events.tags[{index}]")
        for index, tag in enumerate((event or {}).get("tags") or [])
    )
    for tag, field in tags:
        if not isinstance(tag, str):
            continue
        for match in _CVE_PATTERN.finditer(tag):
            add(_entity("cve", "CVE", match.group(0).upper(), field, "uppercase CVE identifier"))
        galaxy_match = _GALAXY_PATTERN.match(tag.strip())
        if not galaxy_match:
            continue
        taxonomy = galaxy_match.group(1).lower()
        cluster_name = galaxy_match.group(2) or galaxy_match.group(3) or ""
        if taxonomy in {"malpedia", "mitre-malware", "malware", "ransomware"}:
            entity_type, subtype = "malware", "Malware"
        elif taxonomy in {
            "threat-actor",
            "mitre-intrusion-set",
            "mitre-enterprise-attack-intrusion-set",
        }:
            entity_type, subtype = "actor", "Threat actor"
        elif taxonomy in {"tool", "mitre-attack-tool"}:
            entity_type, subtype = "tool", "Tool"
        else:
            entity_type, subtype = "galaxy", f"Galaxy · {taxonomy}"
        cluster = _entity(
            entity_type,
            subtype,
            cluster_name.strip().casefold(),
            field,
            f"exact MISP Galaxy cluster name ({taxonomy}; case-insensitive)",
        )
        if cluster:
            cluster["display_value"] = cluster_name.strip()
            add(cluster)

    return list(entities.values())


def source_group_pipeline() -> list[dict]:
    return [
        {
            "$group": {
                "_id": {
                    "entity_type": "$entity_type",
                    "subtype": "$subtype",
                    "normalized_value": "$normalized_value",
                    "source": "$source",
                    "evidence_record_id": "$evidence_record_id",
                },
                "display_value": {"$first": "$display_value"},
                "source_label": {"$first": "$source_label"},
                "source_feed_url": {"$first": "$source_feed_url"},
                "record_count": {"$first": 1},
                "sample": {
                    "$first": {
                        "record_id": "$record_id",
                        "event_uuid": "$event_uuid",
                        "feed_id": "$feed_id",
                        "source_feed_url": "$source_feed_url",
                        "indicator_type": "$indicator_type",
                        "indicator_value": "$indicator_value",
                        "record_title": "$record_title",
                        "collection": "$collection",
                        "field": "$field",
                        "normalization": "$normalization",
                        "record_date": "$record_date",
                    }
                },
            }
        },
        {
            "$group": {
                "_id": {
                    "entity_type": "$_id.entity_type",
                    "subtype": "$_id.subtype",
                    "normalized_value": "$_id.normalized_value",
                    "source": "$_id.source",
                },
                "display_value": {"$first": "$display_value"},
                "source_label": {"$first": "$source_label"},
                "source_feed_url": {"$first": "$source_feed_url"},
                "record_count": {"$sum": "$record_count"},
                "sample": {"$first": "$sample"},
            }
        },
        {
            "$sort": {
                "_id.entity_type": 1,
                "_id.subtype": 1,
                "_id.normalized_value": 1,
                "_id.source": 1,
            }
        },
    ]


def iter_match_documents(source_rows: Iterable[dict], analyzed_at: str) -> Iterator[dict]:
    current_key = None
    current_sources: list[dict] = []

    def make_document(key: dict, sources: list[dict]) -> dict | None:
        distinct_sources = sorted({item["source"] for item in sources})
        if len(distinct_sources) < 2:
            return None
        identity = "\0".join(
            (key["entity_type"], key["subtype"], key["normalized_value"])
        )
        match_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        return {
            "_id": match_id,
            "entity_type": key["entity_type"],
            "subtype": key["subtype"],
            "normalized_value": key["normalized_value"],
            "display_value": sources[0]["display_value"],
            "sources": sources,
            "source_count": len(distinct_sources),
            "record_count": sum(item["record_count"] for item in sources),
            "analyzed_at": analyzed_at,
            "algorithm_version": ALGORITHM_VERSION,
        }

    for row in source_rows:
        key = row["_id"]
        entity_key = (
            key["entity_type"],
            key["subtype"],
            key["normalized_value"],
        )
        if current_key is not None and entity_key != current_key:
            document = make_document(
                {
                    "entity_type": current_key[0],
                    "subtype": current_key[1],
                    "normalized_value": current_key[2],
                },
                current_sources,
            )
            if document:
                yield document
            current_sources = []
        current_key = entity_key
        current_sources.append(
            {
                "source": key["source"],
                "source_label": row["source_label"],
                "source_feed_url": row["source_feed_url"],
                "display_value": row["display_value"],
                "record_count": row["record_count"],
                "samples": [row["sample"]],
            }
        )

    if current_key is not None:
        document = make_document(
            {
                "entity_type": current_key[0],
                "subtype": current_key[1],
                "normalized_value": current_key[2],
            },
            current_sources,
        )
        if document:
            yield document


def _iso_timestamp(value) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (int, float)) or (
        isinstance(value, str) and value.isdigit()
    ):
        try:
            return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return str(value)
    return str(value) if value is not None else None


def mark_analysis_stale(database) -> None:
    database[STATE_COLLECTION].update_one(
        {"_id": "current", "status": "ready"},
        {
            "$set": {
                "stale": True,
                "stale_at": datetime.now(timezone.utc),
            }
        },
    )


def analyze_collection(database) -> dict:
    if "working_set_test" not in database.list_collection_names():
        raise ValueError("The working_set_test CTI collection is missing.")

    source_collection = database["working_set_test"]
    analyzed_at = datetime.now(timezone.utc)
    analyzed_at_text = analyzed_at.isoformat()
    state = database[STATE_COLLECTION]
    state.update_one(
        {"_id": "current"},
        {"$set": {"status": "running", "started_at": analyzed_at}},
        upsert=True,
    )

    staging = database[STAGING_COLLECTION]
    matches_build_name = f"{MATCHES_COLLECTION}_build"
    matches_build = database[matches_build_name]
    staging.drop()
    matches_build.drop()

    try:
        batch = []
        records_analyzed = 0
        source_counts: dict[str, int] = {}
        events = {
            (event.get("feed_id"), event.get("event_uuid")): event
            for event in database["feed_events"].find(
                {},
                {
                    "feed_id": 1,
                    "event_uuid": 1,
                    "title": 1,
                    "description": 1,
                    "classification": 1,
                    "tags": 1,
                    "published_at": 1,
                    "date": 1,
                },
            )
        }
        projection = {
            "_id": 1,
            "feed_id": 1,
            "source": 1,
            "source_feed_url": 1,
            "event_uuid": 1,
            "type": 1,
            "value": 1,
            "comment": 1,
            "tags": 1,
            "timestamp": 1,
            "date": 1,
        }
        for record in source_collection.find({}, projection).batch_size(1000):
            records_analyzed += 1
            source = str(record.get("feed_id") or record.get("source") or "").strip()
            if not source:
                continue
            source_counts[source] = source_counts.get(source, 0) + 1
            source_url = record.get("source_feed_url")
            source_label = display_source(source, source_url)
            event = events.get((record.get("feed_id"), record.get("event_uuid")), {})
            event_title = event.get("title")
            for entity in extract_entities(record, event):
                source_event_field = entity["field"].startswith("feed_events.")
                batch.append(
                    {
                        "entity_type": entity["entity_type"],
                        "subtype": entity["subtype"],
                        "normalized_value": entity["normalized_value"],
                        "display_value": entity["display_value"],
                        "field": entity["field"],
                        "normalization": entity["normalization"],
                        "source": source,
                        "source_label": source_label,
                        "source_feed_url": source_url,
                        "record_id": str(
                            event.get("_id") if source_event_field else record.get("_id", "")
                        ),
                        "evidence_record_id": str(
                            event.get("_id") if source_event_field else record.get("_id", "")
                        ),
                        "collection": (
                            "feed_events" if source_event_field else "working_set_test"
                        ),
                        "event_uuid": record.get("event_uuid"),
                        "feed_id": record.get("feed_id"),
                        "indicator_type": record.get("type"),
                        "indicator_value": record.get("value"),
                        "record_title": event_title,
                        "record_date": _iso_timestamp(
                            (
                                event.get("published_at") or event.get("date")
                                if source_event_field
                                else record.get("timestamp") or record.get("date")
                            )
                        ),
                    }
                )
                if len(batch) >= 1000:
                    staging.insert_many(batch, ordered=False)
                    batch.clear()
        if batch:
            staging.insert_many(batch, ordered=False)

        staging.create_index(
            [
                ("entity_type", 1),
                ("subtype", 1),
                ("normalized_value", 1),
                ("source", 1),
                ("evidence_record_id", 1),
            ]
        )
        rows = staging.aggregate(source_group_pipeline(), allowDiskUse=True)
        matches_batch = []
        matches_count = 0
        for document in iter_match_documents(rows, analyzed_at_text):
            matches_batch.append(document)
            if len(matches_batch) >= 500:
                matches_build.insert_many(matches_batch, ordered=False)
                matches_count += len(matches_batch)
                matches_batch.clear()
        if matches_batch:
            matches_build.insert_many(matches_batch, ordered=False)
            matches_count += len(matches_batch)

        matches_build.create_index(
            [("entity_type", 1), ("subtype", 1), ("normalized_value", 1)]
        )
        matches_build.create_index([("sources.source", 1)])
        matches_build.create_index(
            [("source_count", -1), ("entity_type", 1), ("normalized_value", 1)]
        )
        matches_build.rename(MATCHES_COLLECTION, dropTarget=True)
        result = {
            "_id": "current",
            "status": "ready",
            "records_analyzed": records_analyzed,
            "sources": [
                {
                    "source": source,
                    "label": display_source(source),
                    "record_count": count,
                }
                for source, count in sorted(source_counts.items())
            ],
            "source_count": len(source_counts),
            "common_items": matches_count,
            "analyzed_at": analyzed_at,
            "algorithm_version": ALGORITHM_VERSION,
            "stale": False,
        }
        state.replace_one({"_id": "current"}, result, upsert=True)
        staging.drop()
        return result
    except Exception:
        logger.exception("Cross-source analysis refresh failed")
        state.update_one(
            {"_id": "current"},
            {
                "$set": {
                    "status": "failed",
                    "failed_at": datetime.now(timezone.utc),
                    "error": "Analysis failed; check backend logs.",
                }
            },
            upsert=True,
        )
        raise
