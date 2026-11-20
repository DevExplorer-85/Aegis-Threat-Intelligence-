"""Sync real threat-intel MISP feeds into MongoDB.

Feeds: CIRCL OSINT, Botvrij.eu OSINT, abuse.ch ThreatFox.
- Reads each feed's manifest.json and upserts only new or changed events
  (manifest timestamp vs stored timestamp), by event uuid.
- Every stored event carries `source` (feed slug) and `event_uuid` so it
  can be traced back to its feed.
- Indicators (MISP attributes) live in their own collection referencing
  the event uuid, never embedded in the event document.
- Usage:
    python -m scripts.sync_feeds --max-events 50      # quick first run
    python -m scripts.sync_feeds                      # incremental run
    python -m scripts.sync_feeds --full               # refetch everything
"""
import argparse
import concurrent.futures as cf
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from pymongo import MongoClient, UpdateOne

from app.cross_source import mark_analysis_stale

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")

FEEDS = {
    "circl": {
        "name": "CIRCL OSINT",
        "url": "https://www.circl.lu/doc/misp/feed-osint",
        "provider": "CIRCL",
    },
    "botvrij": {
        "name": "Botvrij.eu OSINT",
        "url": "https://www.botvrij.eu/data/feed-osint",
        "provider": "Botvrij.eu",
    },
    "threatfox": {
        "name": "abuse.ch ThreatFox",
        "url": "https://threatfox.abuse.ch/downloads/misp",
        "provider": "abuse.ch",
    },
}

THREAT_LEVEL = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}
NON_SEMANTIC_TAG_PREFIXES = ("type:", "tlp:", "misp-galaxy:", "feed:")
BLOCKLIST = {
    "action", "explorer", "play", "do", "not", "the", "a", "an", "and", "or", "of",
    "in", "on", "to", "for", "with", "from", "by", "at", "is", "are", "was",
    "were", "be", "been", "this", "that", "these", "those", "it", "its", "new",
    "old", "latest", "update", "updates", "campaign", "report", "analysis",
    "malware", "threat", "attack", "attacks", "attacker", "attackers", "group",
    "actor", "actors", "actor", "team", "operation", "secure", "security",
    "open", "source", "osint", "white", "green", "amber", "red", "no", "yes",
    "zero", "one", "two", "first", "second", "third", "part", "chapter",
    "using", "used", "uses", "targeting", "targets", "via", "over", "under",
    "into", "about", "after", "before", "during", "while", "when", "where",
    "which", "who", "whom", "what", "how", "why", "all", "any", "some", "more",
    "most", "other", "such", "as", "than", "then", "them", "they", "their",
    "he", "she", "his", "her", "we", "our", "you", "your", "i", "me", "my",
    "event", "events", "user", "users", "code", "data", "file", "files", "url",
    "urls", "ip", "domain", "host", "server", "network", "system", "systems",
    "windows", "linux", "macos", "android", "ios", "web", "online", "offline",
    "public", "private", "internal", "external", "global", "local", "remote",
    "unknown", "confirmed", "suspected", "reported", "discovered", "found",
}


def fetch(url, timeout=30, retries=3):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cti-sync/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            last = exc
            time.sleep(min(2 ** attempt + random.random(), 10))
    raise RuntimeError(f"fetch failed for {url}: {last}")


def severity_label(level_id):
    return THREAT_LEVEL.get(str(level_id), "Undefined")


def event_tags(event):
    return [t.get("name") for t in event.get("Tag", []) if t.get("name")]


def attribute_tags(attribute):
    return [t.get("name") for t in attribute.get("Tag", []) if t.get("name")]


def semantic_tags(tags):
    return [t for t in tags if not t.startswith(NON_SEMANTIC_TAG_PREFIXES)]


def pick_classification(event, attributes):
    # Prefer the MISP galaxy tag (e.g. misp-galaxy:malpedia="Lumma Stealer")
    def galaxy_values(tags):
        out = []
        for t in tags:
            m = re.match(r'misp-galaxy:([^==]+)="?(.+?)"?$', t)
            if m:
                out.append(m.group(2))
        return out

    for tags in [event_tags(event)] + [attribute_tags(a) for a in attributes]:
        values = galaxy_values(tags)
        if values:
            return values[0]

    candidates = []
    for attr in attributes:
        candidates.extend(semantic_tags(attribute_tags(attr)))
    candidates.extend(semantic_tags(event_tags(event)))
    candidates = [c for c in candidates
                  if not re.match(r'^(osint|misp|creator|estimative)', c, re.I)
                  and "=" not in c]
    for tag in candidates:
        low = tag.lower()
        if any(k in low for k in ("ransom", "phish", "botnet", "c2", "malware",
                                  "spy", "credential", "apt", "bank", "steal",
                                  "exploit", "ddos", "loader", "trojan", "worm")):
            return tag
    return candidates[0] if candidates else "Unclassified"


def parse_date(event):
    raw = event.get("date")
    if isinstance(raw, str):
        try:
            return datetime.strptime(raw, "%Y-%m-%d")
        except ValueError:
            return None
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    return None


def timestamp_number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def events_to_sync(manifest, known_timestamps, full=False, max_events=0):
    todo = []
    for uuid, meta in manifest.items():
        timestamp = timestamp_number(meta.get("timestamp"))
        if full or uuid not in known_timestamps or timestamp > known_timestamps[uuid]:
            todo.append((uuid, timestamp, meta))
    todo.sort(key=lambda item: item[1], reverse=True)
    return todo[:max_events] if max_events else todo


def attributes_of(event):
    for key in ("Attribute", "attributes"):
        attrs = event.get(key)
        if isinstance(attrs, list):
            return attrs
    out = []
    for obj in event.get("Object", []) or []:
        out.extend(obj.get("Attribute", []) or [])
    return out


def build_documents(feed_slug, feed_url, event):
    uuid = event.get("uuid")
    if not uuid:
        return None, []
    attributes = attributes_of(event)
    tags = event_tags(event)
    orgc = (event.get("Orgc") or {}).get("name")
    indicator_types = [a.get("type") for a in attributes if a.get("type")]
    primary_type = indicator_types[0] if indicator_types else None
    first_indicator = next(
        (a for a in attributes if a.get("type") and a.get("value")),
        {},
    )
    published = parse_date(event)
    timestamp = event.get("timestamp") or event.get("publish_timestamp")

    doc = {
        "event_uuid": uuid,
        "misp_uuid": uuid,
        "event_id": f"{feed_slug}:{uuid}",
        "feed_id": feed_slug,
        "source": feed_slug,
        "source_feed_url": feed_url,
        "title": event.get("info"),
        "description": event.get("info"),
        "published_at": published.isoformat() if published else None,
        "date": published.isoformat() if published else None,
        "misp_timestamp": timestamp,
        "threat_level_id": event.get("threat_level_id"),
        "severity": severity_label(event.get("threat_level_id")),
        "classification": pick_classification(event, attributes),
        "event_type": primary_type,
        "indicator_type": primary_type,
        "indicator_value": first_indicator.get("value"),
        "tags": tags,
        "orgc": orgc,
        "analysis": event.get("analysis"),
        "distribution": event.get("distribution"),
        "published_flag": event.get("published"),
        "attribute_count": len(attributes),
        "verdict": (
            "IDS candidate"
            if any(a.get("to_ids") for a in attributes)
            else "Not marked for IDS"
        ),
        "synced_at": datetime.now(timezone.utc),
    }
    indicators = []
    for attr in attributes:
        value = attr.get("value")
        if not value or not attr.get("type"):
            continue
        indicators.append({
            "_id": attr.get("uuid") or f"{uuid}:{attr.get('type')}:{value}",
            "event_uuid": uuid,
            "feed_id": feed_slug,
            "source": feed_slug,
            "type": attr.get("type"),
            "value": value,
            "category": attr.get("category"),
            "to_ids": bool(attr.get("to_ids")),
            "comment": attr.get("comment"),
            "tags": attribute_tags(attr),
            "timestamp": attr.get("timestamp"),
        })
    return doc, indicators


def sync_feed(db, slug, cfg, max_events, full, workers):
    print(f"\n== {cfg['name']} ({cfg['url']}) ==")
    manifest = fetch(f"{cfg['url']}/manifest.json")
    print(f"manifest entries: {len(manifest)}")

    state = db["sync_state"].find_one({"_id": slug}) or {}
    last_ts = state.get("last_timestamp", 0) if not full else 0

    known_ts = {
        doc["event_uuid"]: max(
            timestamp_number(doc.get("manifest_timestamp")),
            timestamp_number(doc.get("misp_timestamp")),
        )
        for doc in db["feed_events"].find(
            {"feed_id": slug}, {"event_uuid": 1, "misp_timestamp": 1, "manifest_timestamp": 1}
        )
    }
    todo = events_to_sync(manifest, known_ts, full=full, max_events=max_events)
    print(f"events to fetch (new/changed): {len(todo)}")
    if not todo:
        now = datetime.now(timezone.utc)
        db["sync_state"].update_one(
            {"_id": slug},
            {"$set": {"last_run_at": now,
                      "last_success_at": now,
                      "last_timestamp": last_ts,
                      "manifest_size": len(manifest),
                      "events_fetched": 0,
                      "failures": 0}},
            upsert=True,
        )
        return 0, 0, 0

    event_ops, indicator_ops, event_indicator_ids = [], [], {}
    upserted_events = upserted_indicators = 0
    successful_timestamps = []
    failures = 0
    done = 0

    def download(uuid):
        return uuid, fetch(f"{cfg['url']}/{uuid}.json")

    def flush_batch():
        nonlocal upserted_events, upserted_indicators
        if event_ops:
            db["feed_events"].bulk_write(event_ops, ordered=False)
            upserted_events += len(event_ops)
            event_ops.clear()
        if indicator_ops:
            db["indicators"].bulk_write(indicator_ops, ordered=False)
            upserted_indicators += len(indicator_ops)
            indicator_ops.clear()
        for event_uuid, indicator_ids in event_indicator_ids.items():
            db["indicators"].delete_many({
                "event_uuid": event_uuid,
                "feed_id": slug,
                "_id": {"$nin": indicator_ids},
            })
        event_indicator_ids.clear()

    todo_iter = iter(todo)
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}

        def submit_next():
            try:
                uuid, timestamp, _ = next(todo_iter)
            except StopIteration:
                return
            futures[pool.submit(download, uuid)] = (uuid, timestamp)

        for _ in range(min(workers, len(todo))):
            submit_next()

        while futures:
            completed, _ = cf.wait(futures, return_when=cf.FIRST_COMPLETED)
            for fut in completed:
                uuid, ts = futures.pop(fut)
                submit_next()
                done += 1
                try:
                    _, payload = fut.result()
                except Exception as exc:
                    failures += 1
                    print(f"  ! {uuid}: {exc}", flush=True)
                    continue
                event = payload.get("Event", payload) if isinstance(payload, dict) else None
                if not isinstance(event, dict) or event.get("uuid") != uuid:
                    failures += 1
                    print(f"  ! {uuid}: invalid event payload or UUID mismatch", flush=True)
                    continue
                doc, indicators = build_documents(slug, cfg["url"], event)
                if doc is None:
                    failures += 1
                    continue
                doc["manifest_timestamp"] = ts
                event_ops.append(UpdateOne({"event_uuid": uuid, "feed_id": slug},
                                           {"$set": doc}, upsert=True))
                event_indicator_ids[uuid] = [indicator["_id"] for indicator in indicators]
                for ind in indicators:
                    indicator_ops.append(UpdateOne({"_id": ind["_id"]},
                                                   {"$set": ind}, upsert=True))
                successful_timestamps.append(ts)
                if done % 100 == 0:
                    print(f"  processed {done}/{len(todo)} ...", flush=True)
                if len(indicator_ops) >= 2000 or len(event_ops) >= 100:
                    flush_batch()
    flush_batch()

    now = datetime.now(timezone.utc)
    new_last = max(successful_timestamps, default=last_ts)
    state_update = {
        "last_run_at": now,
        "manifest_size": len(manifest),
        "events_fetched": done,
        "failures": failures,
    }
    if failures == 0:
        state_update.update({
            "last_success_at": now,
            "last_timestamp": max(new_last, last_ts),
        })
    db["sync_state"].update_one(
        {"_id": slug},
        {"$set": state_update},
        upsert=True,
    )
    print(f"  upserted events: {upserted_events}, indicators: {upserted_indicators}, failures: {failures}")
    return upserted_events, upserted_indicators, failures


def load_galaxy_names():
    names = {}
    for cluster in ("threat-actor", "malpedia", "tool"):
        try:
            data = fetch(f"https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{cluster}.json")
        except Exception as exc:
            print(f"galaxy {cluster} unavailable: {exc}")
            continue
        for v in data.get("values", []):
            entry = {
                "value": v.get("value"),
                "description": v.get("description", ""),
                "synonyms": list((v.get("meta") or {}).get("synonyms", []) or []),
                "cluster": cluster,
            }
            if entry["value"]:
                names[entry["value"].lower()] = entry
            for syn in entry["synonyms"]:
                names.setdefault(syn.lower(), entry)
    if not names:
        raise RuntimeError("No MISP Galaxy clusters could be fetched; derived rebuild aborted.")
    return names


def prepare_threat_name_matcher(galaxy):
    entries = {
        entry["value"].casefold(): entry
        for entry in galaxy.values() if entry.get("value")
    }
    variants = {}
    for canonical, entry in entries.items():
        for variant in {entry["value"], *(entry["synonyms"] or [])}:
            normalized = variant.strip().casefold()
            if (
                len(normalized) < 4
                or normalized in BLOCKLIST
                or any(word in BLOCKLIST for word in normalized.split())
            ):
                continue
            variants.setdefault(normalized, {})[canonical] = entry
    if not variants:
        return None, variants
    alternatives = sorted(variants, key=len, reverse=True)
    pattern = re.compile(
        r"(?<![A-Za-z0-9])(?P<name>"
        + "|".join(re.escape(variant) for variant in alternatives)
        + r")(?![A-Za-z0-9])",
        re.IGNORECASE,
    )
    return pattern, variants


def extract_threat_names(texts, galaxy, prepared_matcher=None):
    found = {}
    pattern, variants = prepared_matcher or prepare_threat_name_matcher(galaxy)
    if pattern is None:
        return found
    for text in texts:
        if not text:
            continue
        for match in pattern.finditer(text):
            snippet = match.group("name")
            normalized = snippet.strip().casefold()
            if " " in normalized and not snippet[0].isupper():
                continue
            found.update(variants.get(normalized, {}))
    return found


def rebuild_derived(db, mark_sync_success=True):
    """Rebuild threat_reports, threat_classifications, threat_actors, sources
    from the real feed data now in feed_events/indicators."""
    now = datetime.now(timezone.utc)

    sources = []
    feeds = []
    for slug, cfg in FEEDS.items():
        sources.append({
            "_id": f"source_{slug}",
            "name": cfg["name"],
            "provider": cfg["provider"],
            "type": "Threat Intelligence Feed",
            "url": cfg["url"],
            "source_feed_url": cfg["url"],
            "format": "MISP",
            "feed_id": slug,
        })
        feeds.append({
            "feed_id": slug,
            "name": cfg["name"],
            "provider": cfg["provider"],
            "format": "MISP",
            "feed_type": "OSINT",
            "reliability": "Unrated",
            "status": "configured",
            "url": cfg["url"],
            "source_feed_url": cfg["url"],
            "description": f"Public MISP OSINT feed synced from {cfg['url']}",
        })
    db["sources"].delete_many({})
    if sources:
        db["sources"].insert_many(sources)
    db["intelligence_feeds"].delete_many({})
    if feeds:
        db["intelligence_feeds"].insert_many(feeds)

    # Enrich older source records while preserving their original MISP data.
    for slug, cfg in FEEDS.items():
        for event in db["feed_events"].find(
            {"feed_id": slug},
            {"event_uuid": 1, "event_type": 1},
        ):
            flagged = db["indicators"].count_documents({
                "event_uuid": event["event_uuid"],
                "feed_id": slug,
                "to_ids": True,
            }) > 0
            source_fields = {
                "misp_uuid": event["event_uuid"],
                "source_feed_url": cfg["url"],
                "verdict": "IDS candidate" if flagged else "Not marked for IDS",
            }
            if event.get("event_type") == "event":
                source_fields.update({"event_type": None, "indicator_type": None})
            db["feed_events"].update_one(
                {"event_uuid": event["event_uuid"], "feed_id": slug},
                {
                    "$set": source_fields,
                    "$unset": {"status": ""},
                },
            )

    # Recompute classification from real tag data (galaxy values win)
    for ev in db["feed_events"].find({}, {"event_uuid": 1, "feed_id": 1, "tags": 1}):
        tags = list(ev.get("tags", []) or [])
        sample = db["indicators"].find_one(
            {"event_uuid": ev["event_uuid"], "feed_id": ev["feed_id"]}, {"tags": 1})
        if sample:
            tags.extend(sample.get("tags", []) or [])
        galaxy_value = None
        for t in tags:
            m = re.match(r'misp-galaxy:([^==]+)="?(.+?)"?$', t)
            if m:
                galaxy_value = m.group(2)
                break
        if galaxy_value:
            new_class = galaxy_value
        else:
            semantic = [t for t in tags
                        if not t.startswith(NON_SEMANTIC_TAG_PREFIXES)
                        and not re.match(r'^(osint|misp|creator|estimative)', t, re.I)
                        and "=" not in t]
            new_class = semantic[0] if semantic else "Unclassified"
        db["feed_events"].update_one(
            {"event_uuid": ev["event_uuid"], "feed_id": ev["feed_id"]},
            {"$set": {"classification": new_class}},
        )

    reports = []
    classifications = {}
    for ev in db["feed_events"].find({}, {"_id": 0}):
        reports.append({
            "_id": ev["event_id"],
            "title": ev["title"],
            "description": ev["description"],
            "category": ev["classification"],
            "severity": ev["severity"],
            "published_date": ev.get("published_at"),
            "event_uuid": ev["event_uuid"],
            "feed_id": ev["feed_id"],
            "source_ids": [f"source_{ev['feed_id']}"],
            "tags": ev.get("tags", []),
            "orgc": ev.get("orgc"),
        })
        key = ev["classification"]
        classifications[key] = classifications.get(key, 0) + 1
    db["threat_reports"].delete_many({})
    if reports:
        db["threat_reports"].insert_many(reports)

    db["threat_classifications"].delete_many({})
    for i, (name, count) in enumerate(sorted(classifications.items(), key=lambda kv: -kv[1]), start=1):
        db["threat_classifications"].insert_one({
            "classification_id": f"class_{i:04d}",
            "name": name,
            "event_count": count,
            "description": f"Derived from real MISP events ({count} events).",
        })

    galaxy = load_galaxy_names()
    galaxy_matcher = prepare_threat_name_matcher(galaxy)
    actor_counts = {}
    event_actor_names = {}
    for ev in db["feed_events"].find(
        {}, {"title": 1, "tags": 1, "event_uuid": 1, "feed_id": 1}
    ):
        text_pool = [ev.get("title", "") or "", *(ev.get("tags", []) or [])]
        for canonical, entry in extract_threat_names(
            text_pool, galaxy, galaxy_matcher
        ).items():
            actor_counts.setdefault(
                canonical,
                {"entry": entry, "name": entry["value"], "count": 0},
            )
            actor_counts[canonical]["count"] += 1
            event_key = (ev["feed_id"], ev["event_uuid"])
            event_actor_names.setdefault(event_key, set()).add(canonical)

    db["threat_actors"].delete_many({})
    ranked = sorted(actor_counts.items(), key=lambda kv: -kv[1]["count"])
    print("\nTop extracted threat names (manual check):")
    for value, info in ranked[:20]:
        print(f"  {info['count']:5d}  {value}  [{info['entry']['cluster']}]")
    for i, (value, info) in enumerate(ranked, start=1):
        e = info["entry"]
        db["threat_actors"].insert_one({
            "_id": f"actor_{i:04d}",
            "name": e["value"],
            "aliases": e["synonyms"],
            "description": e["description"][:2000],
            "threat_type": "Threat actor" if e["cluster"] == "threat-actor" else e["cluster"],
            "mention_count": info["count"],
            "source": e["cluster"],
        })
    print(f"threat_actors: {len(ranked)}")

    actor_name_to_id = {value: f"actor_{i:04d}" for i, (value, _) in enumerate(ranked, start=1)}
    ops = []
    for (feed_id, uuid), names in event_actor_names.items():
        ids = [actor_name_to_id[n] for n in sorted(names) if n in actor_name_to_id]
        ops.append(UpdateOne(
            {"event_uuid": uuid, "feed_id": feed_id},
            {"$set": {"threat_actor_ids": ids, "threat_actor_id": ids[0] if ids else None}},
        ))
    if ops:
        for i in range(0, len(ops), 1000):
            db["threat_reports"].bulk_write(ops[i:i + 1000])
        print(f"threat_actor links set on {len(ops)} reports")

    state_update = {
        "feeds": list(FEEDS),
        "counts": {
            "feed_events": db["feed_events"].count_documents({}),
            "indicators": db["indicators"].count_documents({}),
            "threat_reports": db["threat_reports"].count_documents({}),
            "threat_actors": db["threat_actors"].count_documents({}),
            "threat_classifications": db["threat_classifications"].count_documents({}),
            "sources": db["sources"].count_documents({}),
        },
    }
    if mark_sync_success:
        state_update["last_successful_sync"] = now
    db["sync_state"].update_one(
        {"_id": "global"},
        {"$set": state_update},
        upsert=True,
    )


def ensure_indexes(db):
    db["feed_events"].create_index([("event_uuid", 1), ("feed_id", 1)], unique=True)
    db["feed_events"].create_index([("feed_id", 1), ("misp_timestamp", -1)])
    db["feed_events"].create_index("classification")
    db["feed_events"].create_index("severity")
    db["feed_events"].create_index("misp_uuid")
    db["indicators"].create_index([("event_uuid", 1)])
    db["indicators"].create_index([("type", 1), ("value", 1)])
    db["threat_reports"].create_index("category")
    db["threat_reports"].create_index("severity")
    db["threat_reports"].create_index("published_date")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-events", type=int, default=0,
                        help="Cap events fetched per feed (quick first run). 0 = no cap.")
    parser.add_argument("--full", action="store_true",
                        help="Refetch all events, ignoring stored timestamps.")
    parser.add_argument("--feed", choices=list(FEEDS), default=None,
                        help="Sync only one feed.")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--skip-derived", action="store_true",
                        help="Do not rebuild derived collections.")
    args = parser.parse_args()
    if args.max_events < 0:
        parser.error("--max-events must be zero or greater")
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    if not MONGO_URI or not DATABASE_NAME:
        raise SystemExit("Set MONGO_URI and DATABASE_NAME in backend/.env")
    client = MongoClient(MONGO_URI)
    db = client[DATABASE_NAME]

    total_events = total_indicators = total_failures = 0
    started = time.time()
    for slug, cfg in FEEDS.items():
        if args.feed and slug != args.feed:
            continue
        try:
            e, i, failures = sync_feed(db, slug, cfg, args.max_events, args.full, args.workers)
            total_events += e
            total_indicators += i
            total_failures += failures
        except Exception as exc:
            total_failures += 1
            print(f"ERROR syncing {slug}: {exc}")

    if total_events or total_indicators:
        mark_analysis_stale(db)

    ensure_indexes(db)
    if not args.skip_derived:
        rebuild_derived(
            db,
            mark_sync_success=(total_failures == 0 and args.feed is None),
        )
    if total_failures:
        print(f"\nSync incomplete: {total_failures} feed/event failures.")
    print(f"\nDone in {time.time() - started:.1f}s. events upserted: {total_events}, indicators: {total_indicators}")
    client.close()
    if total_failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
