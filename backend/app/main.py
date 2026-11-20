from fastapi import FastAPI, Query
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from app.database import client, db
import base64
import hashlib
import ipaddress
import itertools
import json
import os
import random
import re
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
from threading import Lock
from app.cross_source import (
    MATCHES_COLLECTION,
    SOURCE_FEED_URLS,
    STATE_COLLECTION,
    analyze_collection,
    display_source,
)
from app.lab_api import router as lab_router
from app.auth import router as auth_router, ensure_users_collection
from app.lab13_api import router as lab13_router
from app.lab14_api import router as lab14_router, ensure_indexes as ensure_lab14_indexes, start_sampler as start_lab14_sampler, stop_sampler as stop_lab14_sampler
from app.cases_api import router as cases_router, ensure_indexes as ensure_case_indexes
from app.lab16_api import router as lab16_router, ensure_indexes as ensure_lab16_indexes
from app.lab17_api import router as lab17_router, ensure_indexes as ensure_lab17_indexes
from app.lab18_api import router as lab18_router, ensure_indexes as ensure_lab18_indexes

_CROSS_SOURCE_REFRESH_LOCK = Lock()

LAB_WORKING_SET_COLLECTION = "working_set_test"
LAB_WORKING_SET_SOURCE = "public MISP OSINT feeds"


@asynccontextmanager
async def lifespan(_app):
    try:
        ping = client.admin.command("ping")
        if ping and ping.get("ok"):
            db["security_reports"].create_index("report_id")
            db["security_report_passages"].create_index(
                [("year", -1), ("title", 1), ("page_number", 1)]
            )
            ensure_users_collection()
            ensure_lab14_indexes()
            ensure_case_indexes()
            ensure_lab16_indexes()
            ensure_lab17_indexes()
            ensure_lab18_indexes()
    except Exception as error:
        print(f"Startup index creation skipped (MongoDB unavailable or disconnected): {error}")
    start_lab14_sampler()
    try:
        yield
    finally:
        stop_lab14_sampler()


app = FastAPI(
    title="Cyber Threat Intelligence Platform",
    description="MongoDB based Cyber Threat Intelligence platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(lab_router)
app.include_router(auth_router)
app.include_router(lab13_router)
app.include_router(lab14_router)
app.include_router(cases_router)
app.include_router(lab16_router)
app.include_router(lab17_router)
app.include_router(lab18_router)


def _virustotal_resource(indicator: str) -> tuple[str, str]:
    value = indicator.strip()
    if not value:
        raise HTTPException(status_code=422, detail="Indicator cannot be empty.")

    try:
        ipaddress.ip_address(value)
        return "ip_addresses", value
    except ValueError:
        pass

    if re.fullmatch(r"(?i)(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value):
        return "files", value.lower()

    if value.startswith(("http://", "https://")):
        encoded_url = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return "urls", encoded_url

    if re.fullmatch(r"(?i)(?:[a-z0-9-]+\.)+[a-z]{2,}", value):
        return "domains", value.lower()

    raise HTTPException(
        status_code=422,
        detail="Enter an IP address, domain, URL, or MD5/SHA1/SHA256 hash.",
    )


@app.get("/virustotal/lookup")
def virustotal_lookup(
    indicator: str = Query(..., min_length=1, max_length=2048),
    refresh: bool = False,
):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="Set VIRUSTOTAL_API_KEY in the local service environment to enable lookups.",
        )

    resource_type, resource_id = _virustotal_resource(indicator)
    normalized_indicator = indicator.strip().lower()
    cache = db["vt_cache"]
    cached = cache.find_one({"_id": normalized_indicator})
    now = time.time()
    if cached and not refresh and now - cached.get("checked_at_epoch", 0) < 86_400:
        cached.pop("_id", None)
        cached["cached"] = True
        return cached

    request = Request(
        f"https://www.virustotal.com/api/v3/{resource_type}/{resource_id}",
        headers={"x-apikey": api_key, "accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        if error.code == 404:
            raise HTTPException(status_code=404, detail="No VirusTotal report exists for this indicator.") from error
        if error.code == 401:
            raise HTTPException(status_code=502, detail="VirusTotal rejected the configured API key.") from error
        if error.code == 429:
            raise HTTPException(
                status_code=429,
                detail="VirusTotal rate limit or daily quota reached (free tier: 4 lookups/minute, 500/day). Results are cached in MongoDB; try cached indicators or retry later.",
            ) from error
        raise HTTPException(status_code=502, detail=f"VirusTotal returned HTTP {error.code}.") from error
    except (URLError, TimeoutError) as error:
        raise HTTPException(status_code=502, detail="Could not reach VirusTotal.") from error

    attributes = payload.get("data", {}).get("attributes", {})
    result = {
        "indicator": indicator.strip(),
        "resource_type": resource_type,
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": attributes.get("last_analysis_stats"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "checked_at_epoch": now,
        "cached": False,
        "source": "VirusTotal API v3",
    }
    cache.replace_one(
        {"_id": normalized_indicator},
        {"_id": normalized_indicator, **result},
        upsert=True,
    )
    return result


@app.get("/virustotal/status")
def virustotal_status():
    return {"configured": bool(os.getenv("VIRUSTOTAL_API_KEY"))}


def _cross_source_state():
    return db[STATE_COLLECTION].find_one({"_id": "current"})


@app.get("/api/cross-source/summary")
def cross_source_summary():
    state = _cross_source_state()
    collection = db[MATCHES_COLLECTION]
    by_type = {}
    if state and state.get("status") == "ready":
        by_type = {
            row["_id"]: row["count"]
            for row in collection.aggregate(
                [{"$group": {"_id": "$entity_type", "count": {"$sum": 1}}}]
            )
        }
    if state:
        records_analyzed = state.get("records_analyzed", 0)
        sources = state.get("sources", [])
        status = state.get("status", "not_analyzed")
    else:
        source_collection = db[LAB_WORKING_SET_COLLECTION]
        records_analyzed = source_collection.count_documents({})
        sources = [
            {"source": source, "label": source, "record_count": 0}
            for source in source_collection.distinct("feed_id")
            if source
        ]
        status = "not_analyzed"
    return {
        "status": status,
        "stale": bool(state and state.get("stale")),
        "records_analyzed": records_analyzed,
        "sources": sources,
        "source_count": state.get("source_count", len(sources)) if state else len(sources),
        "common_items": state.get("common_items", 0) if state else 0,
        "by_type": by_type,
        "analyzed_at": state.get("analyzed_at") if state else None,
        "error": state.get("error") if state and status == "failed" else None,
    }


@app.get("/api/cross-source/sources")
def cross_source_sources():
    state = _cross_source_state()
    if state:
        return {"sources": state.get("sources", [])}
    collection = db[LAB_WORKING_SET_COLLECTION]
    feeds = list(
        collection.aggregate(
            [
                {
                    "$group": {
                        "_id": "$feed_id",
                        "source_feed_url": {"$first": "$source_feed_url"},
                        "record_count": {"$sum": 1},
                    }
                },
                {"$sort": {"_id": 1}},
            ]
        )
    )
    return {
        "sources": [
            {
                "source": row["_id"],
                "label": display_source(row["_id"] or "", row.get("source_feed_url")),
                "source_feed_url": row.get("source_feed_url"),
                "record_count": row["record_count"],
            }
            for row in feeds
            if row.get("_id")
        ]
    }


@app.get("/api/cross-source/overlap")
def cross_source_overlap():
    state = _cross_source_state()
    if not state or state.get("status") != "ready":
        return {"status": state.get("status") if state else "not_analyzed", "pairs": []}
    source_rows = state.get("sources", [])
    collection = db[MATCHES_COLLECTION]
    pairs = []
    for left, right in itertools.combinations(source_rows, 2):
        source_a, source_b = left["source"], right["source"]
        grouped = collection.aggregate(
            [
                {"$match": {"sources.source": {"$all": [source_a, source_b]}}},
                {"$group": {"_id": "$entity_type", "count": {"$sum": 1}}},
            ]
        )
        counts = {row["_id"]: row["count"] for row in grouped}
        if not counts:
            continue
        pairs.append(
            {
                "source_a": source_a,
                "source_a_label": left["label"],
                "source_b": source_b,
                "source_b_label": right["label"],
                "counts": counts,
                "common_items": sum(counts.values()),
            }
        )
    return {"status": "ready", "pairs": pairs}


@app.get("/api/cross-source/common")
def cross_source_common(
    entity_type: str | None = Query(None, max_length=20),
    source: str | None = Query(None, max_length=100),
    source_count: int | None = Query(None, ge=2, le=100),
    q: str | None = Query(None, max_length=120),
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    state = _cross_source_state()
    if not state or state.get("status") != "ready":
        raise HTTPException(
            status_code=409,
            detail="Run Cross-Source Analysis before requesting common data.",
        )
    query = {}
    if entity_type and entity_type != "all":
        query["entity_type"] = entity_type
    if source and source != "all":
        query["sources.source"] = source
    if source_count is not None:
        query["source_count"] = source_count if source_count < 4 else {"$gte": 4}
    if q:
        safe_query = re.escape(q.strip())
        query["$or"] = [
            {"display_value": {"$regex": safe_query, "$options": "i"}},
            {"normalized_value": {"$regex": safe_query, "$options": "i"}},
        ]
    collection = db[MATCHES_COLLECTION]
    total = collection.count_documents(query)
    items = list(
        collection.find(query)
        .sort([("source_count", -1), ("entity_type", 1), ("normalized_value", 1)])
        .skip(offset)
        .limit(limit)
    )
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/cross-source/compare")
def cross_source_compare(
    source_a: str = Query(..., min_length=1, max_length=100),
    source_b: str = Query(..., min_length=1, max_length=100),
    entity_type: str | None = Query(None, max_length=20),
    source_count: int | None = Query(None, ge=2, le=100),
    q: str | None = Query(None, max_length=120),
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    if source_a == source_b:
        raise HTTPException(status_code=422, detail="Select two different sources.")
    state = _cross_source_state()
    sources = {row["source"] for row in state.get("sources", [])} if state else set()
    if source_a not in sources or source_b not in sources:
        raise HTTPException(status_code=422, detail="One or both sources are not in the analyzed dataset.")
    query: dict[str, object] = {
        "sources.source": {"$all": [source_a, source_b]}
    }
    if entity_type and entity_type != "all":
        query["entity_type"] = entity_type
    if source_count is not None:
        query["source_count"] = source_count if source_count < 4 else {"$gte": 4}
    if q:
        safe_query = re.escape(q.strip())
        query["$or"] = [
            {"display_value": {"$regex": safe_query, "$options": "i"}},
            {"normalized_value": {"$regex": safe_query, "$options": "i"}},
        ]
    collection = db[MATCHES_COLLECTION]
    by_type = {
        row["_id"]: row["count"]
        for row in collection.aggregate(
            [
                {"$match": query},
                {"$group": {"_id": "$entity_type", "count": {"$sum": 1}}},
            ]
        )
    }
    total = collection.count_documents(query)
    items = list(
        collection.find(query)
        .sort([("entity_type", 1), ("normalized_value", 1)])
        .skip(offset)
        .limit(limit)
    )
    return {"source_a": source_a, "source_b": source_b, "by_type": by_type,
            "items": items, "total": total, "limit": limit, "offset": offset}


@app.get("/api/cross-source/evidence/{match_id}")
def cross_source_evidence(match_id: str):
    item = db[MATCHES_COLLECTION].find_one({"_id": match_id})
    if not item:
        raise HTTPException(status_code=404, detail="Common item not found.")
    return {
        "item": item,
        "explanation": (
            f"The exact normalized value {item['display_value']} was found in "
            f"{item['source_count']} distinct source feeds."
        ),
        "collection": LAB_WORKING_SET_COLLECTION,
    }


@app.post("/api/cross-source/refresh")
def refresh_cross_source_analysis():
    if not _CROSS_SOURCE_REFRESH_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Cross-Source Analysis is already running.")
    try:
        return analyze_collection(db)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    finally:
        _CROSS_SOURCE_REFRESH_LOCK.release()


# =========================
# BASIC
# =========================

@app.get("/")
def root():
    frontend = Path(__file__).resolve().parents[2] / "frontend"
    return FileResponse(frontend / "index.html")


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "database": "MongoDB",
        "database_name": "cyber_threat_intelligence"
    }


@app.get("/sync-status")
def sync_status():
    global_state = db["sync_state"].find_one({"_id": "global"}) or {}
    feed_states = list(db["sync_state"].find({"_id": {"$ne": "global"}}, {"_id": 1, "last_run_at": 1, "last_success_at": 1, "events_fetched": 1, "manifest_size": 1}))
    return {
        "last_successful_sync": global_state.get("last_successful_sync"),
        "counts": global_state.get("counts", {}),
        "feeds": feed_states,
    }


# =========================
# STATISTICS
# =========================

@app.get("/stats")
def stats():
    return {
        "threat_reports": db["threat_reports"].count_documents({}),
        "threat_actors": db["threat_actors"].count_documents({}),
        "indicators": db["indicators"].count_documents({}),
        "working_set_indicators": db[LAB_WORKING_SET_COLLECTION].count_documents({}),
        "sources": db["sources"].count_documents({}),
        "vulnerabilities": db["vulnerabilities"].count_documents({}),
        "security_reports": db["security_reports"].count_documents({}),
        "security_report_passages": db["security_report_passages"].count_documents({}),
        "intelligence_feeds": db["intelligence_feeds"].count_documents({}),
        "feed_events": db["feed_events"].count_documents({}),
        "classifications": db["threat_classifications"].count_documents({})
    }


# =========================
# THREAT REPORTS
# =========================

@app.get("/reports")
def get_reports(limit: int = Query(20, ge=1, le=100)):
    reports = list(
        db["threat_reports"]
        .find({}, {"_id": 0})
        .limit(limit)
    )

    return {
        "count": len(reports),
        "reports": reports
    }


@app.get("/reports/search")
def search_reports(q: str):
    query = {
        "$or": [
            {"title": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"category": {"$regex": q, "$options": "i"}},
            {"severity": {"$regex": q, "$options": "i"}}
        ]
    }

    reports = list(
        db["threat_reports"]
        .find(query, {"_id": 0})
        .limit(50)
    )

    return {
        "query": q,
        "count": len(reports),
        "results": reports
    }


# =========================
# THREAT ACTORS
# =========================

@app.get("/actors")
def get_actors():
    actors = list(
        db["threat_actors"]
        .find({}, {"_id": 0})
    )

    return {
        "count": len(actors),
        "actors": actors
    }


# =========================
# INDICATORS
# =========================

@app.get("/indicators")
def get_indicators():
    indicators = list(
        db["indicators"]
        .find({}, {"_id": 0})
        .limit(100)
    )

    return {
        "count": len(indicators),
        "indicators": indicators
    }


# =========================
# VULNERABILITIES
# =========================

@app.get("/vulnerabilities")
def get_vulnerabilities():
    vulnerabilities = list(
        db["vulnerabilities"]
        .find({}, {"_id": 0})
        .limit(100)
    )

    return {
        "count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }


# =========================
# INTELLIGENCE FEEDS
# =========================

@app.get("/feeds")
def get_feeds():
    feeds = list(
        db["intelligence_feeds"]
        .find({}, {"_id": 0})
    )

    return {
        "count": len(feeds),
        "feeds": feeds
    }


# =========================
# CTI FEED EVENTS
# =========================

@app.get("/feed-events")
def get_feed_events(
    limit: int = Query(50, ge=1, le=10_000)
):
    events = list(
        db["feed_events"]
        .find({}, {"_id": 0})
        .limit(limit)
    )

    return {
        "count": len(events),
        "events": events
    }


# =========================
# SEARCH CTI EVENTS
# =========================

@app.get("/feed-events/search")
def search_feed_events(q: str):
    query = {
        "$or": [
            {"title": {"$regex": q, "$options": "i"}},
            {"indicator_value": {"$regex": q, "$options": "i"}},
            {"classification": {"$regex": q, "$options": "i"}},
            {"severity": {"$regex": q, "$options": "i"}},
            {"event_type": {"$regex": q, "$options": "i"}}
        ]
    }

    events = list(
        db["feed_events"]
        .find(query, {"_id": 0})
        .limit(100)
    )

    return {
        "query": q,
        "count": len(events),
        "results": events
    }


# =========================
# CLASSIFICATIONS
# =========================

@app.get("/classifications")
def get_classifications():
    classifications = list(
        db["threat_classifications"]
        .find({}, {"_id": 0})
    )

    return {
        "count": len(classifications),
        "classifications": classifications
    }


# =========================
# THREAT SUMMARY
# =========================

@app.get("/threat-summary")
def threat_summary():

    total_events = db["feed_events"].count_documents({})

    severity_pipeline = [
        {
            "$group": {
                "_id": "$severity",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {
                "count": -1
            }
        }
    ]

    classification_pipeline = [
        {
            "$group": {
                "_id": "$classification",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {
                "count": -1
            }
        }
    ]

    severity = list(
        db["feed_events"].aggregate(severity_pipeline)
    )

    classifications = list(
        db["feed_events"].aggregate(classification_pipeline)
    )

    return {
        "total_events": total_events,
        "by_severity": severity,
        "by_classification": classifications
    }


# =========================
# VERIFICATION LIBRARY
# =========================

@app.get("/verification-library")
def verification_library(
    q: str = Query("", max_length=200),
    limit: int = Query(20, ge=1, le=100)
):
    query = {}

    if q.strip():
        search_term = re.escape(q.strip())
        query = {
            "$or": [
                {"title": {"$regex": search_term, "$options": "i"}},
                {"passage": {"$regex": search_term, "$options": "i"}},
                {"source": {"$regex": search_term, "$options": "i"}}
            ]
        }

    passages = list(db["security_report_passages"].aggregate([
        {"$match": query},
        {"$sort": {"year": -1, "title": 1, "page_number": 1}},
        {"$group": {
            "_id": "$report_id",
            "report_id": {"$first": "$report_id"},
            "title": {"$first": "$title"},
            "year": {"$first": "$year"},
            "source": {"$first": "$source"},
            "file_name": {"$first": "$file_name"},
            "page_number": {"$first": "$page_number"},
            "passage": {"$first": "$passage"},
        }},
        {"$sort": {"year": -1, "title": 1}},
        {"$limit": limit},
        {"$project": {"_id": 0}},
    ]))

    for passage in passages:
        year = quote(str(passage.get("year", "")), safe="")
        markdown_file = passage.get("file_name") or f"{passage.get('source', 'report')}.md"
        markdown_name = quote(markdown_file, safe="")
        pdf_name = quote(Path(markdown_file).with_suffix(".pdf").name, safe="")
        report_id = quote(str(passage.get("report_id", "")), safe="")
        passage["markdown_url"] = (
            f"/verification-library/reports/{report_id}/markdown"
        )
        passage["markdown_source_url"] = (
            "https://github.com/jacobdjwilson/awesome-annual-security-reports/"
            f"blob/main/Markdown%20Conversions/{year}/{markdown_name}"
        )
        passage["pdf_url"] = (
            "https://github.com/jacobdjwilson/awesome-annual-security-reports/"
            f"blob/main/Annual%20Security%20Reports/{year}/{pdf_name}"
        )

    return {
        "count": len(passages),
        "results": passages
    }


@app.get("/verification-library/reports/{report_id}/markdown")
def get_verification_report_markdown(report_id: str):
    report = db["security_reports"].find_one(
        {"report_id": report_id},
        {"_id": 0, "file_name": 1, "content": 1},
    )
    if report is None:
        raise HTTPException(status_code=404, detail="Security report was not found.")

    content = report.get("content")
    if not content:
        raise HTTPException(
            status_code=404,
            detail="Markdown content is not stored for this security report.",
        )

    filename = quote(report.get("file_name") or f"{report_id}.md", safe="")
    return PlainTextResponse(
        content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"inline; filename*=UTF-8''{filename}"},
    )


# =========================
# WORKING SET
# =========================

@app.get("/working-set")
def working_set():
    collection_name = LAB_WORKING_SET_COLLECTION
    if collection_name not in db.list_collection_names():
        raise HTTPException(
            status_code=409,
            detail="Lab 7.2 dataset is missing. Run python -m scripts.fetch_working_set.",
        )
    collection = db[collection_name]

    stats_data = db.command(
        "collStats",
        collection_name
    )
    status = db.command("serverStatus")
    cache = status.get("wiredTiger", {}).get("cache", {})
    maximum_cache = cache.get("maximum bytes configured")
    current_cache = cache.get("bytes currently in the cache")
    storage_engine = status.get("storageEngine", {}).get("name")
    footprint_bytes = stats_data.get("size", 0) + stats_data.get("totalIndexSize", 0)
    cache_available = (
        storage_engine == "wiredTiger"
        and bool(cache)
        and maximum_cache is not None
    )

    return {
        "collection": collection_name,
        "source_collection": LAB_WORKING_SET_SOURCE,
        "documents": collection.count_documents({}),
        "average_document_size_bytes": stats_data.get("avgObjSize"),
        "data_size_mb": round(
            stats_data.get("size", 0) / (1024 * 1024),
            2
        ),
        "index_size_mb": round(
            stats_data.get("totalIndexSize", 0) / (1024 * 1024),
            2
        ),
        "data_plus_index_size_mb": round(
            (stats_data.get("size", 0) + stats_data.get("totalIndexSize", 0))
            / (1024 * 1024),
            2
        ),
        "mongodb_version": status.get("version"),
        "storage_engine": storage_engine,
        "wiredTiger_cache_available": cache_available,
        "cache_maximum_bytes": maximum_cache,
        "cache_current_bytes": current_cache,
        "wiredTiger_cache_fill_percent": (
            round(current_cache / maximum_cache * 100, 2)
            if current_cache is not None and maximum_cache
            else None
        ),
        "dataset_to_cache_capacity_percent": (
            round(footprint_bytes / maximum_cache * 100, 2)
            if maximum_cache
            else None
        ),
        "cache_metrics_note": (
            "WiredTiger cache usage is process-wide and includes all collections; "
            "the dataset footprint/cache-capacity ratio is not actual residency."
            if cache_available else
            "This MongoDB deployment does not expose WiredTiger cache capacity; "
            "cache usage and residency cannot be reported."
        )
    }


def _random_document_ids(collection, reads):
    total = collection.count_documents({})
    if not total:
        return []
    sampled = list(collection.aggregate([
        {"$sample": {"size": min(total, reads)}},
        {"$project": {"_id": 1}},
    ]))
    ids = [document["_id"] for document in sampled]
    return random.choices(ids, k=reads) if ids else []


def _cache_snapshot():
    status = db.command("serverStatus")
    cache = status.get("wiredTiger", {}).get("cache", {})
    return {
        "cache": cache,
        "pages_read": cache.get("pages read into cache"),
        "pages_requested": cache.get("pages requested from the cache"),
        "evicted_pages": cache.get("pages evicted by application threads"),
    }


@app.get("/working-set/benchmark")
def working_set_benchmark(reads: int = Query(500, ge=1, le=5000)):
    collection = db[LAB_WORKING_SET_COLLECTION]
    total_documents = collection.count_documents({})
    if total_documents == 0:
        raise HTTPException(
            status_code=409,
            detail="Lab 7.2 dataset is empty. Run python -m scripts.fetch_working_set.",
        )

    random_ids = _random_document_ids(collection, reads)
    before = _cache_snapshot()
    latencies_ms = []
    found = 0
    for random_id in random_ids:
        start = time.perf_counter()
        document = collection.find_one(
            {"_id": random_id},
            {"_id": 1, "event_uuid": 1, "type": 1, "value": 1},
        )
        latencies_ms.append((time.perf_counter() - start) * 1000)
        found += document is not None

    after = _cache_snapshot()
    ordered = sorted(latencies_ms)
    p95_index = max(0, (len(ordered) * 95 + 99) // 100 - 1)
    pages_read_delta = None
    evicted_pages_delta = None
    if before["pages_read"] is not None and after["pages_read"] is not None:
        pages_read_delta = after["pages_read"] - before["pages_read"]
    if before["evicted_pages"] is not None and after["evicted_pages"] is not None:
        evicted_pages_delta = after["evicted_pages"] - before["evicted_pages"]

    return {
        "collection": LAB_WORKING_SET_COLLECTION,
        "source_collection": LAB_WORKING_SET_SOURCE,
        "documents": total_documents,
        "reads_requested": reads,
        "reads_found": found,
        "average_latency_ms": round(sum(latencies_ms) / len(latencies_ms), 3),
        "median_latency_ms": round(ordered[len(ordered) // 2], 3),
        "p95_latency_ms": round(ordered[p95_index], 3),
        "minimum_latency_ms": round(ordered[0], 3),
        "maximum_latency_ms": round(ordered[-1], 3),
        "disk_page_reads_delta": pages_read_delta,
        "evicted_pages_delta": evicted_pages_delta,
        "cache_counters_available": pages_read_delta is not None,
        "note": (
            "Latency includes client/network round-trip. Cache page-read and eviction "
            "deltas are process-wide WiredTiger counters, so concurrent queries can "
            "contribute."
        ),
    }


@app.get("/working-set/benchmark/stream")
def working_set_benchmark_stream(reads: int = Query(500, ge=1, le=5000)):
    collection = db[LAB_WORKING_SET_COLLECTION]
    total_documents = collection.count_documents({})
    if total_documents == 0:
        raise HTTPException(
            status_code=409,
            detail="Lab 7.2 dataset is empty. Run python -m scripts.fetch_working_set.",
        )

    def emit_progress():
        random_ids = _random_document_ids(collection, reads)
        before = _cache_snapshot()
        latencies_ms = []
        found = 0
        chunk_size = 25
        started_at = time.perf_counter()

        for completed, random_id in enumerate(random_ids, start=1):
            read_started = time.perf_counter()
            document = collection.find_one(
                {"_id": random_id},
                {"_id": 1, "event_uuid": 1, "type": 1, "value": 1},
            )
            latencies_ms.append((time.perf_counter() - read_started) * 1000)
            found += document is not None

            if completed % chunk_size == 0 or completed == reads:
                elapsed = time.perf_counter() - started_at
                batch_start = max(0, completed - chunk_size)
                batch_latencies = latencies_ms[batch_start:completed]
                yield json.dumps({
                    "type": "progress",
                    "completed": completed,
                    "total": reads,
                    "elapsed_seconds": round(elapsed, 2),
                    "batch_average_latency_ms": round(
                        sum(batch_latencies) / len(batch_latencies), 3
                    ),
                    "batch_minimum_latency_ms": round(min(batch_latencies), 3),
                    "batch_maximum_latency_ms": round(max(batch_latencies), 3),
                }) + "\n"

        after = _cache_snapshot()
        ordered = sorted(latencies_ms)
        p95_index = max(0, (len(ordered) * 95 + 99) // 100 - 1)
        pages_read_delta = None
        evicted_pages_delta = None
        if before["pages_read"] is not None and after["pages_read"] is not None:
            pages_read_delta = after["pages_read"] - before["pages_read"]
        if before["evicted_pages"] is not None and after["evicted_pages"] is not None:
            evicted_pages_delta = after["evicted_pages"] - before["evicted_pages"]

        result = {
            "type": "result",
            "collection": LAB_WORKING_SET_COLLECTION,
            "source_collection": LAB_WORKING_SET_SOURCE,
            "documents": total_documents,
            "reads_requested": reads,
            "reads_found": found,
            "average_latency_ms": round(sum(latencies_ms) / len(latencies_ms), 3),
            "median_latency_ms": round(ordered[len(ordered) // 2], 3),
            "p95_latency_ms": round(ordered[p95_index], 3),
            "minimum_latency_ms": round(ordered[0], 3),
            "maximum_latency_ms": round(ordered[-1], 3),
            "disk_page_reads_delta": pages_read_delta,
            "evicted_pages_delta": evicted_pages_delta,
            "cache_counters_available": pages_read_delta is not None,
            "note": (
                "Latency includes client/network round-trip. Cache page-read and eviction "
                "deltas are process-wide WiredTiger counters, so concurrent queries can "
                "contribute."
            ),
        }
        yield json.dumps(result) + "\n"

    return StreamingResponse(
        emit_progress(),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )


@app.get("/working-set/reports")
def working_set_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(30, ge=1, le=100),
    q: str = Query("", max_length=200),
    category: str = Query("", max_length=100),
    indicator_type: str = Query("", max_length=100),
    source: str = Query("", max_length=100),
):
    collection = db[LAB_WORKING_SET_COLLECTION]
    query: dict[str, Any] = {}
    if q.strip():
        term = re.escape(q.strip())
        matching_events = list(db["feed_events"].find(
            {"$or": [
                {"title": {"$regex": term, "$options": "i"}},
                {"description": {"$regex": term, "$options": "i"}},
                {"classification": {"$regex": term, "$options": "i"}},
                {"severity": {"$regex": term, "$options": "i"}},
                {"tags": {"$regex": term, "$options": "i"}},
            ]},
            {"_id": 0, "event_uuid": 1, "feed_id": 1},
        ))
        search_filters: list[dict[str, Any]] = [
            {"value": {"$regex": term, "$options": "i"}},
            {"type": {"$regex": term, "$options": "i"}},
            {"category": {"$regex": term, "$options": "i"}},
            {"comment": {"$regex": term, "$options": "i"}},
        ]
        for event in matching_events:
            event_filter: dict[str, Any] = {
                "event_uuid": event["event_uuid"],
                "feed_id": event["feed_id"],
            }
            search_filters.append(event_filter)
        query["$or"] = search_filters
    if category:
        matching_events = db["feed_events"].distinct(
            "event_uuid", {"classification": category}
        )
        query["event_uuid"] = {"$in": matching_events}
    if indicator_type:
        query["type"] = indicator_type
    if source:
        query["feed_id"] = source

    total = collection.count_documents(query)
    indicators = list(
        collection.find(
            query,
            {
                "_id": 1,
                "event_uuid": 1,
                "feed_id": 1,
                "source": 1,
                "type": 1,
                "value": 1,
                "category": 1,
                "to_ids": 1,
                "tags": 1,
                "comment": 1,
                "source_feed_url": 1,
                "misp_attribute_uuid": 1,
            },
        )
        .sort("_id", 1)
        .skip(skip)
        .limit(limit)
    )
    event_refs = [
        {"event_uuid": item["event_uuid"], "feed_id": item["feed_id"]}
        for item in indicators
    ]
    events = {
        (event.get("feed_id"), event.get("event_uuid")): event
        for event in db["feed_events"].find(
            {"$or": event_refs} if event_refs else {"_id": {"$exists": False}},
            {
                "_id": 0,
                "event_uuid": 1,
                "feed_id": 1,
                "event_id": 1,
                "title": 1,
                "description": 1,
                "published_at": 1,
                "classification": 1,
                "severity": 1,
                "tags": 1,
                "source_feed_url": 1,
                "verdict": 1,
            },
        )
    }
    records = []
    for indicator in indicators:
        event = events.get((indicator["feed_id"], indicator["event_uuid"]), {})
        records.append({
            "report_id": event.get("event_id"),
            "event_uuid": indicator["event_uuid"],
            "feed_id": indicator["feed_id"],
            "source": indicator.get("source"),
            "source_feed_url": (
                event.get("source_feed_url")
                or indicator.get("source_feed_url")
            ),
            "title": event.get("title"),
            "description": event.get("description"),
            "category": event.get("classification"),
            "severity": event.get("severity"),
            "published_at": event.get("published_at"),
            "created_at": event.get("published_at"),
            "indicator_value": indicator.get("value"),
            "indicator_type": indicator.get("type"),
            "event_type": indicator.get("type"),
            "to_ids": indicator.get("to_ids", False),
            "verdict": (
                "IDS candidate" if indicator.get("to_ids")
                else "Not marked for IDS"
            ),
            "tags": list(dict.fromkeys(
                (event.get("tags") or []) + (indicator.get("tags") or [])
            )),
        })
    feed_metadata = list(db["intelligence_feeds"].find(
        {}, {"_id": 0, "feed_id": 1, "name": 1}
    ))
    return {
        "collection": LAB_WORKING_SET_COLLECTION,
        "total": total,
        "skip": skip,
        "limit": limit,
        "results": records,
        "types": sorted(value for value in collection.distinct("type") if value),
        "categories": sorted(
            value for value in db["feed_events"].distinct("classification") if value
        ),
        "sources": feed_metadata,
        "feed_metadata": feed_metadata,
    }


@app.get("/working-set/event-groups")
def working_set_event_groups(
    skip: int = Query(0, ge=0),
    limit: int = Query(30, ge=1, le=100),
    q: str = Query("", max_length=200),
    category: str = Query("", max_length=100),
    indicator_type: str = Query("", max_length=100),
    source: str = Query("", max_length=100),
):
    collection = db[LAB_WORKING_SET_COLLECTION]
    valid_sources = [
        {
            "feed_id": feed_id,
            "source": feed_id,
            "source_feed_url": feed_url,
        }
        for feed_id, feed_url in SOURCE_FEED_URLS.items()
    ]
    initial_match: dict[str, Any] = {
        "$and": [
            {"$or": valid_sources},
            {"event_uuid": {"$type": "string", "$ne": ""}},
            {"misp_attribute_uuid": {"$type": "string", "$ne": ""}},
            {"type": {"$type": "string", "$ne": ""}},
            {"value": {"$type": "string", "$ne": ""}},
        ]
    }
    if source:
        initial_match["feed_id"] = source
    if indicator_type:
        initial_match["type"] = indicator_type
    if q.strip():
        term = re.escape(q.strip())
        attribute_search: dict[str, Any] = {
            "$or": [
                {"value": {"$regex": term, "$options": "i"}},
                {"type": {"$regex": term, "$options": "i"}},
                {"category": {"$regex": term, "$options": "i"}},
                {"comment": {"$regex": term, "$options": "i"}},
                {"tags": {"$regex": term, "$options": "i"}},
            ]
        }
        candidate_sources = {
            feed_id: feed_url
            for feed_id, feed_url in SOURCE_FEED_URLS.items()
            if not source or source == feed_id
        }
        matching_event_ids: dict[str, list[str]] = {}
        if candidate_sources:
            matching_events = db["feed_events"].find(
                {
                    "$and": [
                        {
                            "$or": [
                                {
                                    "feed_id": feed_id,
                                    "source_feed_url": feed_url,
                                }
                                for feed_id, feed_url in candidate_sources.items()
                            ]
                        },
                        {"title": {"$regex": r"\S"}},
                        {
                            "$or": [
                                {"title": {"$regex": term, "$options": "i"}},
                                {"description": {"$regex": term, "$options": "i"}},
                                {"classification": {"$regex": term, "$options": "i"}},
                                {"tags": {"$regex": term, "$options": "i"}},
                            ]
                        },
                    ]
                },
                {"_id": 0, "feed_id": 1, "event_uuid": 1},
            )
            for event in matching_events:
                event_id = event.get("event_uuid")
                if isinstance(event_id, str) and event_id:
                    matching_event_ids.setdefault(event["feed_id"], []).append(event_id)
        search_branches: list[dict[str, Any]] = [attribute_search]
        search_branches.extend(
            {
                "feed_id": feed_id,
                "event_uuid": {"$in": event_ids},
            }
            for feed_id, event_ids in matching_event_ids.items()
        )
        initial_match["$and"].append({"$or": search_branches})

    event_lookup = {
        "$lookup": {
            "from": "feed_events",
            "let": {"feed_id": "$feed_id", "event_uuid": "$event_uuid"},
            "pipeline": [
                {
                    "$match": {
                        "$expr": {
                            "$and": [
                                {"$eq": ["$feed_id", "$$feed_id"]},
                                {"$eq": ["$event_uuid", "$$event_uuid"]},
                            ]
                        }
                    }
                },
                {
                    "$project": {
                        "_id": 0,
                        "title": 1,
                        "description": 1,
                        "classification": 1,
                        "severity": 1,
                        "published_at": 1,
                        "tags": 1,
                        "source_feed_url": 1,
                        "verdict": 1,
                    }
                },
            ],
            "as": "_event",
        }
    }
    valid_event_match = {
        "$match": {
            "$and": [
                {
                    "$or": [
                        {
                            "feed_id": feed_id,
                            "_event.source_feed_url": feed_url,
                        }
                        for feed_id, feed_url in SOURCE_FEED_URLS.items()
                    ]
                },
                {"_event.title": {"$regex": r"\S"}},
            ]
        }
    }
    group_stage = {
        "$group": {
            "_id": {"feed_id": "$feed_id", "event_uuid": "$event_uuid"},
            "feed_id": {"$first": "$feed_id"},
            "event_uuid": {"$first": "$event_uuid"},
            "source": {"$first": "$source"},
            "source_feed_url": {"$first": "$source_feed_url"},
            "indicator_count": {"$sum": 1},
            "indicators": {
                "$topN": {
                    "n": 10,
                    "sortBy": {"type": 1, "value": 1, "_id": 1},
                    "output": {
                        "value": "$value",
                        "type": "$type",
                        "category": "$category",
                        "to_ids": "$to_ids",
                        "tags": "$tags",
                        "comment": "$comment",
                        "misp_attribute_uuid": "$misp_attribute_uuid",
                    },
                }
            },
        }
    }
    pipeline = [
        {"$match": initial_match},
        group_stage,
        event_lookup,
        {"$unwind": "$_event"},
        valid_event_match,
    ]
    if category:
        pipeline.append({"$match": {"_event.classification": category}})
    pipeline.extend(
        [
            {
                "$set": {
                    "title": "$_event.title",
                    "description": "$_event.description",
                    "classification": "$_event.classification",
                    "severity": "$_event.severity",
                    "published_at": "$_event.published_at",
                    "tags": "$_event.tags",
                    "verdict": "$_event.verdict",
                }
            },
            {"$unset": "_event"},
        ]
    )
    pipeline.extend(
        [
            {"$sort": {"published_at": -1, "feed_id": 1, "event_uuid": 1}},
            {
                "$facet": {
                    "items": [{"$skip": skip}, {"$limit": limit}],
                    "totals": [
                        {
                            "$group": {
                                "_id": None,
                                "total": {"$sum": 1},
                                "total_indicators": {"$sum": "$indicator_count"},
                            }
                        }
                    ],
                }
            },
        ]
    )
    facet = next(iter(collection.aggregate(pipeline, allowDiskUse=True)), {})
    totals = next(iter(facet.get("totals", [])), {})
    feed_metadata = list(
        db["intelligence_feeds"].find(
            {}, {"_id": 0, "feed_id": 1, "name": 1}
        )
    )
    return {
        "collection": LAB_WORKING_SET_COLLECTION,
        "total": totals.get("total", 0),
        "total_indicators": totals.get("total_indicators", 0),
        "skip": skip,
        "limit": limit,
        "results": facet.get("items", []),
        "types": sorted(
            value
            for value in collection.distinct("type", {"feed_id": {"$in": list(SOURCE_FEED_URLS)}})
            if value
        ),
        "categories": sorted(
            value for value in db["feed_events"].distinct("classification") if value
        ),
        "sources": feed_metadata,
        "feed_metadata": feed_metadata,
    }


@app.get("/working-set/event-groups/{feed_id}/{event_uuid}/indicators")
def working_set_event_indicators(
    feed_id: str,
    event_uuid: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=50),
    q: str = Query("", max_length=200),
    category: str = Query("", max_length=100),
    indicator_type: str = Query("", max_length=100),
):
    feed_url = SOURCE_FEED_URLS.get(feed_id)
    if not feed_url:
        raise HTTPException(status_code=404, detail="Source feed not found.")
    event_query = {
        "feed_id": feed_id,
        "event_uuid": event_uuid,
        "source_feed_url": feed_url,
        "title": {"$regex": r"\S"},
    }
    event = db["feed_events"].find_one(
        event_query,
        {
            "_id": 0,
            "classification": 1,
            "title": 1,
            "description": 1,
            "tags": 1,
        },
    )
    if not event or (category and event.get("classification") != category):
        raise HTTPException(status_code=404, detail="Valid MISP event not found.")
    query: dict[str, object] = {
        "feed_id": feed_id,
        "source": feed_id,
        "source_feed_url": feed_url,
        "event_uuid": event_uuid,
        "misp_attribute_uuid": {"$type": "string", "$ne": ""},
        "type": {"$type": "string", "$ne": ""},
        "value": {"$type": "string", "$ne": ""},
    }
    if indicator_type:
        query["type"] = indicator_type
    normalized_query = q.strip().casefold()
    event_searchable = " ".join(
        str(value)
        for value in [
            event.get("title"),
            event.get("description"),
            event.get("classification"),
            *(event.get("tags") or []),
        ]
        if value is not None
    ).casefold()
    if normalized_query and normalized_query not in event_searchable:
        term = re.escape(normalized_query)
        query["$or"] = [
            {"value": {"$regex": term, "$options": "i"}},
            {"type": {"$regex": term, "$options": "i"}},
            {"category": {"$regex": term, "$options": "i"}},
            {"comment": {"$regex": term, "$options": "i"}},
            {"tags": {"$regex": term, "$options": "i"}},
        ]
    collection = db[LAB_WORKING_SET_COLLECTION]
    total = collection.count_documents(query)
    items = list(
        collection.find(
            query,
            {
                "_id": 0,
                "value": 1,
                "type": 1,
                "category": 1,
                "to_ids": 1,
                "tags": 1,
                "comment": 1,
                "misp_attribute_uuid": 1,
            },
        )
        .sort([("type", 1), ("value", 1), ("_id", 1)])
        .skip(skip)
        .limit(limit)
    )
    return {"items": items, "total": total, "skip": skip, "limit": limit}


def _missing_annual_reports():
    reports_path = (
        Path(__file__).resolve().parents[2]
        / "awesome-annual-security-reports"
        / "Markdown Conversions"
    )
    if not reports_path.is_dir():
        raise HTTPException(
            status_code=503,
            detail="Annual report clone is missing. Clone awesome-annual-security-reports beside backend/.",
        )

    existing = {
        (document.get("year"), document.get("file_name"))
        for document in db["security_reports"].find(
            {}, {"_id": 0, "year": 1, "file_name": 1}
        )
    }
    missing = []
    for report_path in reports_path.rglob("*.md"):
        relative_path = report_path.relative_to(reports_path).as_posix()
        year = report_path.parent.name
        if (year, report_path.name) not in existing:
            missing.append({
                "relative_path": relative_path,
                "file_name": report_path.name,
                "source": report_path.stem,
                "year": year,
                "title": report_path.stem.replace("-", " "),
            })
    return reports_path, sorted(missing, key=lambda item: (item["year"], item["file_name"]))


@app.get("/annual-reports/missing")
def annual_reports_missing(limit: int = Query(100, ge=1, le=500)):
    try:
        _, missing = _missing_annual_reports()
    except HTTPException as error:
        if error.status_code != 503:
            raise
        return {
            "available": False,
            "message": error.detail,
            "missing_count": 0,
            "results": [],
        }
    return {
        "available": True,
        "missing_count": len(missing),
        "results": missing[:limit],
    }


@app.post("/annual-reports/sync")
def sync_annual_reports(limit: int = Query(100, ge=1, le=1000)):
    reports_path, missing = _missing_annual_reports()
    inserted_reports = 0
    inserted_passages = 0
    report_collection = db["security_reports"]
    passage_collection = db["security_report_passages"]

    for item in missing[:limit]:
        file_path = reports_path / Path(item["relative_path"])
        content = re.sub(r"\n{3,}", "\n\n", file_path.read_text(
            encoding="utf-8", errors="ignore"
        ).replace("\x00", "")).strip()
        if not content:
            continue

        heading = re.search(r"^\s*#\s+(.+)", content, re.MULTILINE)
        report_id = "annual_" + hashlib.sha1(
            item["relative_path"].encode("utf-8")
        ).hexdigest()[:16]
        report = {
            "report_id": report_id,
            "year": item["year"],
            "title": heading.group(1).strip() if heading else item["title"],
            "source": item["source"],
            "file_name": item["file_name"],
            "relative_path": item["relative_path"],
            "content": content,
            "content_size_bytes": len(content.encode("utf-8")),
            "dataset": "Awesome Annual Security Reports",
        }
        result = report_collection.update_one(
            {"report_id": report_id}, {"$setOnInsert": report}, upsert=True
        )
        if not result.upserted_id:
            continue
        inserted_reports += 1

        words = content.split()
        for page_number, start_index in enumerate(range(0, len(words), 500), start=1):
            passage_collection.insert_one({
                "report_id": report_id,
                "title": report["title"],
                "year": item["year"],
                "source": item["source"],
                "file_name": item["file_name"],
                "relative_path": item["relative_path"],
                "page_number": page_number,
                "passage": " ".join(words[start_index:start_index + 500]),
                "dataset": "Awesome Annual Security Reports",
            })
            inserted_passages += 1

    _, remaining = _missing_annual_reports()
    return {
        "reports_inserted": inserted_reports,
        "passages_inserted": inserted_passages,
        "remaining_missing": len(remaining),
        "processed_limit": limit,
    }


# =========================
# CACHE TEST
# =========================

@app.get("/cache-test")
def cache_test(iterations: int = Query(20, ge=1, le=100)):

    collection = db[LAB_WORKING_SET_COLLECTION]
    total_documents = collection.count_documents({})
    if total_documents == 0:
        raise HTTPException(
            status_code=409,
            detail="Lab 7.2 dataset is empty. Run python -m scripts.fetch_working_set.",
        )

    samples = []
    random_ids = _random_document_ids(collection, iterations)

    for i, random_id in enumerate(random_ids):

        start = time.perf_counter()

        document = collection.find_one(
            {"_id": random_id},
            {
                "_id": 1,
                "event_uuid": 1,
                "type": 1,
                "value": 1,
            }
        )

        elapsed = time.perf_counter() - start

        samples.append({
            "iteration": i + 1,
            "latency_ms": round(elapsed * 1000, 3),
            "found": document is not None
        })

    average_latency = sum(
        x["latency_ms"] for x in samples
    ) / len(samples)

    return {
        "collection": LAB_WORKING_SET_COLLECTION,
        "source_collection": LAB_WORKING_SET_SOURCE,
        "iterations": iterations,
        "average_latency_ms": round(
            average_latency,
            3
        ),
        "samples": samples
    }

# =========================
# WIREDTIGER CACHE METRICS
# =========================

@app.get("/metrics")
def get_metrics():

    try:
        # Get MongoDB server status
        status = db.command("serverStatus")

        # Get WiredTiger cache information
        wired_tiger = status.get("wiredTiger", {})
        cache = wired_tiger.get("cache", {})

        maximum_cache = cache.get("maximum bytes configured")
        current_cache = cache.get("bytes currently in the cache")
        pages_requested = cache.get("pages requested from the cache")
        pages_read = cache.get("pages read into cache")
        pages_written = cache.get("pages written from cache")

        fill_percent = (
            current_cache / maximum_cache * 100
            if current_cache is not None and maximum_cache
            else None
        )
        page_read_fraction = (
            pages_read / pages_requested * 100
            if pages_read is not None and pages_requested
            else None
        )

        return {
            "wiredTiger_available": (
                status.get("storageEngine", {}).get("name") == "wiredTiger"
                and bool(cache)
            ),
            "storage_engine": status.get("storageEngine", {}).get("name"),

            "cache": {
                "maximum_bytes": maximum_cache,

                "current_bytes": current_cache,

                "fill_percent": round(
                    fill_percent,
                    2
                ) if fill_percent is not None else None,

                "pages_requested": pages_requested,

                "pages_read": pages_read,

                "pages_written": pages_written,

                "page_read_fraction_since_start_percent": (
                    round(page_read_fraction, 4)
                    if page_read_fraction is not None
                    else None
                ),
                "hit_ratio_percent": None,
            },
            "note": (
                "Cache bytes and capacity are live WiredTiger values. Page counters "
                "are cumulative since server start; use a before/after benchmark "
                "for workload-specific page-read deltas. The benchmark counters are "
                "process-wide, so concurrent queries can contribute."
                if cache else
                "WiredTiger cache counters are not exposed by this deployment."
            )
        }

    except Exception as e:

        return {
            "wiredTiger_available": False,

            "cache": {
                "maximum_bytes": None,
                "current_bytes": None,
                "fill_percent": None,
                "pages_requested": None,
                "pages_read": None,
                "pages_written": None,
                "hit_ratio_percent": None
            },

            "storage_engine": None,
            "error": str(e)
        }
# =========================
# DEBUG WIREDTIGER
# =========================

# =========================
# DEBUG WIREDTIGER CACHE
# =========================

@app.get("/metrics-debug")
def metrics_debug():

    try:
        status = db.command("serverStatus")

        wired_tiger = status.get("wiredTiger", {})
        cache = wired_tiger.get("cache", {})
        storage_engine = status.get("storageEngine", {})

        return {
            "server_status": "SUCCESS",

            "mongodb_version": str(
                status.get("version", "unknown")
            ),

            "storage_engine": str(
                storage_engine.get("name", "unknown")
            ),

            "wiredTiger_present": bool(wired_tiger),

            "cache_present": bool(cache),

            "cache_keys": [
                str(key)
                for key in cache.keys()
            ],

            "cache_values": {
                "maximum_bytes_configured": cache.get(
                    "maximum bytes configured"
                ),

                "bytes_currently_in_cache": cache.get(
                    "bytes currently in the cache"
                ),

                "pages_requested_from_cache": cache.get(
                    "pages requested from the cache"
                ),

                "pages_read_into_cache": cache.get(
                    "pages read into cache"
                ),

                "pages_written_from_cache": cache.get(
                    "pages written from cache"
                ),

                "bytes_read_into_cache": cache.get(
                    "bytes read into cache"
                ),

                "bytes_written_from_cache": cache.get(
                    "bytes written from cache"
                )
            }
        }

    except Exception as e:

        return {
            "server_status": "FAILED",
            "error_type": type(e).__name__,
            "error": str(e)
        }


FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

@app.get("/extras/lab14", response_class=FileResponse)
def get_lab14_page():
    return FileResponse(FRONTEND_DIR / "lab14.html")

@app.get("/cases", response_class=FileResponse)
def get_cases_page():
    return FileResponse(FRONTEND_DIR / "cases.html")

@app.get("/extras/lab16", response_class=FileResponse)
def get_lab16_page():
    return FileResponse(FRONTEND_DIR / "lab16.html")

@app.get("/ask", response_class=FileResponse)
def get_ask_page():
    return FileResponse(FRONTEND_DIR / "ask.html")

@app.get("/extras/lab17", response_class=FileResponse)
def get_lab17_page():
    return FileResponse(FRONTEND_DIR / "lab17.html")

@app.get("/extras/lab18", response_class=FileResponse)
def get_lab18_page():
    return FileResponse(FRONTEND_DIR / "lab18.html")

@app.get("/admin/ops", response_class=FileResponse)
def get_admin_ops_page(tab: str = ""):
    if tab.lower() in {"orgs", "organisations", "organizations"}:
        return FileResponse(FRONTEND_DIR / "chapter15.html")
    if tab.lower() in {"backups", "monitoring", "metrics", "alerts", "recovery"}:
        return FileResponse(FRONTEND_DIR / "lab14.html")
    if tab.lower() == "audit":
        return FileResponse(FRONTEND_DIR / "lab16.html")
    if tab.lower() == "ask":
        return FileResponse(FRONTEND_DIR / "lab17.html")
    if tab.lower() == "sources":
        return FileResponse(FRONTEND_DIR / "lab18.html")
    return FileResponse(FRONTEND_DIR / "lab13.html")

@app.get("/moderation", response_class=FileResponse)
def get_moderation_page(tab: str = ""):
    if tab.lower() in {"orgs", "organisations", "organizations"}:
        return FileResponse(FRONTEND_DIR / "chapter15.html")
    if tab.lower() == "fraud":
        return FileResponse(FRONTEND_DIR / "lab16.html")
    if tab.lower() == "fp":
        return FileResponse(FRONTEND_DIR / "lab18.html")
    return FileResponse(FRONTEND_DIR / "lab14.html")

@app.get("/extras/lab13", response_class=FileResponse)
def get_lab13_page():
    return FileResponse(FRONTEND_DIR / "lab13.html")

app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
