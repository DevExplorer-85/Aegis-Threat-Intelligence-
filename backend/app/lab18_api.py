"""Chapter 18: comparative threat evidence across MongoDB, Cassandra and Neo4j."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import statistics
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.auth import SESSIONS
from app.database import client as mongo_client, db
from app.lab16_api import _cassandra, _neo4j, admin_user, moderator_user

router = APIRouter(tags=["Chapter 18 · Comparative False-Positive Capstone"])
_fpdb = mongo_client["fp"]
_job_lock = threading.RLock()
_job: dict[str, Any] = {"status": "idle", "completed": 0, "total": 0, "accepted": 0, "rejected": 0, "failures": [], "started_at": None, "finished_at": None}
_job_thread: Optional[threading.Thread] = None
_benchmark_lock = threading.Lock()
_schema_lock = threading.RLock()
_cassandra_schema_ready = False
_neo4j_schema_ready = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_error(error: Exception) -> str:
    return f"{type(error).__name__}: database operation failed"


def _keyspace() -> str:
    value = os.getenv("LAB16_CASSANDRA_KEYSPACE", "aegis_intel")
    if not value.replace("_", "").isalnum():
        raise RuntimeError("Cassandra keyspace name is invalid")
    return value


def _collections():
    full = _fpdb["full_threats"]
    candidates = _fpdb["candidates"]
    decisions = _fpdb["decisions"]
    return full, candidates, decisions


def ensure_indexes() -> None:
    try:
        full, candidates, decisions = _collections()
        full.create_index("record_id", unique=True)
        full.create_index([("source", 1), ("timestamp", -1)])
        full.create_index([("value", 1), ("timestamp", -1)])
        full.create_index([("family", 1), ("timestamp", -1)])
        full.create_index([("ground_truth_false_positive", 1)])
        candidates.create_index("value", unique=True)
        candidates.create_index([("status", 1), ("source", 1), ("timestamp", -1)])
        decisions.create_index([("value", 1), ("created_at", -1)])
    except Exception:
        pass


def _ensure_cassandra_schema(session) -> None:
    global _cassandra_schema_ready
    with _schema_lock:
        if _cassandra_schema_ready: return
    ks = _keyspace()
    session.execute(f"CREATE KEYSPACE IF NOT EXISTS {ks} WITH replication = {{'class':'SimpleStrategy','replication_factor':1}}")
    session.set_keyspace(ks)
    session.execute("""CREATE TABLE IF NOT EXISTS threats_by_source (
      source text, event_time timestamp, record_id text, event_day date, value text,
      threat_type text, family text, classification text, candidate_reason text, ground_truth_false_positive boolean,
      PRIMARY KEY ((source), event_time, record_id)) WITH CLUSTERING ORDER BY (event_time DESC)""")
    session.execute("""CREATE TABLE IF NOT EXISTS threats_by_value (
      value text, event_time timestamp, record_id text, event_day date, source text,
      threat_type text, family text, classification text, candidate_reason text, ground_truth_false_positive boolean,
      PRIMARY KEY ((value), event_time, record_id)) WITH CLUSTERING ORDER BY (event_time DESC)""")
    session.execute("""CREATE TABLE IF NOT EXISTS threats_by_family (
      family text, event_time timestamp, record_id text, value text, source text,
      threat_type text, classification text,
      PRIMARY KEY ((family), event_time, record_id)) WITH CLUSTERING ORDER BY (event_time DESC)""")
    session.execute("""CREATE TABLE IF NOT EXISTS volume_by_day (
      event_day date, source text, event_time timestamp, record_id text, value text,
      PRIMARY KEY ((event_day, source), event_time, record_id)) WITH CLUSTERING ORDER BY (event_time DESC)""")
    session.execute("""CREATE TABLE IF NOT EXISTS benchmark_writes (
      run_id text, event_time timestamp, record_id text, value text,
      PRIMARY KEY ((run_id), event_time, record_id))""")
    with _schema_lock: _cassandra_schema_ready = True


def _ensure_neo4j_schema(driver) -> None:
    global _neo4j_schema_ready
    with _schema_lock:
        if _neo4j_schema_ready: return
    with driver.session() as session:
        session.run("CREATE CONSTRAINT lab18_threat_record_id IF NOT EXISTS FOR (n:Threat) REQUIRE n.record_id IS UNIQUE")
        session.run("CREATE CONSTRAINT lab18_family_name IF NOT EXISTS FOR (n:Family) REQUIRE n.name IS UNIQUE")
        session.run("CREATE CONSTRAINT lab18_source_name IF NOT EXISTS FOR (n:Source) REQUIRE n.name IS UNIQUE")
        session.run("CREATE CONSTRAINT lab18_indicator_value IF NOT EXISTS FOR (n:Indicator) REQUIRE n.value IS UNIQUE")
    with _schema_lock: _neo4j_schema_ready = True


def _normalise(record: dict[str, Any], dataset_label: Optional[str] = None) -> dict[str, Any]:
    value = str(record.get("value") or record.get("indicator") or "").strip()
    if not value or len(value) > 4096 or any(ord(char) < 32 for char in value):
        raise ValueError("Indicator value is missing or invalid")
    kind = str(record.get("threat_type") or record.get("type") or "unknown").strip().lower()[:100]
    if kind in {"ip", "ip-src", "ip-dst"}:
        candidate = value.split("|", 1)[0]
        value = ipaddress.ip_address(candidate).compressed
    elif kind in {"domain", "hostname", "fqdn"}:
        value = value.rstrip(".").lower()
    source = str(record.get("source") or record.get("feed_id") or "import").strip()[:200]
    source_id = str(record.get("source_id") or record.get("event_uuid") or record.get("misp_attribute_uuid") or record.get("id") or "").strip()[:300]
    if not source_id:
        raise ValueError("Source record identifier is required for duplicate-safe ingestion")
    raw_time = record.get("timestamp") or record.get("published_at") or record.get("event_time")
    if isinstance(raw_time, datetime):
        timestamp = raw_time if raw_time.tzinfo else raw_time.replace(tzinfo=timezone.utc)
    elif raw_time:
        timestamp = datetime.fromisoformat(str(raw_time).replace("Z", "+00:00"))
        if timestamp.tzinfo is None: timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = _now()
    tags = record.get("tags") or []
    if isinstance(tags, str): tags = [tags]
    tags = [str(tag)[:250] for tag in tags if tag is not None][:100]
    label = record.get("ground_truth_false_positive")
    if label is None and "ground_truth" in record:
        label = record["ground_truth"]
    if label is not None and not isinstance(label, bool):
        raise ValueError("ground_truth_false_positive must be boolean")
    candidate_reason = str(record.get("candidate_reason") or "")[:500]
    if not candidate_reason and any("false-positive" in tag.lower() or "false_positive" in tag.lower() or "benign" == tag.lower() for tag in tags):
        candidate_reason = "Source record explicitly contains a benign/false-positive tag; analyst review required."
    family = str(record.get("family") or record.get("threat_family") or "").strip()[:200]
    record_id = hashlib.sha256(f"{source}\0{source_id}\0{value}".encode()).hexdigest()
    return {"record_id": record_id, "source": source, "source_id": source_id, "timestamp": timestamp.astimezone(timezone.utc), "event_day": timestamp.date(), "value": value, "threat_type": kind, "family": family or None, "classification": str(record.get("classification") or "")[:200], "tags": tags, "candidate_reason": candidate_reason or None, "ground_truth_false_positive": label, "dataset_label": dataset_label or record.get("dataset_label") or "configured MongoDB threat records", "title": str(record.get("title") or "")[:500], "first_seen": timestamp.astimezone(timezone.utc), "last_seen": timestamp.astimezone(timezone.utc)}


def _records_from_existing(limit: int) -> list[dict[str, Any]]:
    sources = []
    try:
        sources = list(db["working_set_test"].find({"value": {"$type": "string", "$ne": ""}}, {"_id": 1, "feed_id": 1, "source": 1, "misp_attribute_uuid": 1, "event_uuid": 1, "value": 1, "type": 1, "category": 1, "tags": 1, "comment": 1, "timestamp": 1, "published_at": 1}).limit(limit))
    except Exception:
        sources = []
    output = []
    for item in sources:
        output.append({**item, "source": item.get("source") or item.get("feed_id"), "source_id": item.get("misp_attribute_uuid") or item.get("_id"), "threat_type": item.get("type"), "title": item.get("comment")})
    if len(output) < limit:
        try:
            remaining = limit - len(output)
            for item in db["threat_reports"].find({}, {"_id": 1, "report_id": 1, "source": 1, "published_date": 1, "title": 1, "indicators": 1, "value": 1, "type": 1}).limit(remaining):
                indicators = item.get("indicators") if isinstance(item.get("indicators"), list) else [item]
                for idx, indicator in enumerate(indicators):
                    if not isinstance(indicator, dict) or not (indicator.get("value") or indicator.get("indicator")): continue
                    output.append({**indicator, "source": indicator.get("source") or item.get("source") or "threat_reports", "source_id": indicator.get("id") or f"{item.get('report_id') or item.get('_id')}:{idx}", "timestamp": indicator.get("timestamp") or item.get("published_date"), "title": item.get("title")})
                    if len(output) >= limit: break
                if len(output) >= limit: break
        except Exception:
            pass
    return output[:limit]


def _peer_cassandra_write(record: dict[str, Any]) -> None:
    session = _cassandra(); _ensure_cassandra_schema(session)
    values = (record["source"], record["timestamp"], record["record_id"], record["event_day"], record["value"], record["threat_type"], record.get("family"), record.get("classification"), record.get("candidate_reason"), record.get("ground_truth_false_positive"))
    session.execute("INSERT INTO threats_by_source (source,event_time,record_id,event_day,value,threat_type,family,classification,candidate_reason,ground_truth_false_positive) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", values)
    session.execute("INSERT INTO threats_by_value (value,event_time,record_id,event_day,source,threat_type,family,classification,candidate_reason,ground_truth_false_positive) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (record["value"], record["timestamp"], record["record_id"], record["event_day"], record["source"], record["threat_type"], record.get("family"), record.get("classification"), record.get("candidate_reason"), record.get("ground_truth_false_positive")))
    if record.get("family"):
        session.execute("INSERT INTO threats_by_family (family,event_time,record_id,value,source,threat_type,classification) VALUES (%s,%s,%s,%s,%s,%s,%s)", (record["family"], record["timestamp"], record["record_id"], record["value"], record["source"], record["threat_type"], record.get("classification")))
    session.execute("INSERT INTO volume_by_day (event_day,source,event_time,record_id,value) VALUES (%s,%s,%s,%s,%s)", (record["event_day"], record["source"], record["timestamp"], record["record_id"], record["value"]))


def _peer_neo4j_write(record: dict[str, Any]) -> None:
    driver = _neo4j(); _ensure_neo4j_schema(driver)
    query = """MERGE (s:Source {name:$source})
      MERGE (t:Threat {record_id:$record_id})
      SET t.value=$value, t.source=$source, t.threat_type=$threat_type, t.event_time=$event_time, t.event_day=$event_day,
          t.classification=$classification, t.family=$family, t.candidate_reason=$candidate_reason,
          t.ground_truth_false_positive=$ground_truth_false_positive
      MERGE (t)-[:OBSERVED_BY]->(s)
      WITH t
      FOREACH (_ IN CASE WHEN $family IS NULL THEN [] ELSE [1] END |
        MERGE (f:Family {name:$family}) MERGE (t)-[:ATTRIBUTED_TO]->(f))
      FOREACH (_ IN CASE WHEN $candidate_reason IS NULL THEN [] ELSE [1] END |
        MERGE (t)-[:SUSPICIOUS {reason:$candidate_reason}]->(s))
      MERGE (i:Indicator {value:$value})
      MERGE (t)-[:SHARES_INDICATOR]->(i)"""
    with driver.session() as session:
        session.run(query, {"source": record["source"], "record_id": record["record_id"], "value": record["value"], "threat_type": record["threat_type"], "event_time": record["timestamp"].isoformat(), "event_day": record["event_day"].isoformat(), "classification": record.get("classification"), "candidate_reason": record.get("candidate_reason"), "ground_truth_false_positive": record.get("ground_truth_false_positive"), "family": record.get("family")}).consume()


def _sync_candidate(record: dict[str, Any]) -> None:
    if not record.get("candidate_reason"):
        return
    _, candidates, _ = _collections()
    candidates.update_one({"value": record["value"]}, {"$setOnInsert": {"value": record["value"], "status": "open", "created_at": _now()}, "$set": {"source": record["source"], "threat_type": record["threat_type"], "detection_reason": record["candidate_reason"], "updated_at": _now(), "dataset_label": record["dataset_label"]}}, upsert=True)


def _run_ingestion(mode: str, limit: int, dataset_label: Optional[str], imported: list[dict[str, Any]]) -> None:
    global _job
    try:
        raw_records = imported if mode == "import" else _records_from_existing(limit)
        if mode == "import" and not dataset_label:
            raise RuntimeError("Explicit import mode requires a dataset label.")
        with _job_lock: _job.update(status="running", total=len(raw_records), completed=0, accepted=0, rejected=0, failures=[], started_at=_now().isoformat(), finished_at=None, mode=mode, dataset_label=dataset_label or "configured MongoDB threat records")
        full, _, _ = _collections()
        for position, raw in enumerate(raw_records, 1):
            normalized = None
            try:
                normalized = _normalise(raw, dataset_label)
                # Peer databases only receive a row after MongoDB acknowledged and can read it back.
                full.update_one({"record_id": normalized["record_id"]}, {"$setOnInsert": normalized}, upsert=True)
                confirmed = full.find_one({"record_id": normalized["record_id"]})
                if not confirmed:
                    raise RuntimeError("MongoDB write was not confirmed by read-back")
                try:
                    _sync_candidate(normalized)
                    _fpdb["source_recent"].update_one({"_id": normalized["source"]},{"$setOnInsert":{"source":normalized["source"]},"$push":{"recent":{"$each":[normalized],"$sort":{"timestamp":-1},"$slice":100}}},upsert=True)
                except Exception as error:
                    with _job_lock: _job["failures"].append({"record_id":normalized["record_id"],"stage":"mongo_derived_view","mongodb_confirmed":True,"error":_safe_error(error)})
                cass_error = neo_error = None
                try: _peer_cassandra_write(normalized)
                except Exception as error: cass_error = _safe_error(error)
                try: _peer_neo4j_write(normalized)
                except Exception as error: neo_error = _safe_error(error)
                if cass_error or neo_error:
                    with _job_lock:
                        _job["failures"].append({"record_id": normalized["record_id"], "stage": "peer_write", "mongodb_confirmed": True, "cassandra": cass_error, "neo4j": neo_error})
                with _job_lock: _job["accepted"] += 1
            except Exception as error:
                with _job_lock:
                    _job["rejected"] += 1
                    _job["failures"].append({"record_id": normalized.get("record_id") if normalized else str(raw.get("source_id") or raw.get("id") or position), "stage": "validation_or_mongodb", "mongodb_confirmed": False, "error": _safe_error(error)})
            finally:
                with _job_lock: _job["completed"] = position
        with _job_lock: _job.update(status="completed_with_errors" if _job["failures"] else "completed", finished_at=_now().isoformat())
    except Exception as error:
        with _job_lock: _job.update(status="failed", finished_at=_now().isoformat(), message=_safe_error(error))


def _job_snapshot() -> dict[str, Any]:
    with _job_lock: return {**_job, "failures": list(_job.get("failures", []))}


def _mongo_health() -> dict[str, Any]:
    started = time.perf_counter()
    try:
        mongo_client.admin.command("ping")
        full, candidates, _ = _collections()
        return {"available": True, "latency_ms": round((time.perf_counter()-started)*1000, 2), "counts": {"fp.full_threats": full.count_documents({}), "fp.candidates": candidates.count_documents({})}}
    except Exception as error: return {"available": False, "latency_ms": None, "counts": {"fp.full_threats": None, "fp.candidates": None}, "error": _safe_error(error)}


def _cassandra_health() -> dict[str, Any]:
    started = time.perf_counter()
    try:
        session = _cassandra(); _ensure_cassandra_schema(session)
        counts = {}
        for table in ("threats_by_source", "threats_by_value", "threats_by_family", "volume_by_day"):
            row = session.execute(f"SELECT COUNT(*) AS n FROM {table}").one(); counts[table] = int(getattr(row, "n", 0)) if row else 0
        return {"available": True, "latency_ms": round((time.perf_counter()-started)*1000, 2), "counts": counts}
    except Exception as error: return {"available": False, "latency_ms": None, "counts": {"threats_by_source": None, "threats_by_value": None, "threats_by_family": None, "volume_by_day": None}, "error": _safe_error(error)}


def _neo4j_health() -> dict[str, Any]:
    started = time.perf_counter()
    try:
        driver = _neo4j(); _ensure_neo4j_schema(driver)
        with driver.session() as session:
            counts = session.run("MATCH (n) RETURN labels(n) AS labels, count(*) AS n").data()
            rels = session.run("MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS n").data()
        nodes = {"Threat": 0, "Family": 0, "Source": 0, "Indicator": 0}
        relationships = {"ATTRIBUTED_TO": 0, "SUSPICIOUS": 0, "SHARES_INDICATOR": 0}
        for row in counts:
            for label in row.get("labels", []):
                if label in nodes: nodes[label] += int(row["n"])
        for row in rels:
            if row.get("type") in relationships: relationships[row["type"]] = int(row["n"])
        return {"available": True, "latency_ms": round((time.perf_counter()-started)*1000, 2), "counts": {"nodes": nodes, "relationships": relationships}}
    except Exception as error: return {"available": False, "latency_ms": None, "counts": {"nodes": None, "relationships": None}, "error": _safe_error(error)}


def _latest_evaluation() -> dict[str, Any]:
    try:
        full, _, _ = _collections()
        labels = list(full.find({"ground_truth_false_positive": {"$in": [True, False]}}, {"_id": 0, "record_id": 1, "value": 1, "source": 1, "source_id": 1, "ground_truth_false_positive": 1, "candidate_reason": 1}).limit(5000))
    except Exception as error:
        return {"available": False, "labelled_records": None, "message": f"MongoDB unavailable; labelled evaluation cannot run ({_safe_error(error)})."}
    if not labels: return {"available": False, "labelled_records": 0, "message": "No imported or curated labelled ground-truth records exist. False-positive evaluation has not been run."}
    adapters: dict[str, dict[str, Any]] = {}
    times: dict[str, list[float]] = defaultdict(list)
    outcomes: dict[str, list[tuple[bool, bool, dict[str, Any]]]] = defaultdict(list)
    for record in labels:
        value = record["value"]
        queries = {}
        try:
            started = time.perf_counter(); rows = list(_collections()[0].find({"value": value}, {"_id": 0, "source": 1, "candidate_reason": 1, "ground_truth_false_positive": 1}).limit(100)); times["MongoDB"].append((time.perf_counter()-started)*1000); queries["MongoDB"] = {"available": True, "flagged": any(r.get("candidate_reason") for r in rows), "evidence": len(rows)}
        except Exception as error: queries["MongoDB"] = {"available": False, "error": _safe_error(error)}
        try:
            started = time.perf_counter(); rows = list(_cassandra().execute("SELECT source,candidate_reason FROM threats_by_value WHERE value=%s LIMIT 100", (value,))); times["Cassandra"].append((time.perf_counter()-started)*1000); queries["Cassandra"] = {"available": True, "flagged": any(getattr(r, "candidate_reason", None) for r in rows), "evidence": len(rows)}
        except Exception as error: queries["Cassandra"] = {"available": False, "error": _safe_error(error)}
        try:
            started = time.perf_counter()
            with _neo4j().session() as session:
                row = session.run("MATCH (t:Threat {value:$value}) OPTIONAL MATCH (t)-[r:SUSPICIOUS]->() RETURN count(DISTINCT t) AS n,count(r) AS suspicious", value=value).single()
            times["Neo4j"].append((time.perf_counter()-started)*1000); queries["Neo4j"] = {"available": True, "flagged": bool(row and row["suspicious"]), "evidence": int(row["n"]) if row else 0}
        except Exception as error: queries["Neo4j"] = {"available": False, "error": _safe_error(error)}
        available = {name: item for name, item in queries.items() if item.get("available")}
        predictions = {name: bool(item["flagged"]) for name, item in available.items()}
        predictions["Two-of-three voting"] = sum(predictions.values()) >= 2 if len(predictions) == 3 else False
        predictions["Any-of-three voting"] = any(predictions.values()) if len(predictions) == 3 else False
        for name, predicted in predictions.items():
            if name in {"Two-of-three voting", "Any-of-three voting"} and len(available) != 3: continue
            outcomes[name].append((bool(predicted), bool(record["ground_truth_false_positive"]), queries))
    for name, rows in outcomes.items():
        tp=sum(p and truth for p,truth,_ in rows); fn=sum((not p) and truth for p,truth,_ in rows); fp=sum(p and (not truth) for p,truth,_ in rows); tn=sum((not p) and (not truth) for p,truth,_ in rows)
        precision=tp/(tp+fp) if tp+fp else None; recall=tp/(tp+fn) if tp+fn else None; f1=(2*precision*recall/(precision+recall)) if precision is not None and recall is not None and precision+recall else None
        adapters[name]={"true_positives":tp,"false_negatives":fn,"false_positives":fp,"true_negatives":tn,"precision":precision,"recall":recall,"f1":f1,"median_processing_ms":statistics.median(times[name]) if times[name] else None,"evaluated":len(rows)}
    disagreements=[]
    for record in labels:
        value=record["value"]
        try:
            mongo_flag=bool(_collections()[1].find_one({"value":value,"status":"open"}))
            cass_rows=list(_cassandra().execute("SELECT candidate_reason FROM threats_by_value WHERE value=%s LIMIT 100",(value,)))
            cass_flag=any(getattr(r,"candidate_reason",None) for r in cass_rows)
            with _neo4j().session() as session: neo_row=session.run("MATCH (t:Threat {value:$value})-[:SUSPICIOUS]->() RETURN count(t) AS n",value=value).single()
            neo_flag=bool(neo_row and neo_row["n"])
            flags={"MongoDB":mongo_flag,"Cassandra":cass_flag,"Neo4j":neo_flag}
            if len(set(flags.values()))>1: disagreements.append({"value":value,"ground_truth_false_positive":record["ground_truth_false_positive"],"verdicts":flags,"evidence":"Explicit source tags and persisted SUSPICIOUS relationships; verify the source records."})
        except Exception: continue
        if len(disagreements)>=30: break
    return {"available": True, "labelled_records": len(labels), "positive_class": "confirmed false positive / benign", "metrics": adapters, "disagreements": disagreements, "method": "Per-store candidate reason from explicit source tags; unavailable stores are excluded and voting is scored only when all three stores responded."}


def _graph_communities() -> dict[str, Any]:
    cypher = "MATCH (a:Threat)-[:SHARES_INDICATOR]->(i:Indicator)<-[:SHARES_INDICATOR]-(b:Threat) WHERE a.record_id < b.record_id RETURN a.record_id AS a, a.value AS av, a.source AS asource, a.family AS afamily, b.record_id AS b, b.value AS bv, b.source AS bsource, b.family AS bfamily, i.value AS indicator LIMIT 20000"
    try:
        driver=_neo4j()
        with driver.session() as session: rows=session.run(cypher).data()
        graph: dict[str,set[str]]=defaultdict(set); meta: dict[str,dict[str,Any]]={}
        for row in rows:
            a,b=row["a"],row["b"]; graph[a].add(b); graph[b].add(a)
            meta[a]={"value":row["av"],"source":row["asource"],"family":row.get("afamily")}; meta[b]={"value":row["bv"],"source":row["bsource"],"family":row.get("bfamily")}
        seen=set(); comps=[]
        for node in graph:
            if node in seen: continue
            queue=[node]; seen.add(node); component=[]
            while queue:
                current=queue.pop(); component.append(current)
                for neighbor in graph[current]:
                    if neighbor not in seen: seen.add(neighbor); queue.append(neighbor)
            if len(component)>=2: comps.append(component)
        sizes=[len(c) for c in comps]; mean=statistics.mean(sizes) if sizes else 0; stdev=statistics.pstdev(sizes) if len(sizes)>1 else 0
        result=[]
        for idx, component in enumerate(sorted(comps,key=len,reverse=True)[:100]):
            members=[meta[n] for n in component if n in meta]; families=sorted({m["family"] for m in members if m.get("family")}); sources=sorted({m["source"] for m in members if m.get("source")}); indicators=sorted({m["value"] for m in members if m.get("value")}); z=(len(component)-mean)/stdev if stdev else 0.0
            result.append({"community_id":f"community-{idx+1}","threat_count":len(component),"families":families,"sources":sources,"shared_indicators":indicators[:100],"bridging_indicators":[v for v in indicators if sum(1 for m in members if m.get("value")==v)>=2][:30],"z_score":round(z,3)})
        return {"available":True,"count":len(result),"communities":result,"cypher":cypher,"method":"Connected components over persisted SHARES_INDICATOR edges; only stored threat/indicator evidence is used."}
    except Exception as error: return {"available":False,"count":None,"communities":[],"cypher":cypher,"error":_safe_error(error)}


def _service_state() -> dict[str, Any]:
    try: benchmarks=list(_fpdb["benchmarks"].find({}, {"_id":0}).sort("measured_at",-1).limit(10))
    except Exception: benchmarks=[]
    return {"timestamp":_now().isoformat(),"databases":{"mongodb":_mongo_health(),"cassandra":_cassandra_health(),"neo4j":_neo4j_health()},"evaluation":_latest_evaluation(),"communities":_graph_communities(),"ingestion":_job_snapshot(),"benchmarks":benchmarks}


class IngestRequest(BaseModel):
    mode: str = Field(default="existing", pattern="^(existing|import)$")
    limit: int = Field(default=100000, ge=1, le=100000)
    dataset_label: Optional[str] = Field(default=None, max_length=200)
    records: list[dict[str, Any]] = Field(default_factory=list, max_length=100000)


class DecisionRequest(BaseModel):
    value: str = Field(min_length=1, max_length=4096)
    decision: str = Field(pattern="^(confirm_false_positive|keep_real_threat)$")
    note: str = Field(min_length=5, max_length=4000)
    confirm: bool


@router.get("/api/services/lab18")
def get_lab18_services(_user=Depends(admin_user)):
    try: return _service_state()
    except Exception as error: raise HTTPException(503,_safe_error(error)) from error


@router.post("/api/ops/lab18/ingest")
def start_ingestion(req: IngestRequest, _user=Depends(admin_user)):
    global _job_thread
    if req.mode == "import" and not req.dataset_label:
        raise HTTPException(422,"Import mode requires an explicit dataset_label so imported data is not presented as live feed data.")
    if req.mode == "existing" and req.records:
        raise HTTPException(422,"Pass records only in explicit import mode.")
    imported=req.records[:req.limit]
    with _job_lock:
        if _job.get("status")=="running": raise HTTPException(409,"A Chapter 18 ingestion job is already running.")
        _job.update(status="running",total=0,completed=0,accepted=0,rejected=0,failures=[],mode=req.mode,started_at=_now().isoformat(),finished_at=None)
        _job_thread=threading.Thread(target=_run_ingestion,args=(req.mode,req.limit,req.dataset_label,imported),name="lab18-ingestion",daemon=True)
        _job_thread.start()
    return {"accepted":True,"job":_job_snapshot()}


@router.get("/api/ops/lab18/ingest")
def ingestion_status(_user=Depends(admin_user)): return _job_snapshot()


def _median(samples: list[float]) -> Optional[float]: return round(statistics.median(samples),4) if samples else None


def _bench_mongo(q: str, source: str, value: str, family: str):
    full,_,_=_collections()
    if q=="Q1": return list(full.find({"$or":[{"source":source},{"value":value}]},{"_id":0}).sort("timestamp",-1).limit(50))
    if q=="Q2": return list(full.find({"$or":[{"family":family},{"value":value}]},{"_id":0,"record_id":1,"source":1,"value":1,"family":1}).limit(100))
    if q=="Q3": return list(full.aggregate([{"$group":{"_id":{"$dateToString":{"format":"%Y-%m-%d","date":"$timestamp"}},"count":{"$sum":1}}},{"$sort":{"_id":-1}},{"$limit":30}]))
    bench=_fpdb["benchmark_writes"]; rows=[{"record_id":str(uuid.uuid4()),"value":f"benchmark-{uuid.uuid4()}","timestamp":_now()} for _ in range(10)]; start=time.perf_counter(); bench.insert_many(rows,ordered=True); elapsed=(time.perf_counter()-start)*1000; bench.delete_many({"record_id":{"$in":[r["record_id"] for r in rows]}}); return {"latency_ms":elapsed,"ops_per_second":10/(elapsed/1000) if elapsed else None}


def _bench_cassandra(q: str, source: str, value: str, family: str):
    session=_cassandra(); _ensure_cassandra_schema(session)
    if q=="Q1": return list(session.execute("SELECT record_id,value,event_time,source FROM threats_by_source WHERE source=%s LIMIT 50",(source,))) if source else list(session.execute("SELECT record_id,value,event_time,source FROM threats_by_value WHERE value=%s LIMIT 50",(value,)))
    if q=="Q2": return list(session.execute("SELECT record_id,value,event_time,source,family FROM threats_by_family WHERE family=%s LIMIT 100",(family,))) if family else list(session.execute("SELECT record_id,value,event_time,source,family FROM threats_by_value WHERE value=%s LIMIT 100",(value,)))
    if q=="Q3":
        today=date.today(); return [session.execute("SELECT COUNT(*) AS n FROM volume_by_day WHERE event_day=%s AND source=%s",(today-timedelta(days=offset),source)).one() for offset in range(7)]
    run_id=str(uuid.uuid4()); rows=[(run_id,_now(),str(uuid.uuid4()),f"benchmark-{uuid.uuid4()}") for _ in range(10)]; start=time.perf_counter()
    for row in rows: session.execute("INSERT INTO benchmark_writes (run_id,event_time,record_id,value) VALUES (%s,%s,%s,%s)",row)
    elapsed=(time.perf_counter()-start)*1000
    for row in rows: session.execute("DELETE FROM benchmark_writes WHERE run_id=%s AND event_time=%s AND record_id=%s",row[:3])
    return {"latency_ms":elapsed,"ops_per_second":10/(elapsed/1000) if elapsed else None}


def _bench_neo(q: str, source: str, value: str, family: str):
    driver=_neo4j()
    if q=="Q1": query="MATCH (t:Threat) OPTIONAL MATCH (t)-[:OBSERVED_BY]->(s:Source) WHERE t.value=$value OR s.name=$source RETURN t.record_id,t.value,t.event_time,collect(s.name) AS sources LIMIT 50"; params={"value":value,"source":source}
    elif q=="Q2": query="MATCH (t:Threat) WHERE t.family=$family OR t.value=$value OPTIONAL MATCH (t)-[:SHARES_INDICATOR]->(i:Indicator) RETURN t.record_id,t.value,t.family,collect(i.value) AS indicators LIMIT 100"; params={"family":family,"value":value}
    elif q=="Q3": query="MATCH (t:Threat) RETURN t.event_day AS day,count(*) AS count ORDER BY day DESC LIMIT 30"; params={}
    else:
        rows=[{"id":str(uuid.uuid4()),"value":f"benchmark-{uuid.uuid4()}"} for _ in range(10)]; start=time.perf_counter()
        with driver.session() as session: session.run("UNWIND $rows AS row CREATE (:Lab18Bench {record_id:row.id,value:row.value})",rows=rows).consume()
        elapsed=(time.perf_counter()-start)*1000
        with driver.session() as session: session.run("MATCH (n:Lab18Bench) WHERE n.record_id IN $ids DETACH DELETE n",ids=[r["id"] for r in rows]).consume()
        return {"latency_ms":elapsed,"ops_per_second":10/(elapsed/1000) if elapsed else None}
    with driver.session() as session: return session.run(query,params).data()


def _count_mongo(): return _collections()[0].count_documents({})
def _count_cassandra(): return int(_cassandra().execute("SELECT COUNT(*) AS n FROM threats_by_source").one().n)
def _count_neo():
    with _neo4j().session() as session: return int(session.run("MATCH (n:Threat) RETURN count(n) AS n").single()["n"])


@router.post("/api/ops/lab18/benchmark")
def run_benchmarks(_user=Depends(admin_user)):
    if not _benchmark_lock.acquire(blocking=False): raise HTTPException(409,"A benchmark is already running.")
    try:
        full,_,_=_collections(); sample=full.find_one({}, {"_id":0,"source":1,"value":1,"family":1}) or {}; source=sample.get("source",""); value=sample.get("value",""); family=sample.get("family","") or ""
        methods={"MongoDB":_bench_mongo,"Cassandra":_bench_cassandra,"Neo4j":_bench_neo}; counts={}
        for name,fn in (("MongoDB",_count_mongo),("Cassandra",_count_cassandra),("Neo4j",_count_neo)):
            try: counts[name]=fn()
            except Exception: counts[name]=None
        results=[]
        for database,fn in methods.items():
            for q,description in (("Q1","Threat history by source or indicator"),("Q2","Threat family and shared-indicator spread"),("Q3","Daily threat volume"),("Q4","Ten-record real-time insert throughput")):
                runs=[]; errors=[]
                for _ in range(10):
                    started=time.perf_counter()
                    try:
                        result=fn(q,source,value,family); elapsed=(time.perf_counter()-started)*1000
                        if q=="Q4": elapsed=float(result["latency_ms"]); runs.append({"latency_ms":round(elapsed,4),"ops_per_second":result["ops_per_second"]})
                        else: runs.append({"latency_ms":round(elapsed,4),"result_count":len(result) if hasattr(result,"__len__") else 1})
                    except Exception as error: errors.append(_safe_error(error)); runs.append({"latency_ms":None,"error":_safe_error(error)})
                valid=[r["latency_ms"] for r in runs if r["latency_ms"] is not None]
                results.append({"database":database,"query":q,"description":description,"dataset_size":counts[database],"runs":runs,"median_latency_ms":_median(valid),"errors":errors,"measured_at":_now().isoformat()})
        report={"run_id":str(uuid.uuid4()),"measured_at":_now().isoformat(),"dataset_sizes":counts,"results":results}
        _fpdb["benchmarks"].insert_one(report)
        report.pop("_id",None)
        return report
    finally: _benchmark_lock.release()


def _fp_evidence(value: str) -> dict[str, Any]:
    results={}
    try:
        started=time.perf_counter(); full, candidates, _=_collections(); sightings=list(full.find({"value":value},{"_id":0,"source":1,"threat_type":1,"candidate_reason":1,"record_id":1}).limit(200)); cand=candidates.find_one({"value":value}); results["mongodb"]={"available":True,"verdict":"candidate" if cand and cand.get("status")=="open" else "confirmed_false_positive" if cand and cand.get("status")=="confirmed_false_positive" else "no_candidate_flag","reason":cand.get("detection_reason") if cand else "No source-supplied false-positive tag was found.","processing_ms":round((time.perf_counter()-started)*1000,3),"sightings":sightings}
    except Exception as error: results["mongodb"]={"available":False,"verdict":None,"reason":_safe_error(error),"processing_ms":None,"sightings":[]}
    try:
        started=time.perf_counter(); rows=list(_cassandra().execute("SELECT source,threat_type,candidate_reason,event_time FROM threats_by_value WHERE value=%s LIMIT 200",(value,))); sources=sorted({r.source for r in rows}); reasons=[r.candidate_reason for r in rows if getattr(r,"candidate_reason",None)]; results["cassandra"]={"available":True,"verdict":"candidate" if reasons else "corroborated" if len(sources)>1 else "single_source","reason":"; ".join(sorted(set(reasons))) if reasons else f"{len(sources)} stored source(s) report this indicator.","processing_ms":round((time.perf_counter()-started)*1000,3),"threat_spread":[{"source":r.source,"type":r.threat_type,"event_time":r.event_time.isoformat() if r.event_time else None} for r in rows]}
    except Exception as error: results["cassandra"]={"available":False,"verdict":None,"reason":_safe_error(error),"processing_ms":None,"threat_spread":[]}
    try:
        started=time.perf_counter()
        with _neo4j().session() as session:
            row=session.run("MATCH (i:Indicator {value:$value}) OPTIONAL MATCH (t:Threat)-[:SHARES_INDICATOR]->(i) OPTIONAL MATCH (t)-[s:SUSPICIOUS]->(src:Source) OPTIONAL MATCH (t)-[:ATTRIBUTED_TO]->(f:Family) RETURN count(DISTINCT t) AS threat_count,count(DISTINCT s) AS suspicious_count,collect(DISTINCT src.name) AS sources,collect(DISTINCT f.name) AS families",value=value).single()
        n=int(row["threat_count"]) if row else 0; suspicious=int(row["suspicious_count"]) if row else 0; results["neo4j"]={"available":True,"verdict":"candidate" if suspicious else "connected" if n>1 else "no_graph_match","reason":f"{n} persisted threat node(s), {suspicious} explicit suspicious relationship(s).","processing_ms":round((time.perf_counter()-started)*1000,3),"related_sources":row["sources"] if row else [],"families":row["families"] if row else []}
    except Exception as error: results["neo4j"]={"available":False,"verdict":None,"reason":_safe_error(error),"processing_ms":None,"related_sources":[],"families":[]}
    available=[r for r in results.values() if r["available"]]
    votes=sum(r["verdict"]=="candidate" for r in available)
    results["vote"]={"available_databases":len(available),"two_of_three":"candidate" if len(available)==3 and votes>=2 else "not_candidate" if len(available)==3 else None,"any_of_three":"candidate" if len(available)==3 and votes>=1 else "not_candidate" if len(available)==3 else None,"disagreement":len({r["verdict"] for r in available})>1,"evidence":"A candidate is a review prompt only. A vote is withheld unless all three databases responded; neither result confirms a false positive."}
    return results


@router.get("/api/moderation/fp")
def list_fp_candidates(reason: str="",kind: str="",source: str="",status: str="open",limit: int=Query(200,ge=1,le=1000),_user=Depends(moderator_user)):
    _, candidates, _=_collections(); query={}
    if status: query["status"]=status
    if source: query["source"]=source
    if kind: query["threat_type"]=kind
    if reason: query["detection_reason"]={"$regex":reason,"$options":"i"}
    rows=list(candidates.find(query,{"_id":0}).sort("updated_at",-1).limit(limit))
    return {"candidates":rows,"count":len(rows),"query":query}


@router.get("/api/moderation/fp/evaluation")
def moderator_fp_evaluation(_user=Depends(moderator_user)):
    return _latest_evaluation()


@router.get("/api/moderation/fp/value")
def investigate_fp_value(value: str=Query(...,min_length=1,max_length=4096),_user=Depends(moderator_user)):
    return {"value":value,"evidence":_fp_evidence(value),"historical_evidence_preserved":True}


@router.post("/api/moderation/fp/decision")
def record_fp_decision(req: DecisionRequest,user=Depends(moderator_user)):
    if not req.confirm: raise HTTPException(400,"Confirm the analyst decision before saving it.")
    full,candidates,decisions=_collections(); existing=candidates.find_one({"value":req.value})
    if not existing: raise HTTPException(404,"No false-positive candidate exists for this indicator.")
    previous=existing.get("status","open"); new_status="confirmed_false_positive" if req.decision=="confirm_false_positive" else "kept_real_threat"
    event={"value":req.value,"user_id":str(user["id"]),"user_name":user.get("name"),"timestamp":_now(),"previous_state":previous,"new_state":new_status,"reason":req.note.strip(),"decision":req.decision}
    decisions.insert_one(event); candidates.update_one({"value":req.value},{"$set":{"status":new_status,"analyst_decision":req.decision,"analyst_note":req.note.strip(),"analyst_id":str(user["id"]),"decided_at":event["timestamp"],"updated_at":event["timestamp"]}})
    full.update_many({"value":req.value},{"$set":{"analyst_status":new_status,"analyst_decision_id":str(event.get("_id",""))}})
    return {"saved":True,"value":req.value,"previous_state":previous,"new_state":new_status,"historical_records_preserved":True,"excluded_from_lab18_exports":new_status=="confirmed_false_positive"}


@router.get("/api/ops/sources")
def source_analytics(_user=Depends(admin_user)):
    full,candidates,_=_collections()
    try:
        sources=list(full.aggregate([{"$group":{"_id":"$source","records":{"$sum":1},"false_positive_candidates":{"$sum":{"$cond":[{"$ne":["$candidate_reason",None]},1,0]}}}},{"$sort":{"records":-1}}]))
        candidate_total=candidates.count_documents({}); evaluation=_latest_evaluation(); metrics=evaluation.get("metrics",{})
        rates=[{"source":row["_id"],"records":row["records"],"candidate_rate":row["false_positive_candidates"]/row["records"] if row["records"] else None} for row in sources]
        pairs=list(full.aggregate([{"$group":{"_id":"$value","sources":{"$addToSet":"$source"} }},{"$match":{"$expr":{"$gt":[{"$size":"$sources"},1]}}},{"$limit":500},{"$project":{"_id":0,"sources":1,"indicator":"$_id"}}]))
        suspicious_pairs=defaultdict(int)
        for item in pairs:
            ss=sorted(item["sources"])
            for i in range(len(ss)):
                for j in range(i+1,len(ss)): suspicious_pairs[f"{ss[i]} ↔ {ss[j]}"]+=1
        best=max(((k,v.get("f1")) for k,v in metrics.items() if v.get("f1") is not None),key=lambda x:x[1],default=(None,None))
        return {"feeds":len(sources),"sources":sources,"candidate_count":candidate_total,"highest_candidate_rate":max(rates,key=lambda r:r["candidate_rate"] or 0,default=None),"suspicious_source_pairs":[{"pair":k,"shared_indicator_count":v} for k,v in sorted(suspicious_pairs.items(),key=lambda x:x[1],reverse=True)[:20]],"best_database_judge":{"name":best[0],"f1":best[1]} if best[0] else None,"evaluation":evaluation,"precision_recall":[{"name":k,"precision":v.get("precision"),"recall":v.get("recall"),"f1":v.get("f1")} for k,v in metrics.items()]}
    except Exception as error: raise HTTPException(503,_safe_error(error)) from error


def _pdf_escape(value: str) -> str:
    return value.replace("\\","\\\\").replace("(","\\(").replace(")","\\)")


def _make_pdf(lines: list[str]) -> bytes:
    # Minimal standards-compliant PDF writer avoids another runtime dependency.
    pages=[lines[i:i+46] for i in range(0,len(lines),46)] or [["Chapter 18 comparative report"]]
    objects=[]; page_ids=[]; font_id=3+len(pages)*2
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    kids=" ".join(f"{3+i*2} 0 R" for i in range(len(pages)))
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>")
    for index,page in enumerate(pages):
        page_id=3+index*2; stream_id=page_id+1; page_ids.append(page_id)
        stream="BT /F1 10 Tf 48 790 Td 13 TL "+" ".join(f"({_pdf_escape(line[:150])}) Tj T*" for line in page)+" ET"
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {stream_id} 0 R >>")
        objects.append(f"<< /Length {len(stream.encode('latin-1','replace'))} >>\nstream\n{stream}\nendstream")
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    data=bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"); offsets=[0]
    for index,obj in enumerate(objects,1):
        offsets.append(len(data)); data.extend(f"{index} 0 obj\n{obj}\nendobj\n".encode("latin-1","replace"))
    xref=len(data); data.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]: data.extend(f"{offset:010d} 00000 n \n".encode())
    data.extend(f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    return bytes(data)


@router.get("/api/ops/report.pdf")
def comparative_report(_user=Depends(admin_user)):
    health={"MongoDB":_mongo_health(),"Cassandra":_cassandra_health(),"Neo4j":_neo4j_health()}; evaluation=_latest_evaluation(); communities=_graph_communities()
    try:
        benchmark=_fpdb["benchmarks"].find_one({}, {"_id":0},sort=[("measured_at",-1)])
        candidate_count=_collections()[1].count_documents({})
    except Exception:
        benchmark=None; candidate_count=None
    lines=["AEGIS INTELLIGENCE - CHAPTER 18", "Comparative Database Capstone Report", f"Generated: {_now().isoformat()}", "", "EXECUTIVE SUMMARY", f"MongoDB threats: {health['MongoDB']['counts'].get('fp.full_threats')}", f"MongoDB FP candidates: {health['MongoDB']['counts'].get('fp.candidates')}", f"Open/decided candidates stored: {candidate_count}", "Evaluation: "+evaluation.get("message","Labelled evaluation available."), "", "SYSTEM ARCHITECTURE", "Threat/import source -> MongoDB fp.full_threats (authoritative) -> Cassandra query tables and Neo4j evidence graph.", "MongoDB acknowledgement/read-back occurs before peer database writes.", "", "METHODOLOGY", "Benchmarks use 10 actual query/insert measurements per database; median and per-run samples are stored.", "False-positive metrics require imported/curated ground_truth_false_positive labels; no label-free accuracy claims are made.", "", "SCHEMA DESIGN", "MongoDB fp.full_threats: unique record_id, source/timestamp, indicator, family and label indexes.", "MongoDB fp.candidates: analyst status and explicit detection evidence; decisions are append-only in fp.decisions.", f"Cassandra keyspace {_keyspace()}: threats_by_source(source partition), threats_by_value(value partition), threats_by_family(family partition), volume_by_day(day, source partition).", "Neo4j: Threat, Family, Source, Indicator nodes; OBSERVED_BY, ATTRIBUTED_TO, SUSPICIOUS and SHARES_INDICATOR relationships.", "", "QUERY PERFORMANCE COMPARISON"]
    if benchmark:
        for result in benchmark.get("results",[]): lines.append(f"{result['database']} {result['query']}: median={result.get('median_latency_ms')} ms, dataset={result.get('dataset_size')}, errors={len(result.get('errors',[]))}; runs="+json.dumps(result.get("runs",[]),default=str)[:400])
    else: lines.append("No benchmark has been run; no performance values are reported.")
    if evaluation.get("metrics"):
        lines += ["", "LABELLED FALSE-POSITIVE EVALUATION"]
        for name, metric in evaluation["metrics"].items(): lines.append(f"{name}: TP={metric['true_positives']}, FN={metric['false_negatives']}, FP={metric['false_positives']}, TN={metric['true_negatives']}, precision={metric['precision']}, recall={metric['recall']}, F1={metric['f1']}, median_ms={metric['median_processing_ms']}")
    lines += ["", "DATA MODELLING ANALYSIS", "MongoDB retains canonical complete evidence and flexible source attributes. Cassandra tables serve source, indicator, and daily-volume access paths. Neo4j stores only imported source/family/indicator links.", "SCALABILITY ASSESSMENT (ESTIMATES, NOT MEASURED)", "1M records: shard/replicate MongoDB as workload warrants; Cassandra partition growth remains bounded by query bucketing; Neo4j graph/index sizing depends on relationship density.", "10M records: multi-shard MongoDB and Cassandra multi-node replication likely required; monitor hot source/indicator partitions and graph traversal depth.", "100M records: dedicated capacity planning, sharding, partition/retention strategy, Neo4j clustering and read scaling required; validate with representative load tests.", "Operational scaling estimates are not benchmark measurements.", "", "HORIZONTAL SCALING", "MongoDB: replica sets for availability; shard by a workload-aligned key with query targeting.", "Cassandra: partition design and replication factor across nodes/regions.", "Neo4j: clustering and supported read scaling depend on edition/version and topology; test graph workloads.", "", "OPERATIONS", "Use encrypted credentials, least privilege, backup/restore drills, database health monitoring, retention policies, and staff skilled in CQL/Cypher/sharding.", "Neo4j Browser password is configured in backend environment and must not be displayed here.", "", "FINAL RECOMMENDATION", "Use each store for its strengths; treat candidate flags as review leads, preserve historical records, and base false-positive quality claims only on labelled ground truth.", "", "DATABASE AVAILABILITY"]
    for name,item in health.items(): lines.append(f"{name}: available={item['available']}; latency_ms={item.get('latency_ms')}; count details="+json.dumps(item.get("counts"),default=str))
    lines += ["", "GRAPH COMMUNITY ANALYSIS", f"Available={communities.get('available')}; communities={communities.get('count')}; query="+communities.get("cypher","")]
    for community in communities.get("communities",[])[:20]: lines.append(f"{community['community_id']}: threats={community['threat_count']}, z={community['z_score']}, families={community['families']}, bridging={community['bridging_indicators']}")
    return Response(_make_pdf(lines),media_type="application/pdf",headers={"Content-Disposition":"attachment; filename=chapter-18-comparative-report.pdf"})


@router.get("/api/ops/lab18/export")
def export_threats(limit: int=Query(1000,ge=1,le=100000),_user=Depends(admin_user)):
    full, candidates, _=_collections(); excluded={row["value"] for row in candidates.find({"status":"confirmed_false_positive"},{"_id":0,"value":1})}
    rows=list(full.find({"value":{"$nin":list(excluded)}},{"_id":0}).sort("timestamp",-1).limit(limit))
    return {"records":rows,"count":len(rows),"excluded_confirmed_false_positives":len(excluded),"filtered_before_export":True}


@router.get("/extras/lab18/health")
def lab18_page_health(): return {"ok":True}
