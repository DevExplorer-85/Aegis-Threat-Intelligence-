import os
import signal
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from pymongo import MongoClient


router = APIRouter()
PROJECT_ROOT = Path(__file__).resolve().parents[2]
LAB_SCRIPT = Path("/app/lab.py") if Path("/app/lab.py").is_file() else PROJECT_ROOT / "lab.py"
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", str(PROJECT_ROOT / "output")))
RESULTS_DIR = OUTPUT_DIR / "results"
JOBS_DIR = OUTPUT_DIR / "jobs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
JOBS_DIR.mkdir(parents=True, exist_ok=True)
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo1:27017/?directConnection=true")
MONGO_URI_CH10 = os.getenv("MONGO_URI_CH10")
MONGO_URI_CH11 = os.getenv("MONGO_URI_CH11")
ALLOWED_JOBS = {
    "setup", "reset", "7-load", "7-status", "7.1", "7.1-try",
    "7.2", "7.2-try", "8.1", "8.1-try", "8.2", "8.2-try",
    "9.1", "9.1-try", "9.2", "10.1", "10.1-try", "10.2", "10.2-try",
    "11.1", "11.1-try", "11.2",
    "12.1", "12.1-try", "12.2", "12.2-try", "12.3",
    "13.1", "13.2", "13-all",
    "7-all", "8-all", "9-all", "10-all", "11-all", "12-all", "all",
}
TRANSACTION_LABS = {"10.1", "10.1-try", "10.2", "10.2-try", "10-all"}
SHARDING_LABS = {"11.2", "11-all"}

_jobs = {}
_jobs_lock = threading.Lock()


def _transaction_uri_for_job(lab):
    if lab not in TRANSACTION_LABS:
        return None
    if not MONGO_URI_CH10:
        raise HTTPException(
            status_code=503,
            detail=(
                "Transaction labs require a replica set. "
                "Configure MONGO_URI_CH10 and ensure its primary is available."
            ),
        )
    return MONGO_URI_CH10


def _sharding_uri_for_job(lab):
    if lab not in SHARDING_LABS:
        return None
    if not MONGO_URI_CH11:
        raise HTTPException(
            status_code=503,
            detail=(
                "The live sharding lab requires a mongos router. "
                "Configure MONGO_URI_CH11 and ensure both shards are available."
            ),
        )
    return MONGO_URI_CH11


class JobRequest(BaseModel):
    lab: str = Field(min_length=1, max_length=16)


def _job_payload(job, since):
    process = job["process"]
    return_code = process.poll()
    if return_code is not None and job["status"] in ("queued", "running", "stopping"):
        job["status"] = "completed" if return_code == 0 else "failed"
        job["return_code"] = return_code
        job["finished_at"] = datetime.now(timezone.utc).isoformat()
    try:
        lines = job["log_path"].read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        lines = []
    cursor = max(0, min(since, len(lines)))
    return {
        "id": job["id"],
        "lab": job["lab"],
        "status": job["status"],
        "lines": lines[cursor:],
        "next": len(lines),
        "return_code": job.get("return_code"),
        "started_at": job["started_at"],
        "finished_at": job.get("finished_at"),
    }


@router.get("/api/cluster")
def get_cluster():
    try:
        with MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=800,
            connectTimeoutMS=800,
            socketTimeoutMS=1000,
        ) as client:
            ping = client.admin.command("ping")
            hello = client.admin.command("hello")
            server = client.admin.command("buildInfo")
    except Exception as error:
        return {
            "deployment": "standalone",
            "connected": False,
            "primary": None,
            "no_primary": False,
            "members": [],
            "error": f"MongoDB unavailable ({type(error).__name__}).",
            "sampled_at": datetime.now(timezone.utc).isoformat(),
        }
    member_name = hello.get("me", "mongo1:27017")
    return {
        "deployment": "standalone",
        "connected": bool(ping.get("ok")),
        "primary": None,
        "no_primary": False,
        "mongodb_version": server.get("version"),
        "members": [{
            "name": member_name,
            "state": "STANDALONE",
            "health": 1 if ping.get("ok") else 0,
            "reachable": bool(ping.get("ok")),
            "network_disconnected": False,
        }],
        "error": None,
        "sampled_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/api/transactions/status")
def get_transaction_cluster():
    if not MONGO_URI_CH10:
        return {
            "configured": False,
            "connected": False,
            "replica_set": None,
            "primary": False,
            "error": "Configure MONGO_URI_CH10 to enable transaction labs.",
            "sampled_at": datetime.now(timezone.utc).isoformat(),
        }

    try:
        with MongoClient(
            MONGO_URI_CH10,
            serverSelectionTimeoutMS=800,
            connectTimeoutMS=800,
            socketTimeoutMS=1000,
        ) as client:
            hello = client.admin.command("hello")
    except Exception as error:
        return {
            "configured": True,
            "connected": False,
            "replica_set": None,
            "primary": False,
            "error": f"Transaction replica set unavailable ({type(error).__name__}).",
            "sampled_at": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "configured": True,
        "connected": bool(hello.get("setName")),
        "replica_set": hello.get("setName"),
        "primary": bool(hello.get("isWritablePrimary")),
        "error": None,
        "sampled_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/api/sharding/status")
def get_sharding_cluster():
    if not MONGO_URI_CH11:
        return {
            "configured": False,
            "connected": False,
            "router": False,
            "shards": [],
            "error": "Configure MONGO_URI_CH11 to enable live sharding labs.",
            "sampled_at": datetime.now(timezone.utc).isoformat(),
        }

    try:
        with MongoClient(
            MONGO_URI_CH11,
            serverSelectionTimeoutMS=800,
            connectTimeoutMS=800,
            socketTimeoutMS=1000,
        ) as client:
            hello = client.admin.command("hello")
            shards = client.admin.command("listShards").get("shards", [])
    except Exception as error:
        return {
            "configured": True,
            "connected": False,
            "router": False,
            "shards": [],
            "error": f"Sharded cluster unavailable ({type(error).__name__}).",
            "sampled_at": datetime.now(timezone.utc).isoformat(),
        }

    is_router = hello.get("msg") == "isdbgrid"
    return {
        "configured": True,
        "connected": is_router,
        "router": is_router,
        "shards": [
            {"id": shard.get("_id"), "host": shard.get("host")}
            for shard in shards
        ],
        "error": None if is_router else "Configured MongoDB endpoint is not a mongos router.",
        "sampled_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/api/security/status")
def get_security_status():
    from scripts.lab12_security import inspect_tls_files

    tls_info = inspect_tls_files()
    return {
        "configured": True,
        "tls_ready": tls_info["all_files_present"],
        "tls_directory": tls_info["tls_dir"],
        "rbac_ready": True,
        "ca_common_name": tls_info["ca_common_name"],
        "server_common_name": tls_info["server_common_name"],
        "subject_alternative_names": tls_info["subject_alternative_names"],
        "sampled_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/api/jobs")
def start_job(request: JobRequest):
    lab = request.lab
    if lab not in ALLOWED_JOBS:
        raise HTTPException(status_code=422, detail=f"Unknown experiment: {lab}")
    transaction_uri = _transaction_uri_for_job(lab)
    sharding_uri = _sharding_uri_for_job(lab)
    with _jobs_lock:
        active = next(
            (job for job in _jobs.values() if job["process"].poll() is None),
            None,
        )
        if active is not None:
            raise HTTPException(
                status_code=409,
                detail=f"Experiment {active['lab']} is already running.",
            )
        job_id = str(uuid.uuid4())
        log_path = JOBS_DIR / f"{job_id}.log"
        log_file = log_path.open("w", encoding="utf-8", buffering=1)
        environment = os.environ.copy()
        if transaction_uri is not None:
            environment["MONGO_URI"] = transaction_uri
        if sharding_uri is not None:
            environment["MONGO_URI"] = sharding_uri
        environment["MONGO_COMMAND_LOG"] = str(OUTPUT_DIR / f"{lab.replace('.', '')}-{job_id}-commands.jsonl")
        environment["PYTHONUNBUFFERED"] = "1"
        try:
            process = subprocess.Popen(
                [os.getenv("PYTHON", sys.executable), str(LAB_SCRIPT), lab],
                cwd=str(PROJECT_ROOT / "backend"),
                env=environment,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except OSError as error:
            log_file.close()
            raise HTTPException(
                status_code=500,
                detail=f"Could not start lab runner: {error}",
            ) from error
        log_file.close()
        job = {
            "id": job_id,
            "lab": lab,
            "process": process,
            "log_path": log_path,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        _jobs[job_id] = job
    return _job_payload(job, 0)


@router.get("/api/jobs/{job_id}")
def get_job(job_id: str, since: int = Query(0, ge=0)):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Lab job not found.")
        return _job_payload(job, since)


@router.post("/api/jobs/{job_id}/stop")
def stop_job(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Lab job not found.")
        process = job["process"]
        if process.poll() is None:
            try:
                process.send_signal(signal.SIGINT)
            except OSError as error:
                raise HTTPException(
                    status_code=500,
                    detail=f"Could not interrupt the experiment: {error}",
                ) from error
            job["status"] = "stopping"
    return _job_payload(job, 0)


@router.get("/api/results")
def get_results():
    results = []
    for path in sorted(RESULTS_DIR.glob("*.json")):
        if path.stem.endswith("-latest"):
            continue
        try:
            record = json_load(path)
        except (OSError, ValueError):
            continue
        if record.get("lab") == path.stem:
            results.append({
                "lab": record["lab"],
                "generated_at": record.get("generated_at"),
                "url": f"/api/results/{record['lab']}",
            })
    return {"results": sorted(results, key=lambda item: item["lab"])}


def json_load(path):
    import json

    return json.loads(path.read_text(encoding="utf-8"))


@router.get("/api/results/{lab}")
def get_result(lab: str):
    if lab not in ALLOWED_JOBS and lab not in ("status", "compose", "results"):
        raise HTTPException(status_code=404, detail="Unknown experiment result.")
    path = RESULTS_DIR / f"{lab}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"No saved result exists for {lab}.")
    try:
        return json_load(path)
    except (OSError, ValueError) as error:
        raise HTTPException(status_code=500, detail=f"Could not read saved result: {error}") from error
