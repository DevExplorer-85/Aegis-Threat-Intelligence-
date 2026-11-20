import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from pymongo import MongoClient, UpdateOne

load_dotenv()

MISP_URL = os.getenv("MISP_URL")
MISP_API_KEY = os.getenv("MISP_API_KEY")
MISP_VERIFY_TLS = os.getenv("MISP_VERIFY_TLS", "true").lower() == "true"
MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")

if MISP_URL is None or MISP_API_KEY is None or MONGO_URI is None or DATABASE_NAME is None:
    raise SystemExit(
        "Set MISP_URL, MISP_API_KEY, MONGO_URI, and DATABASE_NAME in backend/.env."
    )

misp_url = MISP_URL
misp_api_key = MISP_API_KEY
mongo_uri = MONGO_URI
database_name = DATABASE_NAME

try:
    from pymisp import PyMISP
except ImportError as exc:
    PyMISP = None
    _PYMISP_IMPORT_ERROR = exc
else:
    _PYMISP_IMPORT_ERROR = None

if PyMISP is None:
    raise SystemExit(
        "PyMISP is optional. Install backend/requirements-integrations.txt first."
    ) from _PYMISP_IMPORT_ERROR

misp = PyMISP(misp_url, misp_api_key, ssl=MISP_VERIFY_TLS)
client = MongoClient(mongo_uri)
db = client[database_name]
# Keep this separately authorized instance out of the public-feed event
# collection used by the dashboard and the three configured OSINT feeds.
events_collection = db["misp_instance_events"]
now = datetime.now(timezone.utc)

misp_events = misp.search(controller="events", published=True, pythonify=True)
operations = []

for event in misp_events:
    event_info = getattr(event, "info", None)
    event_uuid = getattr(event, "uuid", None)
    if not event_info or not event_uuid:
        print("Skipping MISP event without source info or UUID.")
        continue
    event_tags = [
        getattr(tag, "name", str(tag))
        for tag in (getattr(event, "tags", None) or [])
    ]

    for attribute in getattr(event, "attributes", None) or []:
        value = getattr(attribute, "value", None)
        if not value:
            continue

        attribute_uuid = getattr(attribute, "uuid", None) or str(
            getattr(attribute, "id", value)
        )
        attribute_type = getattr(attribute, "type", "unknown")
        external_id = f"misp:{event_uuid}:{attribute_uuid}"
        document = {
            "event_id": external_id,
            "external_id": external_id,
            "feed_id": "misp_instance",
            "source": "MISP",
            "title": event_info,
            "event_type": attribute_type,
            "indicator_type": attribute_type,
            "indicator_value": value,
            "classification": event_tags[0] if event_tags else "Unclassified",
            "severity": "Unknown",
            "tags": event_tags,
            "status": "active",
            "published": getattr(event, "date", None),
            "last_seen_at": now,
        }
        operations.append(
            UpdateOne(
                {"external_id": external_id},
                {"$set": document},
                upsert=True,
            )
        )

if operations:
    result = events_collection.bulk_write(operations, ordered=False)
    print(
        f"MISP attributes processed: {len(operations)}; "
        f"inserted: {result.upserted_count}; updated: {result.modified_count}"
    )
else:
    print("MISP returned no published event attributes.")

client.close()
