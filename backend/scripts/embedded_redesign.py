from app.database import db


print("\n========================================")
print("LAB 7.1 - EMBEDDING REDESIGN")
print("========================================")


# Remove previous test collection if it exists
db.threat_reports_embedded.drop()


# Fetch reports and join threat actors
reports = db.threat_reports.aggregate([
    {
        "$lookup": {
            "from": "threat_actors",
            "localField": "threat_actor_id",
            "foreignField": "_id",
            "as": "actor"
        }
    }
])


embedded_reports = []


for report in reports:

    actor = report["actor"][0] if report["actor"] else None

    # Create embedded threat actor
    embedded_actor = None

    if actor:
        embedded_actor = {
            "id": actor["_id"],
            "name": actor["name"],
            "aliases": actor["aliases"],
            "description": actor["description"],
            "threat_type": actor["threat_type"],
            "mention_count": actor.get("mention_count"),
        }

    # Remove reference-specific fields
    report.pop("threat_actor_id", None)
    report.pop("actor", None)

    # Add embedded actor
    report["threat_actor"] = embedded_actor

    embedded_reports.append(report)


# Insert redesigned documents
if embedded_reports:
    db.threat_reports_embedded.insert_many(embedded_reports)


print(
    "Embedded documents created:",
    db.threat_reports_embedded.count_documents({})
)


print("\nExample embedded document:")

example = db.threat_reports_embedded.find_one({"threat_actor": {"$ne": None}})

print(example)


print("\n========================================")
print("EMBEDDING REDESIGN COMPLETE")
print("========================================")