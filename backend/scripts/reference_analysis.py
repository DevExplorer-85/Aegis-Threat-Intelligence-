from app.database import db


print("\n========================================")
print("LAB 7.1 - REFERENCING ANALYSIS")
print("========================================")


result = db.threat_reports.aggregate([
    {
        "$lookup": {
            "from": "threat_actors",
            "localField": "threat_actor_id",
            "foreignField": "_id",
            "as": "threat_actor"
        }
    },
    {
        "$project": {
            "_id": 1,
            "title": 1,
            "threat_actor_id": 1,
            "threat_actor": 1
        }
    }
])


for report in result:

    print("\n----------------------------------------")
    print("Report ID:", report["_id"])
    print("Title:", report["title"])
    print("Referenced Actor ID:", report["threat_actor_id"])

    if report["threat_actor"]:
        actor = report["threat_actor"][0]

        print("Actor Name:", actor["name"])
        print("Actor Type:", actor["threat_type"])


print("\n========================================")
print("REFERENCING ANALYSIS COMPLETE")
print("========================================")