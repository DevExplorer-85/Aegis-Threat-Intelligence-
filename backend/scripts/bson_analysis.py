from app.database import db


print("\n========================================")
print("LAB 7.1 - BSON DOCUMENT SIZE ANALYSIS")
print("========================================")


result = list(
    db.threat_reports.aggregate([
        {
            "$group": {
                "_id": None,
                "average_size": {
                    "$avg": {"$bsonSize": "$$ROOT"}
                },
                "minimum_size": {
                    "$min": {"$bsonSize": "$$ROOT"}
                },
                "maximum_size": {
                    "$max": {"$bsonSize": "$$ROOT"}
                }
            }
        }
    ])
)


if result:
    data = result[0]

    print(f"Average document size : {data['average_size']:.2f} bytes")
    print(f"Minimum document size : {data['minimum_size']} bytes")
    print(f"Maximum document size : {data['maximum_size']} bytes")

    print("\nMongoDB document size limit: 16 MB")
    print("16 MB in bytes: 16,777,216 bytes")

    if data["maximum_size"] < 16 * 1024 * 1024:
        print("\nSTATUS: SAFE")
        print("No document is approaching the 16 MB limit.")
    else:
        print("\nSTATUS: WARNING")
        print("A document is approaching/exceeding the 16 MB limit.")


print("========================================")