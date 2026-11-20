from app.database import db
import time


print("\n========================================")
print("EMBEDDING VS REFERENCING COMPARISON")
print("========================================")


# ============================================================
# 1. REFERENCING
# ============================================================

start = time.perf_counter()

referenced_reports = list(
    db.threat_reports.aggregate([
        {
            "$lookup": {
                "from": "threat_actors",
                "localField": "threat_actor_id",
                "foreignField": "_id",
                "as": "threat_actor"
            }
        },
        {
            "$match": {
                "threat_actor.name": "Aisuru"
            }
        }
    ])
)

reference_time = (time.perf_counter() - start) * 1000


# ============================================================
# 2. EMBEDDING
# ============================================================

start = time.perf_counter()

embedded_reports = list(
    db.threat_reports_embedded.find({
        "threat_actor.name": "Aisuru"
    })
)

embedding_time = (time.perf_counter() - start) * 1000


# ============================================================
# RESULTS
# ============================================================

print("\nReferencing Design")
print("------------------")
print("Reports found:", len(referenced_reports))
print(f"Query time: {reference_time:.4f} ms")


print("\nEmbedding Design")
print("----------------")
print("Reports found:", len(embedded_reports))
print(f"Query time: {embedding_time:.4f} ms")


print("\n========================================")
print("ANALYSIS")
print("========================================")

print("""
Embedding allows the application to retrieve the
report and threat actor information from the same
document without requiring a $lookup.

Referencing keeps shared threat actor information
in one place and avoids data duplication.

Embedding becomes harder when a shared threat actor
needs to be updated because the actor information
may exist in many report documents.
""")

print("========================================")