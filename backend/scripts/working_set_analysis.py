from app.database import db

collection_name = "working_set_test"
collection = db[collection_name]

count = collection.count_documents({})
if count != 100_000:
    raise SystemExit(
        f"Lab 7.2 requires exactly 100,000 records; {collection_name} "
        f"currently contains {count:,}. Run scripts.fetch_working_set first."
    )

stats = db.command("collStats", collection_name)
avg_size = stats.get("avgObjSize", 0)
data_size = stats.get("size", 0)
index_size = stats.get("totalIndexSize", 0)
status = db.command("serverStatus")
storage_engine = status.get("storageEngine", {}).get("name")
cache = status.get("wiredTiger", {}).get("cache", {})

print("===================================")
print("WORKING SET ANALYSIS")
print("===================================")

print("Collection      :", collection_name)
print("Source records  : original attributes fetched directly from public MISP feeds")
print("Documents       :", f"{count:,}")
print("Average Doc Size:", avg_size, "bytes")
print("Data Size       :", round(data_size / (1024 * 1024), 2), "MB")
print("Index Size      :", round(index_size / (1024 * 1024), 2), "MB")
print("Data + Indexes  :", round((data_size + index_size) / (1024 * 1024), 2), "MB")

print("\nWIREDTIGER CACHE")
print("===================================")

print("Storage engine  :", storage_engine or "Unavailable")
if storage_engine == "wiredTiger" and cache:
    maximum = cache.get("maximum bytes configured")
    current = cache.get("bytes currently in the cache")
    print("Cache metrics   : live WiredTiger serverStatus values")

    for key in [
        "maximum bytes configured",
        "bytes currently in the cache",
        "tracked dirty bytes in the cache",
        "pages read into cache",
        "pages written from cache"
    ]:
        value = cache.get(key)

        if value is not None:
            if "bytes" in key:
                print(
                    key, ":",
                    round(value / (1024 * 1024), 2),
                    "MB"
                )
            else:
                print(key, ":", value)
    if maximum and current is not None:
        print("Cache utilization:", f"{current / maximum * 100:.2f}%")
    if maximum:
        footprint = data_size + index_size
        print("Dataset footprint/cache capacity:", f"{footprint / maximum * 100:.2f}% (capacity comparison, not residency)")
    print("Note: cache counters cover the entire MongoDB process, not just this collection.")
else:
    print("WiredTiger cache metrics are unavailable from this deployment.")

print("\nMongoDB Version:")
print(status.get("version", "Unknown"))