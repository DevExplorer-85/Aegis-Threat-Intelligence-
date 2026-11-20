from app.database import db

source = db["security_reports"]
target = db["security_report_passages"]

# Clean old collection if it exists
target.drop()

documents = []
total_passages = 0

for report in source.find({}):
    content = report.get("content", "")

    if not content:
        continue

    # Split large reports into approximately page-sized passages
    words = content.split()
    chunk_size = 500

    page_number = 1

    for i in range(0, len(words), chunk_size):
        passage = " ".join(words[i:i + chunk_size])

        documents.append({
            "report_id": report.get("report_id"),
            "title": report.get("title"),
            "year": report.get("year"),
            "source": report.get("source"),
            "file_name": report.get("file_name"),
            "page_number": page_number,
            "passage": passage,
            "passage_size": len(passage),
            "dataset": "Awesome Annual Security Reports"
        })

        page_number += 1
        total_passages += 1

        # Insert in batches
        if len(documents) >= 500:
            target.insert_many(documents)
            documents = []

if documents:
    target.insert_many(documents)

print("===================================")
print("Passage creation completed")
print("Reports:", source.count_documents({}))
print("Passages:", target.count_documents({}))
print("===================================")