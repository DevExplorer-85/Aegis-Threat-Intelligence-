import os
import re
from pathlib import Path
from pymongo import MongoClient
from dotenv import load_dotenv

# -----------------------------
# Load environment variables
# -----------------------------
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")

client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]

collection = db["security_reports"]

# -----------------------------
# Dataset path
# -----------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    PROJECT_ROOT
    / "awesome-annual-security-reports"
    / "Markdown Conversions"
)

print("Dataset path:")
print(DATASET_PATH)

if not DATASET_PATH.exists():
    raise FileNotFoundError(
        f"Dataset folder not found: {DATASET_PATH}"
    )

# -----------------------------
# Helper functions
# -----------------------------
def extract_title(text, filename):
    """
    Try to extract the first Markdown heading.
    """

    match = re.search(r"^\s*#\s+(.+)", text, re.MULTILINE)

    if match:
        return match.group(1).strip()

    return Path(filename).stem


def clean_text(text):
    """
    Basic Markdown cleanup.
    """

    text = text.replace("\x00", "")

    # Remove excessive blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


# -----------------------------
# Read reports
# -----------------------------
documents = []

files = list(DATASET_PATH.rglob("*.md"))

print(f"\nMarkdown files found: {len(files)}")

for index, file_path in enumerate(files, start=1):

    try:
        text = file_path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

        text = clean_text(text)

        if not text:
            continue

        # Year is the parent folder
        year = file_path.parent.name

        title = extract_title(
            text,
            file_path.name
        )

        # Source/report filename
        source = file_path.stem

        document = {
            "report_id": f"report_{index:05d}",
            "year": year,
            "title": title,
            "source": source,
            "file_name": file_path.name,
            "content": text,
            "content_size_bytes": len(
                text.encode("utf-8")
            ),
            "dataset": "Awesome Annual Security Reports"
        }

        documents.append(document)

        if index % 100 == 0:
            print(
                f"Processed {index}/{len(files)} files"
            )

    except Exception as e:

        print(
            f"Error reading {file_path}: {e}"
        )


# -----------------------------
# Insert into MongoDB
# -----------------------------
if documents:

    print(
        f"\nInserting {len(documents)} reports into MongoDB..."
    )

    collection.delete_many({})

    collection.insert_many(
        documents,
        ordered=False
    )

    print(
        f"Successfully inserted {len(documents)} documents."
    )

else:

    print("No documents found.")


# -----------------------------
# Create indexes
# -----------------------------
collection.create_index("year")
collection.create_index("title")
collection.create_index("source")

print("\nIndexes created.")

print(
    "\nFinal document count:",
    collection.count_documents({})
)

client.close()