import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import db

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = PROJECT_ROOT / "awesome-annual-security-reports" / "Markdown Conversions"
COLLECTION = db["security_reports"]
INTERVAL_SECONDS = 10


def find_unimported_reports():
    known_sources = set(COLLECTION.distinct("source"))
    candidates = []
    if not REPORTS_DIR.is_dir():
        raise FileNotFoundError(f"Annual reports directory not found: {REPORTS_DIR}")

    for report_path in REPORTS_DIR.rglob("*.md"):
        if report_path.stem not in known_sources:
            candidates.append(report_path)

    return sorted(candidates, key=lambda path: (path.parent.name, path.name), reverse=True)


def cache_counters():
    cache = db.command("serverStatus").get("wiredTiger", {}).get("cache", {})
    requested = cache.get("pages requested from the cache")
    pages_read = cache.get("pages read into cache")
    if requested is None or pages_read is None:
        return None
    return requested, pages_read


def main():
    parser = argparse.ArgumentParser(
        description="Watch the local annual-report corpus for files not yet in MongoDB."
    )
    parser.add_argument("--once", action="store_true", help="Check once, then exit.")
    args = parser.parse_args()

    previous_counters = None
    print(f"Watching {REPORTS_DIR} every {INTERVAL_SECONDS} seconds; press Ctrl+C to stop.")
    try:
        while True:
            now = datetime.now().astimezone().isoformat(timespec="seconds")
            missing = find_unimported_reports()
            counters = cache_counters()
            interval_hit_ratio = None

            if counters is not None and previous_counters is not None:
                requested_delta = counters[0] - previous_counters[0]
                read_delta = counters[1] - previous_counters[1]
                if requested_delta > 0:
                    interval_hit_ratio = max(0, 1 - read_delta / requested_delta) * 100
            previous_counters = counters

            ratio_text = (
                f"{interval_hit_ratio:.2f}%"
                if interval_hit_ratio is not None
                else "unavailable"
            )
            print(f"[{now}] Unimported reports: {len(missing)} | 10s cache hit ratio: {ratio_text}")
            for path in missing[:20]:
                print(f"  {path.relative_to(REPORTS_DIR)}")
            if len(missing) > 20:
                print(f"  ... and {len(missing) - 20} more")

            if args.once:
                break
            time.sleep(INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")


if __name__ == "__main__":
    main()
