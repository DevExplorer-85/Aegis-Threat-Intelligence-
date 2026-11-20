import json
import os
import threading
from datetime import datetime, timezone

from bson import json_util
from pymongo.monitoring import CommandListener


class JsonCommandLogger(CommandListener):
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.pending = {}

    def _write(self, record):
        with self.lock, open(self.path, "a", encoding="utf-8") as output:
            output.write(json.dumps(record, default=json_util.default) + "\n")

    def started(self, event):
        with self.lock:
            self.pending[(event.connection_id, event.request_id)] = {
                "command": event.command_name,
                "database": event.database_name,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "request": event.command,
            }

    def succeeded(self, event):
        with self.lock:
            started = self.pending.pop((event.connection_id, event.request_id), {})
        self._write({
            **started,
            "duration_micros": event.duration_micros,
            "reply": event.reply,
            "status": "succeeded",
        })

    def failed(self, event):
        with self.lock:
            started = self.pending.pop((event.connection_id, event.request_id), {})
        self._write({
            **started,
            "duration_micros": event.duration_micros,
            "failure": event.failure,
            "status": "failed",
        })

    def close(self):
        return None


def command_listeners_from_environment():
    log_path = os.getenv("MONGO_COMMAND_LOG")
    return [JsonCommandLogger(log_path)] if log_path else []
