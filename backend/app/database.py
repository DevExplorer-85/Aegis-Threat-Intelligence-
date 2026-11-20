import os
from pymongo import MongoClient
from dotenv import load_dotenv
from app.mongo_command_log import command_listeners_from_environment

load_dotenv()

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://localhost:27017",
)
DATABASE_NAME = os.getenv("DATABASE_NAME", "cyber_threat_intelligence")

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=int(os.getenv("MONGO_TIMEOUT_MS", "1500")),
    connectTimeoutMS=int(os.getenv("MONGO_TIMEOUT_MS", "1500")),
    event_listeners=command_listeners_from_environment(),
)

db = client[DATABASE_NAME]
