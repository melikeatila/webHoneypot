from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, DateTime, Text
from datetime import datetime
import os

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.getenv("HONEYPOT_DB_PATH", os.path.join(BASE_DIR, "honeypot.db"))
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH}")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
metadata = MetaData()

admin_login_attempts = Table(
    "admin_login_attempts", metadata,
    Column("id", Integer, primary_key=True),
    Column("ip", String(100)),
    Column("username", String(255)),
    Column("password_mask", String(255)),
    Column("user_agent", String(512)),
    Column("timestamp", DateTime, default=datetime.utcnow),
)

search_logs = Table(
    "search_logs", metadata,
    Column("id", Integer, primary_key=True),
    Column("ip", String(100)),
    Column("query", Text),  # Arama sorgusu
    Column("q_hash", String(255)),
    Column("user_agent", String(512)),
    Column("timestamp", DateTime, default=datetime.utcnow),
)

upload_logs = Table(
    "upload_logs", metadata,
    Column("id", Integer, primary_key=True),
    Column("ip", String(100)),
    Column("filename", String(255)),
    Column("content_type", String(100)),
    Column("file_size", Integer),
    Column("file_hash", String(255)),
    Column("user_agent", String(512)),
    Column("timestamp", DateTime, default=datetime.utcnow),
)

request_logs = Table(
    "request_logs", metadata,
    Column("id", Integer, primary_key=True),
    Column("ip", String(100)),
    Column("path", String(255)),
    Column("method", String(10)),
    Column("query", Text),
    Column("body_hash", String(255)),
    Column("user_agent", String(512)),
    Column("timestamp", DateTime, default=datetime.utcnow),
)

contact_submissions = Table(
    "contact_submissions", metadata,
    Column("id", Integer, primary_key=True),
    Column("ip", String(100)),
    Column("name", String(255)),
    Column("email_masked", String(255)),
    Column("phone_masked", String(50)),
    Column("message_hash", String(255)),
    Column("user_agent", String(512)),
    Column("timestamp", DateTime, default=datetime.utcnow),
)

bait_clicks = Table(
    "bait_clicks", metadata,
    Column("id", Integer, primary_key=True),
    Column("ip", String(100)),
    Column("bait_path", String(255)),
    Column("referer", String(512)),
    Column("user_agent", String(512)),
    Column("timestamp", DateTime, default=datetime.utcnow),
)

command_executions = Table(
    "command_executions", metadata,
    Column("id", Integer, primary_key=True),
    Column("ip", String(100)),
    Column("command_hash", String(255)),
    Column("user_agent", String(512)),
    Column("timestamp", DateTime, default=datetime.utcnow),
)

def init_db():
    metadata.create_all(engine)
    return DB_PATH
