# Security-hardened application code
import sqlite3
import subprocess
import pickle
import os
import logging

logger = logging.getLogger(__name__)

# API token loaded from environment variable instead of hardcoded
API_TOKEN = os.environ.get("API_TOKEN", "")

# simple SQLite DB on local disk
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # Fix CWE-89: Use parameterized queries to prevent SQL injection
    sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    cur.execute(sql, (username, password))
    conn.commit()

def get_user(username):
    # Fix CWE-89: Use parameterized queries to prevent SQL injection
    q = "SELECT id, username FROM users WHERE username = ?"
    cur.execute(q, (username,))
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # insecure deserialization of untrusted data
    return pickle.loads(blob)

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Fix CWE-200: Do not print sensitive information to logs
    logger.debug("Application initialized")
    print(get_user("alice"))
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize an arbitrary blob (will likely raise)
        deserialize_blob(b"not-a-valid-pickle")
    except Exception as e:
        logger.error("Deserialization error: %s", e)
