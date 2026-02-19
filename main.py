# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import ast  # Using ast.literal_eval instead of pickle for safe deserialization
import os

# hardcoded API token (Issue 1)
API_TOKEN = "AKIAEXAMPLERAWTOKEN12345"

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # Using parameterized queries to prevent SQL injection
    sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    cur.execute(sql, (username, password))
    conn.commit()

def get_user(username):
    # Using parameterized queries to prevent SQL injection
    q = "SELECT id, username FROM users WHERE username = ?"
    cur.execute(q, (username,))
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input (Issue 4)
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # Using ast.literal_eval for safe deserialization of basic Python literals
    # This only allows strings, numbers, tuples, lists, dicts, booleans, and None
    try:
        return ast.literal_eval(blob.decode() if isinstance(blob, bytes) else blob)
    except (ValueError, SyntaxError):
        raise ValueError("Invalid or unsafe data format")

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Demonstrate risky calls
    print("API_TOKEN in use:", API_TOKEN)
    print(get_user("alice"))  # Using safe parameterized query
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize using safe method
        deserialize_blob("{'key': 'value'}")
    except Exception as e:
        print("Deserialization error:", e)