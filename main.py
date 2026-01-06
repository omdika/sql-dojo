from fastapi import FastAPI, HTTPException
import sqlite3
import os

# Analysis:
# 1. Vulnerability: SQL injection via f-string concatenation in vulnerable_login_query.
# 2. Fix: use parameterized queries and migrate to hashed password verification using PBKDF2; add password_hash column and migrate initial users.
# 3. Files modified: main.py (changed) and new auth_utils.py (added).
import auth_utils

app = FastAPI(title="Vulnerable SQL Injection Demo")

# Database configuration
DB_FILE = 'users.db'

# Create a simple SQLite database with a users table
def init_db(db_file=DB_FILE):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Insert some test users
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'password123')")
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('user1', 'secret456')")
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('test', 'test789')")

    # Ensure password_hash column exists for storing hashed passwords
    cursor.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in cursor.fetchall()]
    if 'password_hash' not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")

    # Populate password_hash for known initial users (migrate plaintext to hashed)
    initial_users = [('admin', 'password123'), ('user1', 'secret456'), ('test', 'test789')]
    for uname, pw in initial_users:
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (uname,))
        existing = cursor.fetchone()
        if not existing or existing[0] is None:
            ph = auth_utils.hash_password(pw)
            cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (ph, uname))

    conn.commit()
    conn.close()

@app.on_event("startup")
async def startup_event():
    init_db()

@app.get("/")
async def root():
    return {"message": "Vulnerable SQL Injection Demo - Visit /login endpoint"}

def vulnerable_login_query(username: str, password: str, db_file=DB_FILE):
    """
    VULNERABLE LOGIN FUNCTION - Contains SQL Injection Vulnerability

    This function demonstrates a classic SQL injection vulnerability.
    The username and password parameters are directly concatenated into the SQL query
    without any parameterization or input validation.

    Example attack payloads:
    - Username: admin' OR '1'='1' --
    - Username: ' OR 1=1 --
    - Username: admin'; DROP TABLE users; --
    """

    # Secure login: use parameterized queries to prevent SQL injection and verify hashed passwords.
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Basic defense-in-depth: reject overly long inputs
        if len(username) > 150 or len(password) > 512:
            conn.close()
            return None

        # Query by username only (parameterized) to avoid injection
        cursor.execute("SELECT id, username, password, password_hash FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        user_id, uname, plain_pw, pw_hash = row

        # If a password_hash exists, verify it; otherwise fallback to legacy plaintext check and migrate
        if pw_hash:
            if auth_utils.verify_password(pw_hash, password):
                conn.close()
                return (user_id, uname, plain_pw, pw_hash)
            else:
                conn.close()
                return None
        else:
            # Legacy plaintext comparison: verify and migrate to hashed password on successful auth
            if plain_pw == password:
                new_hash = auth_utils.hash_password(password)
                cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_hash, username))
                conn.commit()
                conn.close()
                return (user_id, uname, plain_pw, new_hash)
            else:
                conn.close()
                return None
    except Exception as e:
        raise e

@app.post("/login")
async def login(username: str, password: str):
    """Vulnerable login endpoint that uses the vulnerable query function"""
    try:
        user = vulnerable_login_query(username, password)

        if user:
            return {
                "status": "success",
                "message": "Login successful",
                "user": {
                    "id": user[0],
                    "username": user[1]
                },
                "warning": "This endpoint contains SQL injection vulnerability - for educational purposes only"
            }
        else:
            return {
                "status": "error",
                "message": "Invalid credentials",
                "warning": "This endpoint contains SQL injection vulnerability - for educational purposes only"
            }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Database error: {str(e)}",
            "warning": "This endpoint contains SQL injection vulnerability - for educational purposes only"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

