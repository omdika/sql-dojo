from fastapi import FastAPI, HTTPException
import sqlite3
import os
import hashlib
import binascii
import secrets
import re

# Phase 1 analysis:
# 1) Vulnerability: confirmed SQL injection in vulnerable_login_query due to direct string interpolation.
# 2) Changes: use parameterized queries to prevent SQL injection, store/verify passwords using PBKDF2-HMAC-SHA256,
#    and add basic username validation. These changes are contained within main.py only.
# 3) Files modified: main.py

app = FastAPI(title="Vulnerable SQL Injection Demo")

# Database configuration
DB_FILE = 'users.db'

# Create a simple SQLite database with a users table
def hash_password(password: str, iterations: int = 100_000) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 and return a string of the form:
    pbkdf2_sha256$iterations$salt_hex$hash_hex
    """
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return f"pbkdf2_sha256${iterations}${binascii.hexlify(salt).decode()}${binascii.hexlify(dk).decode()}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a stored pbkdf2 hashed password against one provided by user."""
    try:
        algo, iterations, salt_hex, hash_hex = stored_password.split('$')
        if algo != 'pbkdf2_sha256':
            return False
        iterations = int(iterations)
        salt = binascii.unhexlify(salt_hex)
        dk = binascii.unhexlify(hash_hex)
        test_dk = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, iterations)
        return secrets.compare_digest(dk, test_dk)
    except Exception:
        return False

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

    # Insert some test users with hashed passwords
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
                   ('admin', hash_password('password123')))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
                   ('user1', hash_password('secret456')))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
                   ('test', hash_password('test789')))

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

    # Secure code: use parameterized query to prevent SQL injection and verify hashed password.
    # Basic username validation: allow common username characters and limit length to 150.
    if not isinstance(username, str) or not re.match(r'^[A-Za-z0-9_.-]{1,150}$', username):
        return None

    query = "SELECT * FROM users WHERE username = ?"

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        conn.close()
        # user columns: (id, username, password)
        if user and verify_password(user[2], password):
            return user
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

