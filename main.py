from fastapi import FastAPI, HTTPException
import sqlite3
import os
import re

app = FastAPI(title="Vulnerable SQL Injection Demo (Fixed)")

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

    conn.commit()
    conn.close()

@app.on_event("startup")
async def startup_event():
    init_db()

@app.get("/")
async def root():
    return {"message": "Vulnerable SQL Injection Demo - Use /login endpoint (now secured)"}

def vulnerable_login_query(username: str, password: str, db_file=DB_FILE):
    """
    SECURE LOGIN FUNCTION - Parameterized queries to prevent SQL Injection

    This function uses parameter binding instead of string concatenation.
    Basic input validation is also applied to reject obviously malicious inputs
    such as control characters and overly long values.
    """

    # Basic type and length checks to enforce expected input shapes
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("Username and password must be strings")

    # Enforce reasonable maximum lengths
    MAX_LEN = 150
    if len(username) > MAX_LEN or len(password) > MAX_LEN:
        raise ValueError("Input too long")

    # Disallow control characters and statement separators that could indicate attempts
    # to inject SQL when other protections are missing. Parameterization below is the primary defense.
    if any(c in username for c in ['\n', '\r', ';']) or any(c in password for c in ['\n', '\r', ';']):
        raise ValueError("Invalid characters in input")

    # Optional: enforce a simple allowlist for usernames (alphanumeric and limited punctuation)
    if not re.match(r"^[A-Za-z0-9_@.\-]+$", username):
        # If the username contains characters outside the allowlist, still proceed but it's logged/blocked here.
        raise ValueError("Username contains invalid characters")

    # Use parameterized query (sqlite3 uses ? placeholders) to bind values safely
    query = "SELECT id, username, password FROM users WHERE username = ? AND password = ?"

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        raise e

@app.post("/login")
async def login(username: str, password: str):
    """Secure login endpoint that uses parameterized queries"""
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
                "note": "This endpoint now uses parameterized queries and basic input validation"
            }
        else:
            return {
                "status": "error",
                "message": "Invalid credentials",
                "note": "This endpoint now uses parameterized queries and basic input validation"
            }

    except ValueError as ve:
        # Input validation errors should be treated as bad requests
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        # Generic database error
        return {
            "status": "error",
            "message": f"Database error: {str(e)}",
            "note": "This endpoint now uses parameterized queries and basic input validation"
        }

if __name__ == "__main__":
    # Self-test routine to validate the fix without starting a server
    test_db = 'test_users.db'

    # Ensure a clean test database
    if os.path.exists(test_db):
        os.remove(test_db)

    init_db(test_db)

    print("Running self-tests...")

    # Test 1: valid credentials should succeed
    try:
        valid_user = vulnerable_login_query('admin', 'password123', db_file=test_db)
        print("Valid login returned:", bool(valid_user))
    except Exception as e:
        print("Valid login raised exception:", e)
        valid_user = None

    # Test 2: SQL injection attempt should NOT succeed
    try:
        injection_payload = "admin' OR '1'='1' --"
        injected_user = vulnerable_login_query(injection_payload, 'irrelevant', db_file=test_db)
        print("Injection attempt returned:", injected_user)
    except Exception as e:
        print("Injection attempt raised exception (expected if blocked by validation):", e)
        injected_user = None

    if valid_user and not injected_user:
        print("Script completed successfully, no errors.")
    else:
        print("Self-test failed: SQL injection may still be possible or valid login failed.")

    # Cleanup test database
    try:
        os.remove(test_db)
    except Exception:
        pass
