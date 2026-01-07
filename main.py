from fastapi import FastAPI, HTTPException
import sqlite3
import os
import bcrypt

# Remediation summary:
# 1) Fixes: SQL injection in vulnerable_login_query by replacing string
#    concatenation with parameterized queries and adding password hashing.
# 2) Changes: use sqlite3 parameter binding, store password hashes with bcrypt,
#    and verify supplied password via bcrypt.checkpw.
# 3) Files modified: main.py

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

    # Insert some test users with hashed passwords
    users = [
        ('admin', bcrypt.hashpw(b'password123', bcrypt.gensalt()).decode()),
        ('user1', bcrypt.hashpw(b'secret456', bcrypt.gensalt()).decode()),
        ('test', bcrypt.hashpw(b'test789', bcrypt.gensalt()).decode()),
    ]
    cursor.executemany("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", users)

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

    # Secure: use parameterized query to fetch user by username and verify password hash
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        stored_hash = row[2]
        # Verify provided password against stored bcrypt hash
        if bcrypt.checkpw(password.encode(), stored_hash.encode()):
            return row
        else:
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

