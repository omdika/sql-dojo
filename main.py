from fastapi import FastAPI, HTTPException
import sqlite3
import os
import re

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

    # Insert some test users (static queries with no external input)
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
    return {"message": "Vulnerable SQL Injection Demo - Visit /login endpoint"}

def vulnerable_login_query(username: str, password: str, db_file=DB_FILE):
    """
    FIXED LOGIN FUNCTION - Parameterized queries and input validation applied

    This function replaces previous vulnerable concatenation with a safe,
    parameterized query. It also enforces basic syntactic validation on the
    username to prevent misuse where only an identifier is expected.
    """

    # Basic type checks
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("username and password must be strings")

    # Enforce reasonable length limits to avoid excessively large inputs
    if len(username) == 0 or len(username) > 150:
        raise ValueError("username length is invalid")
    if len(password) == 0 or len(password) > 150:
        raise ValueError("password length is invalid")

    # Restrict username characters to a safe subset (alphanumeric and - _ .)
    # This prevents raw input from being used as SQL fragments or identifiers.
    if not re.match(r'^[A-Za-z0-9_.-]+$', username):
        raise ValueError("username contains invalid characters")

    # Use parameterized queries to avoid SQL injection. Never interpolate user input.
    query = "SELECT id, username FROM users WHERE username = ? AND password = ?"

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        # Re-raise the exception so calling code can handle or log it appropriately
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
                }
            }
        else:
            return {
                "status": "error",
                "message": "Invalid credentials"
            }

    except ValueError as ve:
        # Input validation errors
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        # General database error
        return {
            "status": "error",
            "message": f"Database error: {str(e)}"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
