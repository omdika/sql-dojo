from fastapi import FastAPI, HTTPException
import sqlite3
import os
import logging

logging.basicConfig(level=logging.INFO)

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
    SECURE LOGIN FUNCTION - Parameterized query to prevent SQL Injection

    This function uses parameterized SQL queries and basic input validation to prevent
    SQL injection vulnerabilities. It returns a tuple (id, username) if credentials are valid,
    otherwise returns None.
    """

    # Basic input validation
    if not isinstance(username, str) or not isinstance(password, str):
        logging.warning("Invalid input types provided to login")
        return None

    if len(username) > 150 or len(password) > 150:
        logging.warning("Input exceeds maximum allowed length")
        return None

    query = "SELECT id, username FROM users WHERE username = ? AND password = ?"

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception:
        logging.exception("Database query failed during login")
        return None

@app.post("/login")
async def login(username: str, password: str):
    """Login endpoint using secure parameterized queries to prevent SQL injection"""
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
                "warning": "This endpoint uses parameterized queries to prevent SQL injection"
            }
        else:
            return {
                "status": "error",
                "message": "Invalid credentials",
                "warning": "This endpoint uses parameterized queries to prevent SQL injection"
            }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Database error: {str(e)}",
            "warning": "This endpoint uses parameterized queries to prevent SQL injection"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)