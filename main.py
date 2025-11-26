from fastapi import FastAPI, HTTPException
import sqlite3
import os

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
    FIXED LOGIN FUNCTION - SQL Injection Mitigated

    This function now uses parameterized queries to avoid SQL injection.
    It also performs basic input validation to reject empty or overly long inputs.
    """

    # Basic input validation
    if not isinstance(username, str) or not isinstance(password, str):
        return None

    username = username.strip()
    password = password.strip()

    if not username or not password:
        return None

    # Enforce reasonable maximum lengths to mitigate certain injection vectors
    MAX_LEN = 150
    if len(username) > MAX_LEN or len(password) > MAX_LEN:
        return None

    query = "SELECT id, username FROM users WHERE username = ? AND password = ?"

    try:
        # Use a context manager to ensure the connection is closed properly
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            # Parameterized query prevents SQL injection
            cursor.execute(query, (username, password))
            user = cursor.fetchone()
            return user
    except Exception:
        # Do not leak internal error details
        return None

@app.post("/login")
async def login(username: str, password: str):
    """Secure login endpoint that uses the fixed query function"""
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

    except Exception:
        # Generic error message to avoid leaking implementation details
        return {
            "status": "error",
            "message": "Internal server error"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
