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

def safe_login_query(username: str, password: str, db_file=DB_FILE):
    """
    SAFE LOGIN FUNCTION - Uses parameterized queries to prevent SQL Injection

    This function uses parameterized SQL queries (SQLite parameter style)
    to ensure user-supplied values are never injected directly into the SQL
    string. It also performs basic input validation to guard against
    unexpected input types or extremely long input.
    """

    # Basic input validation
    if not isinstance(username, str) or not isinstance(password, str):
        return None

    # Limit length to reasonable bounds to avoid abuse
    if len(username) > 256 or len(password) > 256:
        return None

    query = "SELECT * FROM users WHERE username = ? AND password = ?"

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        # Use parameterized query to prevent SQL injection
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        # Do not leak internal errors; re-raise for higher-level handling
        raise e

@app.post("/login")
async def login(username: str, password: str):
    """Login endpoint that uses a safe, parameterized query to prevent SQL injection"""
    try:
        # Use the safe, parameterized query function
        user = safe_login_query(username, password)

        if user:
            return {
                "status": "success",
                "message": "Login successful",
                "user": {
                    "id": user[0],
                    "username": user[1]
                },
                "info": "Login performed using safe parameterized queries"
            }
        else:
            return {
                "status": "error",
                "message": "Invalid credentials",
                "info": "Login failed - credentials did not match"
            }

    except Exception as e:
        return {
            "status": "error",
            "message": "Database error",
            "detail": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)