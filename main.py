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


def secure_login_query(username: str, password: str, db_file=DB_FILE):
    """
    SECURE LOGIN FUNCTION - Uses parameterized queries to prevent SQL injection.

    This function uses SQLite parameter binding where user-supplied values are passed
    as parameters to the query instead of being concatenated into the SQL text.
    """

    # Use parameterized query to avoid SQL injection
    query = "SELECT id, username FROM users WHERE username = ? AND password = ?"

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        raise e

# Backwards-compatible wrapper kept for tests/examples. It delegates to the secure implementation
# to maintain the same function name while preventing SQL injection.
def vulnerable_login_query(username: str, password: str, db_file=DB_FILE):
    """Compatibility wrapper that previously contained vulnerable concatenation.

    For security, this now calls the secure, parameterized implementation.
    Keeping this symbol prevents ImportError in existing tests while removing the vulnerability.
    """
    return secure_login_query(username, password, db_file)

@app.post("/login")
async def login(username: str, password: str):
    """Secure login endpoint that uses parameterized queries"""
    try:
        user = secure_login_query(username, password)

        if user:
            return {
                "status": "success",
                "message": "Login successful",
                "user": {
                    "id": user[0],
                    "username": user[1]
                },
                "warning": "This endpoint has been fixed to prevent SQL injection"
            }
        else:
            return {
                "status": "error",
                "message": "Invalid credentials",
                "warning": "This endpoint has been fixed to prevent SQL injection"
            }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Database error: {str(e)}",
            "warning": "This endpoint has been fixed to prevent SQL injection"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
