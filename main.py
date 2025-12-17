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
    SECURE LOGIN FUNCTION - Parameterized Query to Prevent SQL INJECTION

    This function uses parameterized queries instead of directly concatenating
    user input into SQL statements. Parameterized queries ensure that input is
    treated as data, not executable SQL, which prevents SQL injection attacks.

    Basic input validation is also applied: inputs are stripped and limited in length.
    """

    # Basic input validation: enforce types, strip whitespace, and limit length
    if not isinstance(username, str) or not isinstance(password, str):
        return None

    username = username.strip()
    password = password.strip()

    # Enforce reasonable length limits to avoid abuse (e.g., 256 chars)
    MAX_LEN = 256
    if len(username) == 0 or len(password) == 0 or len(username) > MAX_LEN or len(password) > MAX_LEN:
        return None

    # Use parameterized query to prevent SQL injection
    query = "SELECT id, username, password FROM users WHERE username = ? AND password = ?"
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        # Re-raise the exception to be handled by the caller
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