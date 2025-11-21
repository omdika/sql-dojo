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
    SECURE LOGIN FUNCTION - Parameterized Queries

    This function replaces the previous vulnerable implementation and uses
    parameterized SQL queries to prevent SQL injection. It also performs basic
    input validation (type and length checks) to reduce the risk of unexpected input.
    """

    # Basic input validation
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("Invalid input types")

    # Enforce reasonable length limits to avoid extremely large inputs
    MAX_LEN = 150
    if len(username) > MAX_LEN or len(password) > MAX_LEN:
        raise ValueError("Input too long")

    # PARAMETERIZED QUERY: Use placeholders instead of string concatenation
    query = "SELECT * FROM users WHERE username = ? AND password = ?"

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
    """Secure login endpoint that uses a parameterized query"""
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
                "note": "This endpoint uses parameterized queries to prevent SQL injection"
            }
        else:
            return {
                "status": "error",
                "message": "Invalid credentials",
                "note": "This endpoint uses parameterized queries to prevent SQL injection"
            }

    except ValueError as e:
        # Input validation errors
        return {
            "status": "error",
            "message": f"Input validation error: {str(e)}",
            "note": "Ensure input types and lengths are within allowed limits"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Database error: {str(e)}",
            "note": "An unexpected error occurred"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
