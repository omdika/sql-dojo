from fastapi import FastAPI, HTTPException
import sqlite3
import os

app = FastAPI(title="Secure Login Demo")

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

    # Insert some test users using parameterized queries
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('admin', 'password123'))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('user1', 'secret456'))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('test', 'test789'))

    conn.commit()
    conn.close()

@app.on_event("startup")
async def startup_event():
    init_db()

@app.get("/")
async def root():
    return {"message": "Secure Login Demo - Visit /login endpoint"}

def safe_login_query(username: str, password: str, db_file=DB_FILE):
    """
    SAFE LOGIN FUNCTION - Parameterized query to prevent SQL injection

    This function uses parameterized SQL (SQLite placeholders) instead of
    concatenating user input directly into the SQL string. It also performs
    basic input validation to enforce expected types and reasonable lengths.
    """

    # Basic input validation - enforce types and reasonable length limits
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("username and password must be strings")

    # Enforce maximum lengths to reduce attack surface for unexpected inputs
    if len(username) == 0 or len(username) > 150:
        raise ValueError("username length is invalid")
    if len(password) == 0 or len(password) > 150:
        raise ValueError("password length is invalid")

    # Use a parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        # Bubble up the exception for the caller to handle or log appropriately
        raise e

@app.post("/login")
async def login(username: str, password: str):
    """Login endpoint that uses the safe parameterized query function"""
    try:
        user = safe_login_query(username, password)

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
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        return {
            "status": "error",
            "message": f"Database error: {str(e)}"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
