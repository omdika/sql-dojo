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
    return {"message": "SQL Injection Demo - Visit /login endpoint"}

def vulnerable_login_query(username: str, password: str, db_file=DB_FILE):
    """
    FIXED LOGIN FUNCTION - Parameterized Queries to Prevent SQL Injection

    This function previously demonstrated a SQL injection vulnerability by
    concatenating user input into SQL text. It has been updated to use
    parameterized queries so that user input is passed as parameters and
    cannot change the SQL structure.
    """

    # Use parameterized queries to prevent SQL injection
    query = "SELECT id, username, password FROM users WHERE username = ? AND password = ?"

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        # Pass parameters as a tuple to avoid SQL injection
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        raise e

@app.post("/login")
async def login(username: str, password: str):
    """Login endpoint that uses the parameterized query function"""
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
                "info": "Queries are parameterized to prevent SQL injection"
            }
        else:
            return {
                "status": "error",
                "message": "Invalid credentials",
                "info": "Queries are parameterized to prevent SQL injection"
            }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Database error: {str(e)}",
            "info": "Queries are parameterized to prevent SQL injection"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
