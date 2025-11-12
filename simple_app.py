from fastapi import FastAPI
import sqlite3

app = FastAPI(title="Simple Vulnerable SQL Injection Demo")

# Create database and test data on startup
@app.on_event("startup")
def startup():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'password123')")
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('user1', 'secret456')")
    conn.commit()
    conn.close()

@app.post("/login")
def login(username: str, password: str):
    """
    VULNERABLE LOGIN ENDPOINT - Contains SQL Injection Vulnerability

    ⚠️ WARNING: This code contains intentional SQL injection vulnerabilities
    for educational and testing purposes only. DO NOT use in production.

    Example attack payloads:
    - Username: admin' OR '1'='1' --
    - Username: ' OR 1=1 --
    - Username: admin'; DROP TABLE users; --
    """

    # VULNERABLE CODE: Direct string concatenation - SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return {
                "status": "success",
                "message": "Login successful",
                "user": {
                    "id": user[0],
                    "username": user[1]
                },
                "warning": "⚠️ This endpoint contains SQL injection vulnerability - for educational purposes only"
            }
        else:
            return {
                "status": "error",
                "message": "Invalid credentials",
                "warning": "⚠️ This endpoint contains SQL injection vulnerability - for educational purposes only"
            }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Database error: {str(e)}",
            "warning": "⚠️ This endpoint contains SQL injection vulnerability - for educational purposes only"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)