from fastapi import FastAPI, HTTPException
import sqlite3
import os
import hashlib
import hmac
import binascii

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
    SECURE LOGIN FUNCTION - Parameterized queries and password hash verification

    This implementation avoids SQL injection by using parameterized queries and
    verifies passwords using a PBKDF2-based hash format. For backward compatibility
    a constant-time comparison against plaintext-stored passwords is performed as
    a transitional fallback (migrate existing plaintext passwords to the hashed
    format as soon as possible).
    """

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        # Parameterized query to avoid SQL injection
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return None

        stored_password = user[2]

        # Support hashed password format: "pbkdf2$<iterations>$<salt_hex>$<hash_hex>"
        if isinstance(stored_password, str) and stored_password.startswith("pbkdf2$"):
            try:
                parts = stored_password.split("$")
                iterations = int(parts[1])
                salt = binascii.unhexlify(parts[2])
                stored_key = binascii.unhexlify(parts[3])
                derived_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
                if hmac.compare_digest(derived_key, stored_key):
                    return user
                else:
                    return None
            except Exception:
                # If hash parsing/verifying fails, treat as authentication failure
                return None
        else:
            # Transitional plaintext fallback (constant-time compare)
            try:
                if hmac.compare_digest(password.encode(), str(stored_password).encode()):
                    return user
                else:
                    return None
            except Exception:
                return None

    except Exception as e:
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

