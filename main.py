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

    # Insert some test users (passwords are stored as salted PBKDF2-HMAC-SHA256 hashes)
    def _hash_pw(pw: str) -> str:
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 100_000)
        return binascii.hexlify(salt).decode() + '$' + binascii.hexlify(dk).decode()

    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('admin', _hash_pw('password123')))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('user1', _hash_pw('secret456')))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('test', _hash_pw('test789')))

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
    SECURE LOGIN FUNCTION - Prevents SQL injection and uses password hash verification.

    This function queries for the user by username using a parameterized query,
    retrieves the stored password hash (salt$hash), and verifies the provided password
    using PBKDF2-HMAC-SHA256. It no longer constructs SQL from unsanitized input.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        # Parameterized query to prevent SQL injection
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        user_id, user_name, stored = row

        # stored format: salt_hex$hash_hex
        try:
            salt_hex, hash_hex = stored.split('$', 1)
            salt = binascii.unhexlify(salt_hex)
            stored_hash = binascii.unhexlify(hash_hex)
        except Exception:
            # Malformed stored password entry
            return None

        # Recompute the hash for the provided password and compare securely
        computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
        if hmac.compare_digest(computed_hash, stored_hash):
            return (user_id, user_name)
        else:
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

