# Remediation: Fix SQL injection by using parameterized queries and PBKDF2 password hashing.
# Purpose: parameterize the username lookup to eliminate SQL injection and verify/migrate stored passwords to a secure PBKDF2-HMAC-SHA256 format.
from fastapi import FastAPI, HTTPException
import sqlite3
import os
import hashlib
import binascii
import secrets

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
    SECURE LOGIN FUNCTION - Parameterized query + password hashing verification

    This function prevents SQL injection by using parameterized queries and
    verifies passwords using PBKDF2-HMAC-SHA256. It also supports migrating
    existing plaintext passwords to the hashed format on successful authentication.

    Stored hash format used for migration/verification:
        pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Parameterized query to prevent SQL injection: select user by username only
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return None

        user_id, user_name, stored_password = row

        # Ensure stored_password is a str
        if isinstance(stored_password, bytes):
            stored_password = stored_password.decode("utf-8")

        # If stored password uses the pbkdf2_sha256 format, verify it
        if stored_password and stored_password.startswith("pbkdf2_sha256$"):
            try:
                parts = stored_password.split("$")
                # expected: ["pbkdf2_sha256", iterations, salt_hex, hash_hex]
                iterations = int(parts[1])
                salt_hex = parts[2]
                stored_hash_hex = parts[3]

                salt_bytes = binascii.unhexlify(salt_hex)
                dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
                calc_hash_hex = binascii.hexlify(dk).decode("utf-8")

                if secrets.compare_digest(calc_hash_hex, stored_hash_hex):
                    conn.close()
                    # Return a tuple compatible with existing callers (id, username, ...)
                    return (user_id, user_name)
                else:
                    conn.close()
                    return None
            except Exception:
                conn.close()
                return None
        else:
            # Stored as plaintext (legacy). Compare in constant time and migrate to hashed form if successful.
            if stored_password is not None and secrets.compare_digest(stored_password, password):
                # Migrate password: hash with PBKDF2-HMAC-SHA256
                iterations = 100_000
                salt_bytes = secrets.token_bytes(16)
                salt_hex = binascii.hexlify(salt_bytes).decode("utf-8")
                dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
                hash_hex = binascii.hexlify(dk).decode("utf-8")
                hashed_value = f"pbkdf2_sha256${iterations}${salt_hex}${hash_hex}"

                try:
                    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_value, user_id))
                    conn.commit()
                except Exception:
                    # If migration fails for any reason, do not block authentication but do not leak details
                    pass

                conn.close()
                return (user_id, user_name)
            else:
                conn.close()
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

