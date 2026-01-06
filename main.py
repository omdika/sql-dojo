import bcrypt
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
    Secure login: use parameterized queries to prevent SQL injection and handle
    legacy plaintext passwords by re-hashing them with bcrypt on successful authentication.

    This replacement fixes the SQL injection at the original implementation by:
    1) Using a parameterized query to fetch the user by username only.
    2) Verifying the provided password against a stored bcrypt hash when present.
    3) If the stored password is plaintext (legacy), compare directly and on success
       re-hash the password with bcrypt and update the database (migration on-auth).
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Parameterized query to fetch user by username only (prevents SQL injection)
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return None

        user_id, user_name, stored_password = row
        password_bytes = password.encode("utf-8")

        authenticated = False

        # Determine whether stored_password is a bcrypt hash (starts with $2b$/$2a$/$2y$)
        try:
            if isinstance(stored_password, bytes):
                stored_str = stored_password.decode("utf-8", errors="ignore")
            else:
                stored_str = stored_password

            if stored_str.startswith("$2b$") or stored_str.startswith("$2a$") or stored_str.startswith("$2y$"):
                # Verify bcrypt hash
                authenticated = bcrypt.checkpw(password_bytes, stored_str.encode("utf-8"))
            else:
                # Legacy plaintext password: compare directly and migrate to bcrypt on success
                if stored_str == password:
                    authenticated = True
                    # Re-hash and store the password using bcrypt (migration on successful auth)
                    new_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")
                    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_hash, user_id))
                    conn.commit()
        except Exception:
            # On any error during hash verification/migration, do not authenticate
            authenticated = False

        conn.close()

        if authenticated:
            # Return the same user shape as before (id, username, password) so callers remain compatible
            return (user_id, user_name, stored_password)
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

