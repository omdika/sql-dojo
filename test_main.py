import pytest
from fastapi.testclient import TestClient
import sqlite3
import os
from main import app, init_db, secure_login_query

# Test client for FastAPI
client = TestClient(app)

# Test database file
TEST_DB_FILE = "test_users.db"

def setup_test_db():
    """Setup a test database"""
    # Remove test database if exists
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)

    # Create test database
    init_db(TEST_DB_FILE)

def teardown_test_db():
    """Cleanup test database"""
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)

def test_root_endpoint():
    """Test the root endpoint returns correct message"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "Secure Login Demo" in data["message"]

def test_valid_login():
    """Test normal login with correct credentials"""
    setup_test_db()
    try:
        response = client.post("/login", params={"username": "admin", "password": "password123"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["message"] == "Login successful"
        assert "user" in data
        assert data["user"]["username"] == "admin"
    finally:
        teardown_test_db()

def test_invalid_login():
    """Test login with incorrect credentials"""
    setup_test_db()
    try:
        response = client.post("/login", params={"username": "admin", "password": "wrongpassword"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"
        assert data["message"] == "Invalid credentials"
    finally:
        teardown_test_db()

def test_sql_injection_bypass_authentication():
    """Ensure SQL injection attempts cannot bypass authentication"""
    setup_test_db()
    try:
        # Classic SQL injection payload
        response = client.post("/login", params={
            "username": "admin' OR '1'='1' --",
            "password": "anything"
        })
        assert response.status_code == 200
        data = response.json()
        # With secure parameterized queries, injection should NOT succeed
        assert data["status"] == "error"
        assert data["message"] == "Invalid credentials"
    finally:
        teardown_test_db()

def test_sql_injection_always_true():
    """Ensure always-true SQL injection attempts fail"""
    setup_test_db()
    try:
        response = client.post("/login", params={
            "username": "' OR 1=1 --",
            "password": "anything"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"
        assert data["message"] == "Invalid credentials"
    finally:
        teardown_test_db()

def test_sql_injection_function_direct():
    """Test that the secure function resists SQL injection directly"""
    setup_test_db()
    try:
        # Test normal login
        user = secure_login_query("admin", "password123", TEST_DB_FILE)
        assert user is not None
        assert user[1] == "admin"

        # Test SQL injection - should not return a user
        user = secure_login_query("admin' OR '1'='1' --", "anything", TEST_DB_FILE)
        assert user is None

        # Test another SQL injection
        user = secure_login_query("' OR 1=1 --", "anything", TEST_DB_FILE)
        assert user is None

    finally:
        teardown_test_db()

def test_multiple_sql_injection_payloads():
    """Test various SQL injection payloads do not authenticate"""
    setup_test_db()
    try:
        payloads = [
            "admin' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "admin' --",
            "x' OR username LIKE '%admin%' --",
        ]

        for payload in payloads:
            response = client.post("/login", params={
                "username": payload,
                "password": "anything"
            })
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "error"
    finally:
        teardown_test_db()

def test_normal_vs_injected_login_comparison():
    """Compare normal login vs SQL injection login - injected should fail"""
    setup_test_db()
    try:
        # Normal login with wrong password
        response_normal = client.post("/login", params={
            "username": "admin",
            "password": "wrongpassword"
        })
        data_normal = response_normal.json()

        # SQL injection login
        response_injected = client.post("/login", params={
            "username": "admin' OR '1'='1' --",
            "password": "wrongpassword"
        })
        data_injected = response_injected.json()

        # Both should fail with secure implementation
        assert data_normal["status"] == "error"
        assert data_injected["status"] == "error"

    finally:
        teardown_test_db()

def test_sql_injection_destructive():
    """Test destructive SQL injection (DROP TABLE) should not be executed"""
    setup_test_db()
    try:
        # First verify the table exists
        conn = sqlite3.connect(TEST_DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        assert cursor.fetchone() is not None  # Table exists
        conn.close()

        # Attempt destructive SQL injection
        response = client.post("/login", params={
            "username": "admin'; DROP TABLE users; --",
            "password": "anything"
        })

        # With parameterized queries, this should not drop the table and authentication should fail
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"

        # Verify table still exists
        conn = sqlite3.connect(TEST_DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        assert cursor.fetchone() is not None
        conn.close()

    finally:
        teardown_test_db()

if __name__ == "__main__":
    # Run tests
    test_root_endpoint()
    test_valid_login()
    test_invalid_login()
    test_sql_injection_bypass_authentication()
    test_sql_injection_always_true()
    test_sql_injection_function_direct()
    test_normal_vs_injected_login_comparison()
    print("\n✅ All tests passed! Secure implementation verified.")
