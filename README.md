# Vulnerable SQL Injection Demo

⚠️ **SECURITY WARNING: This code contains intentional SQL injection vulnerabilities for educational and testing purposes only. DO NOT use this in production environments.**

## Overview

This repository contains demonstration FastAPI applications with intentional SQL injection vulnerabilities in the `/login` endpoint. The purpose is to demonstrate how SQL injection attacks work and to provide a safe environment for security testing and education.

## Application Overview

This repository contains a FastAPI application (`main.py`) with intentional SQL injection vulnerabilities in the `/login` endpoint. The application is designed for security testing and education purposes.

## Features

- FastAPI web application with SQL injection vulnerability
- SQLite database with sample user data
- Single vulnerable `/login` endpoint
- Clear documentation of the security vulnerability

## Installation

#### Option 1: Local Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python main.py
```

3. Access the application at: `http://localhost:8000`

#### Option 2: Docker Installation

1. Build the Docker image:
```bash
docker build -t vulnerable-sql-injection .
```

2. Run the container:
```bash
docker run -p 8000:8000 vulnerable-sql-injection
```

3. Access the application at: `http://localhost:8000`

#### Option 3: Docker Compose (Recommended)

1. Run with Docker Compose:
```bash
docker-compose up
```

2. Access the application at: `http://localhost:8000`

## Vulnerable Endpoint

### POST /login
- **Parameters**: `username`, `password`
- **Vulnerability**: Direct string concatenation in SQL query
- **Example Attack Payloads**:
  - Username: `admin' OR '1'='1' --`
  - Username: `' OR 1=1 --`
  - Username: `admin'; DROP TABLE users; --`

## Testing

### Unit Tests

This repository includes comprehensive unit tests to verify the SQL injection vulnerability and test application functionality.

#### Vulnerability Detection Tests

Run the vulnerability detection tests to verify the current security state:

```bash
# Run vulnerability detection tests
python3 vulnerability_test.py

# Or run with pytest
python3 -m pytest vulnerability_test.py -v
```

**Expected Output (Current Vulnerable State):**
- ✅ `test_valid_login` - PASS (normal functionality)
- ✅ `test_sql_injection_vulnerability` - PASS (vulnerability confirmed)

**After Security Fixes:**
- ✅ `test_valid_login` - PASS (no regression)
- ❌ `test_sql_injection_vulnerability` - FAIL (vulnerability fixed)

#### Comprehensive Test Suite

Run the full test suite for complete testing:

```bash
# Run all tests
python3 -m pytest test_main.py -v

# Run specific test file
python3 test_main.py
```

### Test Files

- `vulnerability_test.py` - Security vulnerability detection tests
- `test_main.py` - Comprehensive test suite
- `TESTING_GUIDE.md` - Detailed testing instructions

## Security Notice

This application is intentionally vulnerable and should only be used for:
- Security education and training
- Penetration testing practice
- Understanding SQL injection attacks
- Learning secure coding practices

**NEVER deploy this code in production or expose it to the internet.**