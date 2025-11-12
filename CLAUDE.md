# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **FastAPI Python application** that demonstrates SQL injection vulnerabilities for educational and security testing purposes. The application contains intentional vulnerabilities in the `/login` endpoint to help developers understand and test SQL injection attacks.

## Current State

- **FastAPI web application** with SQL injection vulnerability
- **SQLite database** with test users
- **Single vulnerable endpoint**: `/login`
- **Comprehensive test suite** to verify the vulnerability
- **Security warnings** throughout code and documentation

## Development Commands

### Running the Application
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Running with Docker
```bash
# Build and run with Docker
docker build -t vulnerable-sql-injection .
docker run -p 8000:8000 vulnerable-sql-injection

# Or use Docker Compose (recommended)
docker-compose up
```

### Running Tests
```bash
# Run all tests
python -m pytest test_main.py -v

# Run specific test file
python test_main.py
```

## Architecture

- **FastAPI** web framework
- **SQLite** database for user storage
- **TestClient** for API testing
- **pytest** for unit testing

### Key Files
- `main.py` - FastAPI application with vulnerable login endpoint
- `test_main.py` - Comprehensive test suite for SQL injection vulnerabilities
- `requirements.txt` - Python dependencies
- `README.md` - Security warnings and usage instructions

## Security Testing

The application is designed to demonstrate SQL injection vulnerabilities:
- Direct string concatenation in SQL queries
- No input validation or parameterization
- Multiple test cases for different SQL injection payloads

**⚠️ WARNING**: This code contains intentional vulnerabilities and should only be used for educational purposes in secure environments.