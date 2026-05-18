"""
tests/test_auth.py
───────────────────
Integration tests for authentication endpoints.
Uses pytest-asyncio and httpx AsyncClient with SQLite in-memory DB.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from backend.app.main import app
from backend.app.db.init_db import create_tables, drop_tables


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Create fresh tables before each test, drop after."""
    await create_tables()
    yield
    await drop_tables()


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_register_success():
    """Test successful user registration."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "test@smartfuzz.io",
                "username": "testuser",
                "password": "SecurePass1",
                "full_name": "Test User",
            },
        )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@smartfuzz.io"
    assert data["username"] == "testuser"
    assert "id" in data
    assert "hashed_password" not in data  # Never expose hash


@pytest.mark.anyio
async def test_register_duplicate_email():
    """Test that duplicate email returns 409."""
    payload = {
        "email": "dupe@smartfuzz.io",
        "username": "user1",
        "password": "SecurePass1",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post("/api/v1/auth/register", json=payload)
        payload["username"] = "user2"
        response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 409


@pytest.mark.anyio
async def test_login_success():
    """Test login returns valid JWT tokens."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "login@test.io",
                "username": "loginuser",
                "password": "SecurePass1",
            },
        )
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "login@test.io", "password": "SecurePass1"},
        )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.anyio
async def test_login_wrong_password():
    """Test wrong password returns 401."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "wp@test.io",
                "username": "wpuser",
                "password": "SecurePass1",
            },
        )
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "wp@test.io", "password": "WrongPassword99"},
        )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_get_me_authenticated():
    """Test /auth/me returns user profile with valid token."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "me@test.io",
                "username": "meuser",
                "password": "SecurePass1",
            },
        )
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "me@test.io", "password": "SecurePass1"},
        )
        token = login.json()["access_token"]
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    assert response.json()["email"] == "me@test.io"


@pytest.mark.anyio
async def test_get_me_unauthenticated():
    """Test /auth/me returns 401 without token."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401
