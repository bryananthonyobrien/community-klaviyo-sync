import pytest
import redis
import json
import logging
from datetime import datetime, timedelta
from flask import Flask
from flask_jwt_extended import create_access_token, create_refresh_token
from admin import add_user, remove_user, suspend_user
from cache import get_redis_client
import requests  # Using requests to hit localhost:5001 endpoints
from common import decode_jwt


# Constants
BASE_URL = "http://host.docker.internal:5001"
TEST_USERNAME = "test_user"
TEST_PASSWORD = "TestPassword123!"
TEST_ROLE = "client"

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

@pytest.fixture
def app():
    from app import app
    return app

@pytest.fixture(scope="function")
def redis_client():
    """Fixture to provide a Redis client for testing."""
    return get_redis_client()

@pytest.fixture(scope="function", autouse=True)
def cleanup_test_user(redis_client):
    """Ensure the test user is removed before and after each test."""
    if redis_client.exists(TEST_USERNAME):
        remove_user(TEST_USERNAME)
    yield
    if redis_client.exists(TEST_USERNAME):
        remove_user(TEST_USERNAME)

# 1. Test Successful Login
def test_successful_login(redis_client):
    logger.info("Test 1: Successful login")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    
    response = requests.post(f"{BASE_URL}/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data

# 2. Test Login with Wrong Password
def test_invalid_password_login(redis_client):
    logger.info("Test 2: Invalid login (wrong password)")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    
    response = requests.post(f"{BASE_URL}/login", json={"username": TEST_USERNAME, "password": "WrongPassword123"})
    
    assert response.status_code == 401
    assert response.json() == {"msg": "Bad username or password"}

# 3. Test Login for Non-Existent User
def test_non_existent_user_login():
    logger.info("Test 3: Login for non-existent user")
    
    response = requests.post(f"{BASE_URL}/login", json={"username": "fake_user", "password": "Password123!"})
    
    assert response.status_code == 404
    assert response.json() == {"msg": "User does not exist"}

# 4. Test Login for Suspended User
def test_suspended_user_login(redis_client):
    logger.info("Test 4: Suspended user login")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    suspend_user(TEST_USERNAME)

    response = requests.post(f"{BASE_URL}/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})

    assert response.status_code == 403
    assert response.json() == {"msg": "User account is suspended"}

# 5. Test Too Many Login Attempts
def test_too_many_login_attempts(redis_client):
    logger.info("Test 5: Too many login attempts")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    for _ in range(3):
        requests.post(f"{BASE_URL}/login", json={"username": TEST_USERNAME, "password": "WrongPassword123"})

    response = requests.post(f"{BASE_URL}/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})

    assert response.status_code == 429
    assert response.json() == {"msg": "Too many login attempts, please wait"}

# 6. Test Successful Logout
def test_successful_logout(redis_client):
    logger.info("Test 6: Successful logout")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    login_response = requests.post(f"{BASE_URL}/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    assert login_response.status_code == 200

    access_token = login_response.json()["access_token"]

    response = requests.post(f"{BASE_URL}/logout", headers={"Authorization": f"Bearer {access_token}"})

    assert response.status_code == 200
    assert response.json() == {"msg": "Successfully logged out"}

# 7. Test Logout with Expired Token
def test_logout_with_expired_token(redis_client, app):
    logger.info("Test 7: Logout with expired token")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    user_issued_tokens_key = f"issued_tokens:{TEST_USERNAME}"  # Per-user key

    with app.app_context():
        expired_token = create_access_token(identity=TEST_USERNAME, expires_delta=timedelta(seconds=-1))

        # Decode the expired token with expiration check disabled
        payload = decode_jwt(expired_token, app.config["JWT_SECRET_KEY"], allow_expired=True)
        jti = payload.get("jti")

        if jti:
            # Ensure issued_tokens for this user exists in the correct type
            if redis_client.exists(user_issued_tokens_key):
                key_type = redis_client.type(user_issued_tokens_key).decode("utf-8")
                logger.info(f"Redis key type for '{user_issued_tokens_key}': {key_type}")

            # Now safely use hset
            redis_client.sadd(user_issued_tokens_key, json.dumps({"username": TEST_USERNAME}))
        else:
            logger.error("Failed to extract JTI from token")
            assert False, "Failed to extract JTI from expired token"

    headers = {"Authorization": f"Bearer {expired_token}"}
    response = requests.post(f"{BASE_URL}/logout", headers=headers)

    assert response.status_code == 401  # Expecting Unauthorized due to expired token
    assert response.json() == {"msg": "Token has expired and has been logged out"}
 
# 8. Test Logout with Missing Token
def test_logout_without_token():
    logger.info("Test 8: Logout without a token")
    
    response = requests.post(f"{BASE_URL}/logout")

    assert response.status_code == 401
    assert response.json() == {"msg": "Unauthorized"}

# 9. Test Logout with Invalid Token
def test_logout_with_invalid_token():
    logger.info("Test 9: Logout with invalid token")

    invalid_token = "Bearer this.is.not.a.valid.token"

    response = requests.post(f"{BASE_URL}/logout", headers={"Authorization": invalid_token})

    assert response.status_code == 401
    assert response.json() == {"msg": "Invalid token"}

# 10. Test Logout with Revoked Token
def test_logout_with_revoked_token(redis_client):
    logger.info("Test 10: Logout with revoked token")
    
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    # Step 1: Log in and get a valid token
    login_response = requests.post(f"{BASE_URL}/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Step 2: Log out (revoking the token)
    response = requests.post(f"{BASE_URL}/logout", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert response.json() == {"msg": "Successfully logged out"}

    # Debug: Check revoked tokens in Redis
    revoked_tokens_key = f"revoked_tokens:{TEST_USERNAME}"
    revoked_tokens = redis_client.smembers(revoked_tokens_key)
    assert any(access_token in token.decode('utf-8') for token in revoked_tokens), "Token was not revoked properly"

    # Step 3: Try logging out again with the same token (should be revoked)
    response = requests.post(f"{BASE_URL}/logout", headers={"Authorization": f"Bearer {access_token}"})

    # Step 4: Expect 401 Unauthorized for revoked token
    assert response.status_code == 401
    assert response.json() == {"msg": "Token has been revoked"}
