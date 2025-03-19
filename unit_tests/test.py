import pytest
import sys
import redis
import json
import logging
import time
import requests
from datetime import datetime
from flask_jwt_extended import create_access_token, decode_token
from admin import add_user, remove_user, user_exists  # ✅ Import user_exists
from cache import get_redis_client
from app import app  # Ensure this is imported at the top
import subprocess
import os

ADMIN_SCRIPT_PATH = "/app/admin.py"  # Define the full path

def set_user_limits(username, daily, hourly, minute):
    """Automates setting user limits using admin.py from /app."""
    try:
        result = subprocess.run(
            ["python", ADMIN_SCRIPT_PATH, "--set-limits", username, str(daily), str(hourly), str(minute)],
            capture_output=True,
            text=True
        )
        logger.info(f"Admin.py Output:\n{result.stdout}")
        if result.stderr:
            logger.error(f"Admin.py Error:\n{result.stderr}")

        assert result.returncode == 0, "Setting limits via admin.py failed."
    except Exception as e:
        logger.error(f"🚨 Error executing admin.py --set-limits: {str(e)}")
        raise

# Constants
BASE_URL = "http://host.docker.internal:5001"
LOGIN_URL = f"{BASE_URL}/login"
LOGOUT_URL = f"{BASE_URL}/logout"
TEST_USERNAME = "test_user"
TEST_PASSWORD = "TestPassword123!"
TEST_ROLE = "client"

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def manual_continue():
    """Pause execution and wait for user input before continuing."""
    # input("🔍 Inspect Redis now. Press Enter to continue and flush the database...")
    return

@pytest.fixture(scope="function")
def redis_client():
    """Fixture to provide a Redis client for testing."""
    return get_redis_client()

@pytest.fixture(scope="function", autouse=True)
def reset_test_environment(redis_client):
    """Flush Redis before each test to ensure a clean state."""
    logger.info("🧹 Flushing Redis to reset test environment...")
    manual_continue()
    redis_client.flushdb()
    logger.info(f"🚀 Creating test user: {TEST_USERNAME}")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    yield

# ✅ 1. Test Successful Login
def test_successful_login():
    logger.info("Test 1: Successful login")

    response = requests.post(
        LOGIN_URL,
        json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
    )

    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
    data = response.json()
    
    assert "access_token" in data, "Access token missing in response"
    assert "refresh_token" in data, "Refresh token missing in response"

    logger.info(f"✅ Login successful, access token received.")

# ✅ 2. Test Successful Logout (User Exists)
def test_logout_success(redis_client):
    logger.info("Test 2: Logout success when user exists")

    # ✅ Ensure the test user exists before starting the test
    if not user_exists(TEST_USERNAME):  # ✅ Using `user_exists()`
        add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    assert user_exists(TEST_USERNAME), "Test user should exist but does not"

    # ✅ Authenticate the user to get an access token
    login_response = requests.post(
        LOGIN_URL,
        json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
    )

    assert login_response.status_code == 200, "Login failed"
    tokens = login_response.json()
    access_token = tokens.get("access_token")

    assert access_token, "Access token missing in response"

    # ✅ Perform Logout Request
    logout_response = requests.post(
        LOGOUT_URL,
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert logout_response.status_code == 200, "Logout failed"
    assert logout_response.json()["msg"] == "Successfully logged out"

    # ✅ Check if the token was revoked
    revoked_tokens = redis_client.smembers(f"revoked_tokens:{TEST_USERNAME}")
    assert revoked_tokens, "Access token was not revoked"

    logger.info(f"✅ Logout successful, revoked tokens: {len(revoked_tokens)}")

# ✅ 3. Test Logout When User Does Not Exist
def test_logout_user_not_found(redis_client):
    logger.info("Test 3: Logout failure when user does not exist")

    # 🧹 Ensure the test user does NOT exist
    if user_exists(TEST_USERNAME):
        remove_user(TEST_USERNAME)

    assert not user_exists(TEST_USERNAME), "Test user should NOT exist"

    # ✅ Generate an access token for a non-existent user inside the Flask app context

    with app.app_context():  # ✅ Wrap in app_context
        access_token = create_access_token(identity=TEST_USERNAME)

    # ✅ Perform Logout Request
    logout_response = requests.post(
        LOGOUT_URL,
        headers={"Authorization": f"Bearer {access_token}"}
    )

    # ✅ Expecting a 401 Unauthorized because the user does not exist
    assert logout_response.status_code == 401, "Logout should fail for a non-existent user"
    assert "Invalid token" in logout_response.json()["msg"]

    logger.info("✅ Logout correctly failed for non-existent user")

# ✅ 4. Test Logout Removes Token from Issued Tokens and Invalidates `test_token`
def test_logout_removes_token_and_invalidates(redis_client):
    logger.info("Test 4: Logout removes token from issued set and test_token fails")

    # ✅ Ensure the test user exists before starting the test
    if not user_exists(TEST_USERNAME):
        add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    assert user_exists(TEST_USERNAME), "Test user should exist but does not"

    issued_tokens_key = f"issued_tokens:{TEST_USERNAME}"
    revoked_tokens_key = f"revoked_tokens:{TEST_USERNAME}"

    # ✅ Step 1: Login and get an access token
    login_response = requests.post(
        LOGIN_URL,
        json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
    )

    assert login_response.status_code == 200, "Login failed"
    tokens = login_response.json()
    access_token = tokens.get("access_token")

    assert access_token, "Access token missing in response"
    logger.info("✅ Step 1: Login and get an access token")

    try:
        with app.app_context():  # Ensure we're inside an application context
            decoded_payload = decode_token(access_token)
    
        logger.info(f"🔍 Decoded token payload: {decoded_payload}")
        token_jti = decoded_payload.get("jti")

        assert token_jti, "Token JTI is missing from decoded token."
    except Exception as e:
        logger.error(f"🚨 Failed to decode token {access_token}: {str(e)}")
        raise

    # ✅ Step 2: Verify issued tokens in Redis AFTER login
    issued_tokens_after_login = redis_client.smembers(issued_tokens_key)
    logger.info("After issued_tokens_after_login")
    issued_tokens_after_login_decoded = {token.decode("utf-8") for token in issued_tokens_after_login}  # 🔹 Decode bytes

    logger.info(f"🔍 Issued tokens in Redis AFTER login (raw bytes): {issued_tokens_after_login}")
    logger.info(f"🔍 Issued tokens in Redis AFTER login (decoded JSON): {issued_tokens_after_login_decoded}")

    assert redis_client.exists(issued_tokens_key), f"❌ Redis key {issued_tokens_key} should exist after login!"
    logger.info(f"✅ Redis key {issued_tokens_key} exists after login.")

    assert issued_tokens_after_login, "❌ Issued tokens should not be empty after login!"

    found_in_issued = any(
        json.loads(token).get("jti") == token_jti for token in issued_tokens_after_login_decoded
    )

    assert found_in_issued, f"Access token {token_jti} should exist in issued_tokens before logout"
    logger.info(f"✅ Access token {token_jti} found in {issued_tokens_key} before logout.")

    # ✅ Step 3: Logout
    logout_response = requests.post(
        LOGOUT_URL,
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert logout_response.status_code == 200, "Logout failed"
    assert logout_response.json()["msg"] == "Successfully logged out"
    logger.info("✅ Step 3: Logout successful")

    # ✅ Step 4: Verify issued tokens AFTER logout
    issued_tokens_after_logout = redis_client.smembers(issued_tokens_key)
    issued_tokens_after_logout_decoded = {token.decode("utf-8") for token in issued_tokens_after_logout}  # 🔹 Decode bytes

    found_in_issued_after_logout = any(
        json.loads(token).get("jti") == token_jti for token in issued_tokens_after_logout_decoded
    )

    assert not found_in_issued_after_logout, f"❌ Access token {token_jti} should be removed from issued_tokens after logout"
    logger.info(f"✅ Access token {token_jti} removed from {issued_tokens_key} after logout.")

    # ✅ Step 5: Verify ALL tokens are removed from `issued_tokens`
    assert not issued_tokens_after_logout, "❌ Issued tokens should be empty after logout!"
    
    # ✅ Step 6: Verify token is moved to revoked_tokens
    revoked_tokens_after_logout = redis_client.smembers(revoked_tokens_key)
    revoked_tokens_after_logout_decoded = {token.decode("utf-8") for token in revoked_tokens_after_logout}  # 🔹 Decode bytes

    found_in_revoked = any(
        json.loads(token)["jwt"] == access_token for token in revoked_tokens_after_logout_decoded
    )

    assert found_in_revoked, f"❌ Access token {token_jti} should exist in revoked_tokens after logout"
    logger.info(f"✅ Access token {token_jti} correctly moved to {revoked_tokens_key} after logout.")

    # ✅ Step 7: Ensure `issued_tokens` key is deleted if empty
    assert not redis_client.exists(issued_tokens_key), f"❌ {issued_tokens_key} should not exist after logout."
    logger.info(f"✅ {issued_tokens_key} deleted after logout.")

    logger.info(f"✅ Test 4: Logout fully validated.")


# ✅ 5. Test Setting and Enforcing Dynamic Rate Limits on `/test-token`
def test_dynamic_rate_limiting(redis_client):
    logger.info("Test 5: Setting and enforcing dynamic rate limits on `/test-token`")

    # ✅ Ensure the test user exists
    if not user_exists(TEST_USERNAME):
        add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    assert user_exists(TEST_USERNAME), "Test user should exist but does not"
    
    manual_continue()

    # ✅ Set custom rate limits for the test user
    limits_key = f"{TEST_USERNAME}:limits"
    custom_limits = {
        "daily_limit": "5",   # Max 5 requests per day
        "hourly_limit": "3",  # Max 3 requests per hour
        "minute_limit": "2"   # Max 2 requests per minute
    }
    for field, value in custom_limits.items():
        redis_client.hset(limits_key, field, value)

    logger.info(f"✅ Custom rate limits set for {TEST_USERNAME}: {custom_limits}")
    manual_continue()

    # ✅ Authenticate to get an access token
    login_response = requests.post(
        LOGIN_URL,
        json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
    )
    assert login_response.status_code == 200, "Login failed"
    access_token = login_response.json().get("access_token")
    assert access_token, "Access token missing in response"

    headers = {"Authorization": f"Bearer {access_token}"}

    # ✅ Send allowed requests within the rate limits
    for i in range(2):  # Should succeed (2 per minute limit)
        response = requests.get(f"{BASE_URL}/test-token", headers=headers)
        assert response.status_code == 200, f"Unexpected status code on attempt {i+1}: {response.status_code}"

    logger.info("✅ Rate limit is correctly allowing valid requests.")

    # ✅ Send a request that should exceed the minute limit
    response = requests.get(f"{BASE_URL}/test-token", headers=headers)
    assert response.status_code == 429, "Rate limit should have been exceeded but was not."
    logger.info("✅ Rate limiting enforced successfully.")

   
    # ✅ Step 5: Increase limits using admin.py
    logger.info("✅ Automatically increasing limits using admin.py...")
    set_user_limits(TEST_USERNAME, daily=10, hourly=5, minute=3)
    logger.info("✅ Limits updated successfully.")
 
    # ✅ Step 6: Fetch new limits (validate that they changed)
    updated_limits = redis_client.hgetall(limits_key)
    updated_limits = {key.decode("utf-8"): value.decode("utf-8") for key, value in updated_limits.items()}
    logger.info(f"🔍 Updated rate limits from Redis: {updated_limits}")

    # ✅ Step 7: Send a request that should now succeed after limit increase
    response = requests.get(f"{BASE_URL}/test-token", headers=headers)
    assert response.status_code == 200, "Request should now succeed after increasing rate limit!"

    logger.info("✅ Successfully verified new rate limits after admin update.")

    manual_continue()  # 🔍 Pause for final inspection

def test_multiple_logins_token_behavior(redis_client):
    logger.info("Test: Multiple logins token behavior")

    # ✅ Step 1: First login
    login_response_1 = requests.post(
        LOGIN_URL,
        json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
    )
    assert login_response_1.status_code == 200, "First login failed"
    tokens_1 = login_response_1.json()
    access_token_1 = tokens_1.get("access_token")
    refresh_token_1 = tokens_1.get("refresh_token")
    assert access_token_1 and refresh_token_1, "First access or refresh token missing"

    logger.info(f"✅ First login successful - Access Token 1: {access_token_1}")

    # ✅ Step 2: Call `/test-token` with first access token
    headers_1 = {"Authorization": f"Bearer {access_token_1}"}
    test_response_1 = requests.get(f"{BASE_URL}/test-token", headers=headers_1)
    assert test_response_1.status_code == 200, "First access token should be valid"

    logger.info("✅ First access token successfully used in /test-token")

    # ✅ Step 3: Wait a few seconds
    time.sleep(3)

    # ✅ Step 4: Second login
    login_response_2 = requests.post(
        LOGIN_URL,
        json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
    )
    assert login_response_2.status_code == 200, "Second login failed"
    tokens_2 = login_response_2.json()
    access_token_2 = tokens_2.get("access_token")
    refresh_token_2 = tokens_2.get("refresh_token")
    assert access_token_2 and refresh_token_2, "Second access or refresh token missing"

    logger.info(f"✅ Second login successful - Access Token 2: {access_token_2}")

    # ✅ Step 5: Compare tokens
    assert access_token_1 != access_token_2, "Access tokens should not be the same"
    assert refresh_token_1 == refresh_token_2, "Refresh tokens should remain the same"

    logger.info("✅ New access token generated, but refresh token remains the same")

    # ✅ Step 6: Call `/test-token` with first access token (should fail)
    test_response_1_after = requests.get(f"{BASE_URL}/test-token", headers=headers_1)
    assert test_response_1_after.status_code == 401, "First access token should be invalid after second login"

    logger.info("✅ First access token correctly invalidated after second login")

    # ✅ Step 7: Call `/test-token` with second access token (should succeed)
    headers_2 = {"Authorization": f"Bearer {access_token_2}"}
    test_response_2 = requests.get(f"{BASE_URL}/test-token", headers=headers_2)
    assert test_response_2.status_code == 200, "Second access token should be valid"

    logger.info("✅ Second access token successfully used in /test-token")

# ✅ 15. Test Expired Token Should Fail
from datetime import timedelta

def test_expired_token(redis_client):
    logger.info("Test: Expired token should fail")

    # ✅ Step 1: Generate an expired token
    with app.app_context():
        expired_token = create_access_token(identity=TEST_USERNAME, expires_delta=timedelta(seconds=-1))  # Immediate expiration

    headers = {"Authorization": f"Bearer {expired_token}"}

    # ✅ Step 2: Call `/test-token` with expired token
    response = requests.get(f"{BASE_URL}/test-token", headers=headers)

    # ✅ Step 3: Ensure the response is 401 with the correct message
    assert response.status_code == 401, f"Expected 401, got {response.status_code}"
    assert response.json().get("msg") == "Token has expired", f"Expected message 'Token has expired', got {response.json().get('msg')}"

    logger.info("✅ Expired token correctly rejected with 401 EXPIRED")

# ✅ 16. Test Tampered Token Should Fail
def test_tampered_token(redis_client):
    logger.info("Test: Tampered token should fail")
    
    # ✅ Step 1: Generate a valid token
    with app.app_context():
        valid_token = create_access_token(identity=TEST_USERNAME)
    
    # ✅ Step 2: Tamper with the token (e.g., change a character)
    tampered_token = valid_token[:-1] + 'X'  # Modify the last character of the token
    
    headers = {"Authorization": f"Bearer {tampered_token}"}
    
    # ✅ Step 3: Call `/test-token` with the tampered token
    response = requests.get(f"{BASE_URL}/test-token", headers=headers)
    
    # ✅ Step 4: Ensure the response is 401 with the "INVALID" status
    assert response.status_code == 401, f"Expected 401, got {response.status_code}"
    assert response.json()['status'] == 'INVALID', f"Expected INVALID, got {response.json()['status']}"


def test_revoked_token_count_logging(redis_client):
    logger.info("Test: Revoked token count logging should update after revocation")

    # ✅ Step 1: Generate a valid token
    with app.app_context():
        valid_token = create_access_token(identity=TEST_USERNAME)

    # ✅ Step 2: Revoke the token (simulating token revocation)
    with app.app_context():
        jwt_data = decode_token(valid_token)  # Decode to get token data
        username = jwt_data.get("sub")  # Extract username from the decoded token
        jti = jwt_data.get("jti")  # Get the unique token identifier

        revoked_tokens_key = f"revoked_tokens:{username}"
        redis_client.sadd(revoked_tokens_key, jti)  # Add the token to revoked tokens set

    # ✅ Step 3: Check the revoked token count in Redis
    revoked_count = redis_client.scard(f"revoked_tokens:{TEST_USERNAME}")

    # ✅ Step 4: Ensure the count has increased by 1 after revocation
    assert revoked_count == 1, f"Expected revoked token count to be 1, but got {revoked_count}"

    logger.info("✅ Revoked token count updated successfully.")

# ✅ 17. Test: Continuous Token Validation for 2 Minutes with 10-second Intervals (Handles Token Expiration)
def test_continuous_token_validation(redis_client):
    logger.info("Test 17: Continuous token validation with login retry loop")

    # ✅ Outer Loop: Login Retry with User Prompt
    while True:
        # Step 1: Attempt login
        login_response = requests.post(
            LOGIN_URL,
            json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        )

        if login_response.status_code == 200:
            # Successful login, get the access token and refresh token
            tokens = login_response.json()
            access_token = tokens.get("access_token")
            refresh_token = tokens.get("refresh_token")
            assert access_token, "Access token missing in response"
            assert refresh_token, "Refresh token missing in response"
            logger.info("✅ Step 1: Login successful and access token received.")
            
            # Once logged in, prepare headers for token validation
            headers = {"Authorization": f"Bearer {access_token}"}

            # ✅ Step 2: Inner Loop - Test /test-token every 10 seconds
            while True:
                # Call /test-token to validate the access token
                response = requests.get(f"{BASE_URL}/test-token", headers=headers)

                # Log response details
                if response.status_code == 200:
                    logger.info(f"✅ Token validation success at {time.ctime()}: {response.json()}")
                elif response.status_code == 401 and response.json().get("msg") == "Token has expired":
                    logger.error(f"🚨 Error during token validation at {time.ctime()} - Status: 401, Message: {response.json()}")
                    
                    # Step 3: Token expired, call /refresh to get a new token
                    logger.info("❌ Token expired. Calling /refresh to get a new token...")
                    refresh_response = requests.post(
                        f"{BASE_URL}/refresh", 
                        headers={"Authorization": f"Bearer {refresh_token}"}
                    )

                    if refresh_response.status_code == 200:
                        # New tokens received
                        new_tokens = refresh_response.json()
                        access_token = new_tokens.get("access_token")
                        refresh_token = new_tokens.get("refresh_token")
                        assert access_token, "New access token missing after refresh"
                        logger.info(f"✅ New access token received: {access_token[:10]}...")

                        # Update headers with the new access token
                        headers = {"Authorization": f"Bearer {access_token}"}
                    else:
                        logger.error("🚨 Refresh failed. Exiting the test.")
                        break  # Exit the loop if refresh fails

                else:
                    logger.error(f"🚨 Error during token validation at {time.ctime()} - Status: {response.status_code}, Message: {response.json()}")
                    # Exit the loop if token validation fails for reasons other than expiration
                    logger.info("❌ Exiting test due to token validation failure.")
                    break  # Exit the loop and terminate the test

                # Wait for 10 seconds before the next call
                logger.info("Waiting 10 seconds before next token validation...")
                time.sleep(10)

        else:
            # If login fails, ask whether the user wants to retry
            logger.error(f"Login failed with status code {login_response.status_code}.")
            retry_login = input("Login failed. Do you want to retry login? (yes/no): ").strip().lower()
            if retry_login != "yes":
                logger.info("❌ User chose not to retry login. Test terminated.")
                return  # Terminate the test if the user chooses not to retry

            # If failed, wait 10 seconds before retrying login
            logger.info("Waiting 10 seconds before retrying login...")
            time.sleep(10)


 