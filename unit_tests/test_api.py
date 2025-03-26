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


# ✅ 17. Test: Continuous Token Validation for 2 Minutes with 10-second Intervals (Handles Token Expiration)
def test_continuous_token_validation(redis_client):
    logger.info("Test 17: Continuous token validation with login retry loop")
    refresh_failed = False

    # ✅ Outer Loop: Login Retry with User Prompt
    while not refresh_failed:
        # Step 1: Attempt login
        headers = {'Content-Type': 'application/json'}  # Add Content-Type header here
        login_response = requests.post(
            LOGIN_URL,
            json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
            headers=headers  # Include headers here
        )

        if login_response.status_code == 200:
            # Successful login, get the access token and refresh token
            tokens = login_response.json()
            access_token = tokens.get("access_token")
            refresh_token = tokens.get("refresh_token")
            assert access_token, "Access token missing in response"
            assert refresh_token, "Refresh token missing in response"
            logger.info(f"access_token : {access_token}")
            logger.info(f"refresh_token : {refresh_token}")
            logger.info(f"✅ Step 1: Login successful and access token received.")
            
            # Once logged in, prepare headers for token validation
            headers = {"Authorization": f"Bearer {access_token}"}  # Include Content-Type here

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
                    logger.info(f"❌ Token expired. Calling /refresh to get a new token ...")
                    logger.info(f"[refresh token : {refresh_token}]")

                    headers = {"Authorization": f"Bearer {refresh_token}"}  # Include Content-Type here
                    # Log the headers before sending the request
                    logger.info(f"Sending refresh request with headers: {headers}")

                    refresh_response = requests.post(f"{BASE_URL}/refresh", headers=headers)

                    if refresh_response.status_code == 200:
                        # New tokens received
                        new_tokens = refresh_response.json()
                        access_token = new_tokens.get("access_token")
                        refresh_token = new_tokens.get("refresh_token")
                        assert access_token, "New access token missing after refresh"
                        logger.info(f"access_token : {access_token}")
                        logger.info(f"refresh_token : {refresh_token}")

                        # Update headers with the new access token
                        headers = {"Authorization": f"Bearer {access_token}"}  # Update headers with new access token
                    else:
                        logger.error(f"🚨 Refresh failed. Exiting the test. [response : {refresh_response.json()}]")
                        refresh_failed = True
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



 