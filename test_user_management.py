import pytest
import redis
import json
import logging
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash
from admin import (
    add_user, remove_user, user_exists, change_password, 
    revoke_all_tokens_for_user, list_tokens, suspend_user, 
    unsuspend_user, change_user_credits_in_admin, 
    get_redis_client, remove_user_transactions
)

# Constants for testing
TEST_USERNAME = "test_user"
TEST_PASSWORD = "TestPassword123!"
TEST_ROLE = "client"
TEST_CREDITS = 10

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

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

# 1. Test Adding a User
def test_add_user(redis_client):
    logger.info("Test 1: Adding a user to Redis.")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    assert user_exists(TEST_USERNAME) is True

    user_data = redis_client.hgetall(TEST_USERNAME)
    assert user_data is not None
    assert user_data[b'role'].decode('utf-8') == TEST_ROLE
    assert user_data[b'user_status'].decode('utf-8') == "active"
    assert int(user_data[b'credits']) == 10

# 2. Test Removing a User
def test_remove_user(redis_client):
    logger.info("Test 2: Removing a user from Redis.")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    assert user_exists(TEST_USERNAME) is True

    remove_user(TEST_USERNAME)

    assert user_exists(TEST_USERNAME) is False
    assert redis_client.exists(TEST_USERNAME) == 0

def test_invalid_password_length():
    logger.info("Test 3: Attempting to add a user with an invalid password length.")
    
    with pytest.raises(ValueError, match="Password must be at least 8 characters long."):
        add_user(TEST_USERNAME, "short")  # Should raise ValueError

def test_add_duplicate_user(redis_client):
    logger.info("Test 4: Adding a duplicate user.")
    
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    with pytest.raises(ValueError, match=f"User {TEST_USERNAME} already exists."):
        add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)  # Should raise ValueError

# 5. Test Changing Password
def test_change_password(redis_client):
    logger.info("Test 5: Changing a user's password.")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    new_password = "NewSecurePass123!"
    change_password(TEST_USERNAME, new_password)

    user_data = redis_client.hgetall(TEST_USERNAME)
    stored_password_hash = user_data[b'password'].decode('utf-8')
    assert check_password_hash(stored_password_hash, new_password)

# 6. Test Revoking Tokens for Non-Existent User
def test_revoke_tokens_non_existent_user(redis_client):
    logger.info("Test 6: Revoking tokens for a non-existent user.")
    revoke_all_tokens_for_user("non_existent_user")

# 7. Test Revoking Malformed Tokens
def test_revoke_malformed_tokens(redis_client):
    logger.info("Test 7: Revoking malformed tokens.")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    issued_tokens_key = f"issued_tokens:{TEST_USERNAME}"
    redis_client.sadd(issued_tokens_key, "bad_token_data")

    revoke_all_tokens_for_user(TEST_USERNAME)

    assert redis_client.scard(issued_tokens_key) == 0

def test_revoke_expired_token(redis_client):
    logger.info("Test 8: Handling expired tokens.")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    issued_tokens_key = f"issued_tokens:{TEST_USERNAME}"
    revoked_tokens_key = f"revoked_tokens:{TEST_USERNAME}"

    expired_token_data = json.dumps({
        "jwt": "fake_token",
        "expires_at": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
        "type": "access"
    })

    redis_client.sadd(issued_tokens_key, expired_token_data)

    # Log issued & revoked tokens before revocation
    logger.info(f"Issued tokens BEFORE revocation: {redis_client.smembers(issued_tokens_key)}")
    logger.info(f"Revoked tokens BEFORE revocation: {redis_client.smembers(revoked_tokens_key)}")

    revoke_all_tokens_for_user(TEST_USERNAME)

    # Log issued & revoked tokens after revocation
    logger.info(f"Issued tokens AFTER revocation: {redis_client.smembers(issued_tokens_key)}")
    logger.info(f"Revoked tokens AFTER revocation: {redis_client.smembers(revoked_tokens_key)}")

    # Ensure expired token is removed but NOT moved to revoked_tokens
    assert redis_client.scard(issued_tokens_key) == 0, "Issued token set should be empty"
    assert redis_client.scard(revoked_tokens_key) == 0, "Revoked token set should be empty for expired tokens"

# 9. Test Suspending and Unsuspending Users
def test_suspend_unsuspend_user(redis_client):
    logger.info("Test 9: Suspending and unsuspending a user.")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    suspend_user(TEST_USERNAME)
    assert redis_client.hget(TEST_USERNAME, "user_status").decode('utf-8') == "suspended"

    unsuspend_user(TEST_USERNAME)
    assert redis_client.hget(TEST_USERNAME, "user_status").decode('utf-8') == "active"

# 10. Test Adding Negative Credits
def test_negative_credit_change(redis_client):
    logger.info("Test 10: Preventing negative credit assignment.")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    result = change_user_credits_in_admin(TEST_USERNAME, 50, "remove")
    assert "Cannot remove" in result

# 11. Test Removing More Credits Than Available
def test_remove_more_credits_than_available(redis_client):
    logger.info("Test 11: Ensuring credit balance does not go negative.")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    result = change_user_credits_in_admin(TEST_USERNAME, 20, "remove")
    assert "Cannot remove" in result

# 12. Test User Deletion with Active Tokens
def test_remove_user_with_tokens(redis_client):
    logger.info("Test 12: Deleting a user with active tokens.")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    issued_tokens_key = f"issued_tokens:{TEST_USERNAME}"

    token_data = json.dumps({
        "jwt": "fake_token",
        "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
        "type": "access"
    })

    redis_client.sadd(issued_tokens_key, token_data)

    remove_user(TEST_USERNAME)

    assert redis_client.exists(issued_tokens_key) == 0

# 13. Test User Deletion with Transactions
def test_remove_user_with_transactions(redis_client):
    logger.info("Test 13: Removing a user with transactions.")
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    transactions_key = f"{TEST_USERNAME}:credit_changes"

    redis_client.lpush(transactions_key, json.dumps({"amount": 10, "source": "admin"}))

    remove_user(TEST_USERNAME)

    assert redis_client.exists(transactions_key) == 0

# 14. Test Listing Transactions for a User with No Transactions
def test_list_transactions_no_transactions(redis_client):
    logger.info("Test 14: Listing transactions for a user with no transactions.")
    
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    transactions_key = f"{TEST_USERNAME}:credit_changes"

    transactions = redis_client.lrange(transactions_key, 0, -1)

    logger.info(f"Transactions in Redis for {TEST_USERNAME}: {transactions}")
    
    # Instead of expecting 0, expect exactly 1 initial transaction
    assert len(transactions) == 1, f"Expected 1 initial transaction, but found {len(transactions)}"
