import pytest
import redis
from datetime import datetime
from admin import add_user, user_exists, remove_user, get_redis_client

# Constants for testing
TEST_USERNAME = "test_user"
TEST_PASSWORD = "TestPassword123!"
TEST_ROLE = "client"

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

def test_add_user(redis_client):
    """Test adding a user to Redis."""
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)

    # Verify user exists
    assert user_exists(TEST_USERNAME) is True

    # Fetch user data from Redis
    user_data = redis_client.hgetall(TEST_USERNAME)
    assert user_data is not None
    assert user_data[b'role'].decode('utf-8') == TEST_ROLE
    assert user_data[b'user_status'].decode('utf-8') == "active"
    assert int(user_data[b'credits']) == 10  # Default initial credits

def test_remove_user(redis_client):
    """Test removing a user from Redis."""
    add_user(TEST_USERNAME, TEST_PASSWORD, TEST_ROLE)
    
    # Verify user exists before removal
    assert user_exists(TEST_USERNAME) is True

    remove_user(TEST_USERNAME)

    # Verify user is gone
    assert user_exists(TEST_USERNAME) is False
    assert redis_client.exists(TEST_USERNAME) == 0

