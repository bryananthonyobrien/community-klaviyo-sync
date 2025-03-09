import os
import sqlite3
import time
from flask_jwt_extended import create_access_token
from jwt import decode, ExpiredSignatureError
from logs import app_logger
from redis import Redis
from redis import exceptions as redis_exceptions
from klaviyo import get_redis_client
import json
import datetime

DEFAULT_DAILY_LIMIT = int(os.getenv('DEFAULT_DAILY_LIMIT', 200))
DEFAULT_HOURLY_LIMIT = int(os.getenv('DEFAULT_HOURLY_LIMIT', 50))
DEFAULT_MINUTE_LIMIT = int(os.getenv('DEFAULT_MINUTE_LIMIT', 10))

def decode_redis_values(user_data):
    """Helper function to decode byte values from Redis into their appropriate types."""
    decoded_data = {}
    for key, value in user_data.items():
        # Decode byte strings to regular strings
        if isinstance(value, bytes):
            decoded_data[key.decode('utf-8')] = value.decode('utf-8')  # Convert byte strings to strings
        else:
            decoded_data[key] = value
    return decoded_data
    
def is_token_revoked(jti):
    try:
        redis_client = get_redis_client()
        revoked_tokens_key = "revoked_tokens"  # The Redis key holding the revoked tokens

        # Check if the 'jti' exists in the Redis set (which stores revoked token 'jti')
        is_revoked = redis_client.sismember(revoked_tokens_key, jti)  # Using set for revoked tokens
        return is_revoked
    except redis.RedisError as e:
        app_logger.error(f"Redis error in is_token_revoked: {str(e)}")
        return False
    except Exception as e:
        app_logger.error(f"Error checking if token is revoked: {str(e)}")
        return False

def decode_jwt(token, secret_key, allow_expired=False):
    app_logger.debug(f"decode_jwt : Secret key used {secret_key}")

    if not isinstance(token, str):
        app_logger.error(f"Token is not a string: {token}")
        raise TypeError("Expected a string value for token")

    if not isinstance(secret_key, str):
        app_logger.error(f"Secret key is not a string: {secret_key}")
        raise TypeError("Expected a string value for secret key")

    try:
        options = {"verify_exp": not allow_expired}
        return decode(token, secret_key, algorithms=["HS256"], options=options)
    except ExpiredSignatureError as e:
        if allow_expired:
            app_logger.warning("Token has expired, but decoding is allowed with expired tokens.")
            return decode(token, secret_key, algorithms=["HS256"], options={"verify_exp": False})
        else:
            app_logger.error("Token has expired and decoding is not allowed.")
            raise e
    except InvalidSignatureError as e:
        app_logger.error("Invalid JWT signature detected.")
        raise e
    except Exception as e:
        app_logger.error(f"Error decoding JWT token: {str(e)}")
        raise
        
def revoke_all_access_tokens_for_user(username, secret, redis_client=None):
    app_logger.debug(f"Revoking all access tokens for {username}")
    try:
        if redis_client is None:
            redis_client = get_redis_client()

        # Global keys for issued and revoked tokens (sets)
        issued_tokens_key = "issued_tokens"
        revoked_tokens_key = "revoked_tokens"

        # Check if the sets are empty, skip if there are no tokens
        tokens = redis_client.smembers(issued_tokens_key)

        if not tokens:
            app_logger.info(f"No tokens found for user {username}.")
            return

        # Iterate over the tokens and revoke the user's access and refresh tokens
        for jti in tokens:
            if not jti:  # Skip empty jti tokens
                app_logger.warning(f"Skipping empty token for user {username}")
                continue

            try:
                # Decode the token data stored in the set (stored as JSON)
                token_data = json.loads(jti.decode('utf-8'))  # Decode byte string to UTF-8 string

                jwt_token = token_data.get('jwt')
                expires_at = token_data.get('expires_at')
                token_username = token_data.get('username')  # Extract the username from the token data

                # Skip if the token doesn't belong to the requested username
                if token_username != username:
                    continue

                # Decode JWT to verify its type and check if it's an access token
                decoded_jwt = decode_jwt(jwt_token, secret, allow_expired=True)

                if decoded_jwt.get('type') == 'access':
                    # Add the token to the global revoked tokens list
                    redis_client.sadd(revoked_tokens_key, jti)  # Adding to global revoked tokens set

                    # Remove the token from the global issued tokens in Redis
                    redis_client.srem(issued_tokens_key, jti)
                    app_logger.debug(f"Revoked and deleted access token {jti} for user {username}")
                else:
                    app_logger.debug(f"Token {jti} for user {username} is not an access token, skipping.")
            except Exception as e:
                app_logger.error(f"Error decoding or processing token {jti} for user {username}: {str(e)}")
                continue

        app_logger.debug(f"Revoked all access tokens for user: {username}")

    except Exception as e:
        app_logger.error(f"Error revoking access tokens for user {username}: {str(e)}")
        raise e  
              
def add_revoked_token_function(jti, username, jwt, expires_at, redis_client=None):
    try:
        if redis_client is None:
            redis_client = get_redis_client()

        # Define the key for the global revoked tokens list in Redis
        revoked_tokens_key = "revoked_tokens"  # Use the global key

        # Ensure 'expires_at' is a string (ISO format) if it's a datetime object
        if isinstance(expires_at, datetime.datetime):
            expires_at = expires_at.isoformat()  # Convert datetime to string

        # Prepare the token data as a dictionary or JSON object
        token_data = {
            "jti": jti,
            "username": username,  # Optionally include the username for tracking
            "jwt": jwt,
            "expires_at": expires_at
        }

        # Store the revoked token in Redis using the global set (sadd) instead of hset
        redis_client.sadd(revoked_tokens_key, json.dumps(token_data))  # Store as a set member

        app_logger.debug(f"Successfully added revoked token: {jti} for user {username} with expiry {expires_at} to global Redis set.")

    except Exception as e:
        app_logger.error(f"Error adding revoked token: {jti} for user {username} in Redis: {str(e)}")
        raise e
        
def add_issued_token_function(jti, username, jwt, expires_at, token_type, redis_client=None):
    try:
        if redis_client is None:
            redis_client = get_redis_client()

        # Define the key for the global issued tokens list in Redis
        issued_tokens_key = "issued_tokens"  # Use the global key

        # Prepare the token data as a dictionary or JSON object
        token_data = {
            "jti": jti,
            "username": username,  # Optionally include the username for tracking
            "jwt": jwt,
            "expires_at": expires_at,  # Already a string from isoformat()
            "type": token_type
        }

        # Store the issued token in Redis using the global set (sadd) instead of hset
        redis_client.sadd(issued_tokens_key, json.dumps(token_data))  # Store as a set member

        app_logger.debug(f"Successfully added issued {token_type} token: {jti} for user {username} with expiry {expires_at} to global Redis set.")

    except Exception as e:
        app_logger.error(f"Error adding issued token: {jti} for user {username} in Redis: {str(e)}")
        raise e
        
def reissue_access_token_with_claims(username, role, credits, daily_limit, hourly_limit, minute_limit):
    additional_claims = {
        "role": role,
        "credits": credits,
        "daily_limit": daily_limit,
        "hourly_limit": hourly_limit,
        "minute_limit": minute_limit
    }
    access_token = create_access_token(identity=username, additional_claims=additional_claims)
    return access_token
