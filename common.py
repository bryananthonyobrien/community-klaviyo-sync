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
    
from jwt import decode, ExpiredSignatureError, InvalidSignatureError, DecodeError

def decode_jwt(token, secret_key, allow_expired=True):

    if not isinstance(token, str):
        app_logger.error(f"Token is not a string: {token}")
        raise TypeError("Expected a string value for token")

    if not isinstance(secret_key, str):
        app_logger.error(f"Secret key is not a string: {secret_key}")
        raise TypeError("Expected a string value for secret key")

    try:
        options = {"verify_exp": not allow_expired}  # Disable expiration check when allow_expired=True
        app_logger.debug(f"Decoding with options: {options}")

        payload = decode(token, secret_key, algorithms=["HS256"], options=options)
        app_logger.debug(f"Decoded token payload: {payload}")  # Debug print full decoded payload
        return payload

    except ExpiredSignatureError as e:
        app_logger.warning(f"Token has expired: {e}")
        if allow_expired:
            try:
                payload = decode(token, secret_key, algorithms=["HS256"], options={"verify_exp": False})
                app_logger.debug(f"Decoded expired token payload: {payload}")
                return payload
            except Exception as nested_error:
                app_logger.error(f"Error decoding expired token: {nested_error}")
                return None
        else:
            return None  # Return None instead of raising if you want to prevent crashes

    except InvalidSignatureError as e:
        app_logger.error(f"Invalid JWT signature: {e}")
        return None

    except DecodeError as e:
        app_logger.error(f"Error decoding JWT token: {e}")
        return None

    except Exception as e:
        app_logger.error(f"Unexpected error decoding JWT: {e}")
        return None

def revoke_all_access_tokens_for_user(username, secret, redis_client=None):
    try:
        if redis_client is None:
            redis_client = get_redis_client()

        issued_tokens_key = f"issued_tokens:{username}"
        revoked_tokens_key = f"revoked_tokens:{username}"

        tokens = redis_client.smembers(issued_tokens_key)
        app_logger.info(f"📡 Raw issued tokens set for {username}: {tokens}")  # Debugging

        if not tokens:
            app_logger.info(f"🔍 No issued access tokens found for user {username}.")
            return []

        decoded_tokens = []
        for token in tokens:
            try:
                token_str = token.decode("utf-8")  # ✅ Decode from bytes
                app_logger.info(f"📜 Decoded raw token string: {token_str}")  # Debugging
                decoded_tokens.append(json.loads(token_str))  # ✅ Convert to dictionary
            except json.JSONDecodeError:
                app_logger.error(f"🚨 Failed to decode token for {username}: {token_str}")

        total_tokens = len(decoded_tokens)
        revoked_count = 0
        remaining_refresh_tokens = []

        for token_data in decoded_tokens:
            try:
                jwt_token = token_data.get("jwt")
                expires_at = token_data.get("expires_at")
                token_username = token_data.get("username")

                if token_username != username:
                    continue

                decoded_jwt = decode_jwt(jwt_token, secret, allow_expired=True)
                app_logger.info(f"🔑 Decoded JWT: {decoded_jwt}")  # Debugging

                if decoded_jwt.get("type") == "access":
                    redis_client.sadd(revoked_tokens_key, json.dumps(token_data))

                    json_token_data = json.dumps(token_data)  # Ensure exact format
                    if redis_client.sismember(issued_tokens_key, json_token_data):
                        redis_client.srem(issued_tokens_key, json_token_data)  # ✅ Exact match required
                        app_logger.info(f"🚨 Removed token {json_token_data} from {issued_tokens_key}")
                    else:
                        app_logger.warning(f"⚠️ Token {json_token_data} was NOT found in {issued_tokens_key}!")

                    revoked_count += 1
                else:
                    remaining_refresh_tokens.append(token_data)

            except Exception as e:
                app_logger.error(f"🚨 Error processing token {token_data} for user {username}: {str(e)}")

        app_logger.info(f"🟢 Processed {total_tokens} issued tokens for user {username}.")
        app_logger.info(f"🛑 Revoked {revoked_count} access tokens for user {username}.")
        app_logger.info(f"🔄 Remaining refresh tokens: {len(remaining_refresh_tokens)} for user {username}.")

        return remaining_refresh_tokens

    except Exception as e:
        app_logger.error(f"❌ Error revoking access tokens for user {username}: {str(e)}")
        raise e  

def add_revoked_token_function(jti, username, jwt, expires_at, redis_client=None):
    try:
        if redis_client is None:
            redis_client = get_redis_client()

        # Define the per-user key for revoked tokens in Redis
        revoked_tokens_key = f"revoked_tokens:{username}"  # Per-user revoked tokens key

        # Ensure 'expires_at' is a string (ISO format) if it's a datetime object
        if isinstance(expires_at, datetime.datetime):
            expires_at = expires_at.isoformat()  # Convert datetime to string

        # 1️⃣ Clean up expired tokens before adding a new one
        existing_tokens = redis_client.smembers(revoked_tokens_key)
        now = datetime.datetime.utcnow()

        for token_data in existing_tokens:
            try:
                token_json = json.loads(token_data.decode('utf-8'))
                token_expiry = datetime.datetime.fromisoformat(token_json["expires_at"])

                # If the token is expired, remove it from Redis
                if token_expiry < now:
                    redis_client.srem(revoked_tokens_key, token_data)
                    app_logger.debug(f"🗑️ Removed expired revoked token {token_json['jti']} for {username}")

            except Exception as e:
                app_logger.warning(f"⚠️ Skipping invalid token data in revoked set: {e}")

        # 2️⃣ Prepare the token data as a dictionary or JSON object
        token_data = {
            "jti": jti,
            "username": username,  # Keep username for tracking
            "jwt": jwt,
            "expires_at": expires_at
        }

        # 3️⃣ Store the revoked token in Redis using the per-user set
        redis_client.sadd(revoked_tokens_key, json.dumps(token_data))  # Store as a set member

        app_logger.debug(f"🚫 Successfully added revoked token: {jti} for user {username} with expiry {expires_at} to per-user Redis set.")

    except Exception as e:
        app_logger.error(f"❌ Error adding revoked token: {jti} for user {username} in Redis: {str(e)}")
        raise e

      
def add_issued_token_function(jti, username, jwt, expires_at, token_type, redis_client=None):
    try:
        if redis_client is None:
            redis_client = get_redis_client()

        # Define the per-user key for issued tokens in Redis
        issued_tokens_key = f"issued_tokens:{username}"  # Per-user issued tokens key

        # Prepare the token data as a dictionary or JSON object
        token_data = {
            "jti": jti,
            "username": username,  # Keep username for tracking
            "jwt": jwt,
            "expires_at": expires_at,  # Already a string from isoformat()
            "type": token_type
        }

        # Store the issued token in Redis using the per-user set
        redis_client.sadd(issued_tokens_key, json.dumps(token_data))  # Store as a set member

        app_logger.debug(f"Successfully added issued {token_type} token: {jti} for user {username} with expiry {expires_at} to Redis set.")

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