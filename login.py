import datetime
import sqlite3
import traceback
from flask import jsonify, request, session
from werkzeug.security import check_password_hash
from logs import app_logger
from common import decode_redis_values, DEFAULT_DAILY_LIMIT, DEFAULT_HOURLY_LIMIT, DEFAULT_MINUTE_LIMIT
from credits import create_tokens
from cache import get_user_data, get_redis_client
import redis
import json

def user_exists(username):
    try:
        redis_client = get_redis_client()
        user_key = f"user:{username}"  # ✅ Use prefixed key

        # Check if the user hash exists by checking the user's hash key
        return redis_client.exists(user_key) > 0  # ✅ Updated key usage

    except redis.RedisError as e:
        logging.error(f"Redis error during user existence check: {e}")
        return False

def login_function(secret, access_expires, refresh_expires):
    app_logger.info("/login")
    try:
        if not request.is_json:
            app_logger.info("Missing JSON in request")
            return jsonify({"msg": "Missing JSON in request"}), 400

        username = request.json.get('username', None)

        if not username:
            app_logger.info("Username is missing in request")
            return jsonify({"msg": "Username is missing in request"}), 400

        # Fetch user data from Redis
        redis_client = get_redis_client()
        user_data_key = f"user:{username}"  # ✅ Use prefixed key

        if not redis_client.exists(user_data_key):
            app_logger.info(f"User {username} does not exist")
            return jsonify({"msg": "User does not exist"}), 404

        # Fetch user data from Redis hash
        user_data = redis_client.hgetall(user_data_key)
        # Decode byte keys and values to strings
        decoded_user_data = {k.decode(): v.decode() for k, v in user_data.items()}

        # Pretty-print the decoded JSON
        app_logger.info(f"Fetched username {username} from Redis: \n{json.dumps(decoded_user_data, indent=4, sort_keys=True)}")

        # Decode all byte string values to proper types
        user_data = decode_redis_values(user_data)

        # Extract user data
        login_attempts = int(user_data.get('login_attempts', 0))
        last_login_attempt = user_data.get('last_login_attempt', None)
        user_status = user_data.get('user_status', 'active')
        is_logged_in_now = int(user_data.get('is_logged_in_now', 0))
        role = user_data.get('role', 'client')
        credits = int(user_data.get('credits', 10))

        if user_status == 'suspended':
            return jsonify({"msg": "User account is suspended"}), 403

        # Check if login attempts exceed the limit and last login attempt time
        if login_attempts >= 3:
            if last_login_attempt and datetime.datetime.utcnow() - datetime.datetime.fromisoformat(last_login_attempt) < datetime.timedelta(seconds=60):
                return jsonify({"msg": "Too many login attempts, please wait"}), 429
            else:
                # Reset login attempts after timeout
                redis_client.hset(user_data_key, 'login_attempts', 0)

        password = request.json.get('password', None)

        if not password:
            app_logger.info("Password is missing in request")
            return jsonify({"msg": "Password is missing in request"}), 422

        # Fetch the hashed password from Redis
        hashed_password = user_data.get('password', None)

        if hashed_password is None:
            app_logger.info(f"Password for user {username} is not set in Redis.")
            return jsonify({"msg": "Password not set for user"}), 500

        # Check password hash
        if not check_password_hash(hashed_password, password):
            # Increment login attempts and set the last login attempt time
            redis_client.hincrby(user_data_key, 'login_attempts', 1)
            redis_client.hset(user_data_key, 'last_login_attempt', datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
            app_logger.info(f"Incorrect password for user {username}")
            return jsonify({"msg": "Bad username or password"}), 401

        # Reset login attempts and mark the user as logged in
        redis_client.hset(user_data_key, 'login_attempts', 0)
        redis_client.hset(user_data_key, 'is_logged_in_now', 1)
        redis_client.hset(user_data_key, 'last_login_attempt', datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))

        # Fetch user limits from Redis or set defaults
        user_limits_key = f"user:{username}:limits"  # ✅ Updated limits key
        if redis_client.exists(user_limits_key):
            daily_limit = int(redis_client.hget(user_limits_key, 'daily_limit'))
            hourly_limit = int(redis_client.hget(user_limits_key, 'hourly_limit'))
            minute_limit = int(redis_client.hget(user_limits_key, 'minute_limit'))
        else:
            daily_limit = DEFAULT_DAILY_LIMIT
            hourly_limit = DEFAULT_HOURLY_LIMIT
            minute_limit = DEFAULT_MINUTE_LIMIT

        # Fetch additional data (e.g., API calls) from the user cache in Redis
        service_count = int(user_data.get('api_calls', 0))

        # Generate tokens
        access_token, refresh_token = create_tokens(username, role, daily_limit, hourly_limit, minute_limit, str(secret), access_expires, refresh_expires, check_existing_refresh=True)

        session['username'] = username
        session['role'] = role

        # Prepare the response data
        response_data = {
            "credits": credits,
            "role": role,
            "user_status": user_status,  # Include user status
            "service_count": service_count,
            "access_token": access_token,
            "refresh_token": refresh_token
        }

        # Log the response data in a pretty format
        app_logger.info(f"Login success for user {username}:\n{json.dumps(response_data, indent=4)}")        
        return jsonify(response_data), 200

    except redis.RedisError as e:
        app_logger.info(f"Redis error during login: {str(e)}")
        return jsonify({"error": "Redis error. Please try again later."}), 500
    except Exception as e:
        app_logger.info(f"Error during login: {str(e)}")
        app_logger.info(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500
