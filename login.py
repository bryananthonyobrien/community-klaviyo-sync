import datetime
import sqlite3
import traceback
from flask import jsonify, request, session
from werkzeug.security import check_password_hash
from logs import app_logger
from common import get_db_connection, DEFAULT_DAILY_LIMIT, DEFAULT_HOURLY_LIMIT, DEFAULT_MINUTE_LIMIT
from credits import create_tokens
from cache import get_user_data  # Import get_user_data from cache

def user_exists(username):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            return result is not None
    except Exception as e:
        app_logger.error(f"Error checking if user exists: {str(e)}")
        return False

def login_function(secret, access_expires, refresh_expires):
    app_logger.debug("/login")
    try:
        if not request.is_json:
            app_logger.error("Missing JSON in request")
            return jsonify({"msg": "Missing JSON in request"}), 400

        username = request.json.get('username', None)

        if not username:
            app_logger.error("Username is missing in request")
            return jsonify({"msg": "Username is missing in request"}), 400

        if not user_exists(username):
            app_logger.error(f"User {username} does not exist")
            return jsonify({"msg": "User does not exist"}), 404

        password = request.json.get('password', None)

        if not password:
            app_logger.error("Password is missing in request")
            return jsonify({"msg": "Password is missing in request"}), 422

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password, login_attempts, last_login_attempt, role, credits, user_status, is_logged_in_now FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()

            if result is None:
                app_logger.error(f"User {username} does not exist")
                return jsonify({"msg": "User does not exist"}), 404

            hashed_password, login_attempts, last_login_attempt, role, credits, user_status, is_logged_in_now = result
            app_logger.debug(f"User {username} has role: {role}")

            login_attempts = int(login_attempts)

            if user_status == 'suspended':
                return jsonify({"msg": "User account is suspended"}), 403

            if login_attempts >= 3:
                if last_login_attempt and datetime.datetime.utcnow() - datetime.datetime.fromisoformat(last_login_attempt) < datetime.timedelta(seconds=60):
                    return jsonify({"msg": "Too many login attempts, please wait"}), 429
                else:
                    cursor.execute("UPDATE users SET login_attempts = 0 WHERE username = ?", (username,))
                    conn.commit()

            if not check_password_hash(hashed_password, password):
                cursor.execute("""
                    UPDATE users
                    SET login_attempts = login_attempts + 1,
                        last_login_attempt = ?
                    WHERE username = ?
                """, (datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), username))
                conn.commit()
                app_logger.debug(f"Incorrect password for user {username}")
                return jsonify({"msg": "Bad username or password"}), 401

            app_logger.debug(f"Login of {username} looks good")

            cursor.execute("""
                UPDATE users
                SET login_attempts = 0,
                    is_logged_in_now = 1,
                    last_login_attempt = ?
                WHERE username = ?
            """, (datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), username))
            conn.commit()

            cursor.execute("SELECT daily_limit, hourly_limit, minute_limit FROM limits WHERE user_id = ?", (username,))
            limits_result = cursor.fetchone()
            if limits_result:
                daily_limit, hourly_limit, minute_limit = limits_result
            else:
                daily_limit = DEFAULT_DAILY_LIMIT
                hourly_limit = DEFAULT_HOURLY_LIMIT
                minute_limit = DEFAULT_MINUTE_LIMIT

            # Fetch user data from the cache
            user_data, cache_status = get_user_data(username)

        access_token, refresh_token = create_tokens(username, role, daily_limit, hourly_limit, minute_limit, str(secret), access_expires, refresh_expires, check_existing_refresh=True)

        session['username'] = username
        session['role'] = role

        response_data = {
            "credits": user_data['credits'],
            "role": role,
            "user_status": user_data.get('user_status', 'active'),  # Include user status
            "cache_status": cache_status,
            "service_count": user_data.get('api_calls', 0),
            "access_token": access_token,
            "refresh_token": refresh_token
        }

        # Log the response data
        app_logger.debug(f"Login success for user {username}: {response_data}")

        return jsonify(response_data), 200

    except sqlite3.OperationalError as e:
        app_logger.error(f"Database error during login: {str(e)}")
        return jsonify({"error": "Database error. Please try again later."}), 500
    except Exception as e:
        app_logger.error(f"Error during login: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500
