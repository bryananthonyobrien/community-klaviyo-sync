import datetime
import sqlite3
import traceback
from flask import jsonify, request, session, current_app as app
from flask_jwt_extended import get_jwt, get_jwt_identity
from common import get_db_connection, add_revoked_token_function
from logs import app_logger

def logout_function():
    try:
        app_logger.debug("Logout route called")

        # Retrieve token details from JWT
        access_jti = get_jwt()['jti']
        username = get_jwt_identity()
        role = get_jwt()['role']
        jwt_token = request.headers.get('Authorization').split()[1]

        app_logger.debug(f"Access token JTI: {access_jti}")
        app_logger.debug(f"User logging out: {username} with role: {role}")

        # Revoke the access token by adding it to the global revoked tokens set
        revoke_all_access_tokens_for_user(username)  # Revoke any existing tokens (can be handled in the same function)

        # Add the access token to the global revoked tokens set
        add_revoked_token_function(access_jti, username, jwt_token, datetime.datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'], redis_client=get_redis_client())
        app_logger.debug(f"Revoked access token for user {username}.")

        # Clear the user's session
        session.clear()  # Clear the session data
        app_logger.debug("Cleared session data")

        # Update user status in Redis (log out status)
        redis_client = get_redis_client()
        redis_client.hset(username, "is_logged_in_now", 0)  # Set 'is_logged_in_now' to False in Redis
        
        app_logger.debug(f"User {username} with role {role} logged out successfully")
        return jsonify({"msg": "Successfully logged out"}), 200

    except redis.RedisError as e:
        app_logger.error(f"Redis error during logout: {str(e)}")
        return jsonify({"error": "Redis error. Please try again later."}), 500
    except Exception as e:
        app_logger.error(f"Error during logout: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

