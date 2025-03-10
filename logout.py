from datetime import datetime
import traceback
import redis
from flask import jsonify, request, session, current_app as app
from flask_jwt_extended import get_jwt, get_jwt_identity
from logs import app_logger
from cache import get_redis_client
from admin import remove_expired_tokens, revoke_all_tokens_for_user

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

        redis_client = get_redis_client()

        # ✅ Revoke all access and refresh tokens
        revoke_all_tokens_for_user(username)

        # ✅ Move the current access token to the revoked list
        revoked_tokens_key = f"revoked_tokens:{username}"
        expires_at = (datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']).strftime('%Y-%m-%d %H:%M:%S')

        redis_client.sadd(revoked_tokens_key, json.dumps({
            "jti": access_jti,
            "username": username,
            "jwt": jwt_token,
            "expires_at": expires_at
        }))

        app_logger.debug(f"🚫 Revoked access token for user {username}.")

        # ✅ Clear the user's session
        session.clear()
        app_logger.debug("✅ Cleared session data")

        # ✅ Update user status in Redis (log out status)
        redis_client.hset(username, "is_logged_in_now", 0)

        # ✅ Cleanup expired tokens
        remove_expired_tokens()

        app_logger.debug(f"✅ User {username} logged out successfully")
        return jsonify({"msg": "Successfully logged out"}), 200

    except redis.RedisError as e:
        app_logger.error(f"Redis error during logout: {str(e)}")
        return jsonify({"error": "Redis error. Please try again later."}), 500
    except Exception as e:
        app_logger.error(f"Error during logout: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500
