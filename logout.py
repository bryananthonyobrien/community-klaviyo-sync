from datetime import datetime
import traceback
import redis
from flask import jsonify, request, session, current_app as app
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required
from logs import app_logger
from cache import get_redis_client
from admin import remove_expired_tokens
import json

def logout_function():
    try:
        app_logger.debug("Logout route called")
        app_logger.debug(f"Request headers: {dict(request.headers)}")

        # Ensure we have a valid JWT before extracting details
        jwt_data = get_jwt()
        if not jwt_data:
            app_logger.warning("JWT missing required claims")
            return jsonify({"msg": "Token is missing or invalid"}), 401

        username = get_jwt_identity()
        jwt_token = request.headers.get('Authorization').split()[1]
        access_jti = jwt_data.get('jti')
        role = jwt_data.get('role')

        if not access_jti or not username or not role:
            app_logger.warning("Missing JWT details")
            return jsonify({"msg": "Invalid token"}), 401

        app_logger.debug(f"User logging out: {username} with role: {role}")

        redis_client = get_redis_client()

        # ✅ Define Redis keys
        user_key = f"user:{username}"
        revoked_tokens_key = f"revoked_tokens:{username}"
        issued_tokens_key = f"issued_tokens:{username}"

        expires_at = (datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']).strftime('%Y-%m-%d %H:%M:%S')

        # ✅ Retrieve all issued tokens
        issued_tokens = redis_client.smembers(issued_tokens_key)
        revoked_count = 0  # Track number of revoked tokens

        for token_json in issued_tokens:
            try:
                token_data = json.loads(token_json)  # Decode JSON object
                token_jti = token_data.get("jti")

                # ✅ Move token to revoked list
                redis_client.sadd(revoked_tokens_key, json.dumps(token_data))
                redis_client.srem(issued_tokens_key, token_json)
                revoked_count += 1
                app_logger.info(f"🚨 Revoked and removed token with JTI {token_jti} for {username}")

            except json.JSONDecodeError:
                app_logger.error(f"❌ Failed to decode JSON token in {issued_tokens_key}")

        # ✅ If no active tokens remain, delete `issued_tokens:{username}`
        if not redis_client.smembers(issued_tokens_key):
            redis_client.delete(issued_tokens_key)
            app_logger.info(f"✅ Cleared {issued_tokens_key} as no active tokens remain.")

        # ✅ Debugging: Confirm tokens moved to revoked list
        revoked_tokens = redis_client.smembers(revoked_tokens_key)
        app_logger.debug(f"🚨 Revoked tokens for {username}: {revoked_tokens}")

        # ✅ Clear the user's session
        session.clear()
        app_logger.debug("✅ Cleared session data.")

        # ✅ Update user status in Redis (log out status)
        redis_client.hset(user_key, "is_logged_in_now", 0)

        # ✅ Cleanup expired tokens
        remove_expired_tokens()

        app_logger.info(f"✅ User {username} logged out successfully. {revoked_count} tokens revoked.")
        return jsonify({"msg": "Successfully logged out"}), 200

    except redis.RedisError as e:
        app_logger.error(f"❌ Redis error during logout: {str(e)}")
        return jsonify({"error": "Redis error. Please try again later."}), 500
    except Exception as e:
        app_logger.error(f"❌ Error during logout: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500
