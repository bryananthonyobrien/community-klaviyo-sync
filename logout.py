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

        access_jti = get_jwt()['jti']
        username = get_jwt_identity()
        role = get_jwt()['role']
        jwt_token = request.headers.get('Authorization').split()[1]

        app_logger.debug(f"Access token JTI: {access_jti}")
        app_logger.debug(f"User logging out: {username} with role: {role}")

        # Revoke access token
        with get_db_connection() as conn:
            app_logger.debug("Revoke access token")
            add_revoked_token_function(access_jti, username, jwt_token, datetime.datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'], conn)

        # Remove the access token from the issued_tokens table
        with get_db_connection() as conn:
            app_logger.debug("Remove access token from issued_tokens table")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM issued_tokens WHERE jti = ?", (access_jti,))
            conn.commit()

        # Update is_logged_in_now to False
        with get_db_connection() as conn:
            app_logger.debug("Update is_logged_in_now to False")
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET is_logged_in_now = 0 WHERE username = ?", (username,))
            conn.commit()

        app_logger.debug("Clearing session data")
        session.clear()  # Clear the session data

        app_logger.debug(f"User {username} with role {role} logged out successfully")
        return jsonify({"msg": "Successfully logged out"}), 200
    except sqlite3.OperationalError as e:
        app_logger.error(f"Database error during logout: {str(e)}")
        return jsonify({"error": "Database error. Please try again later."}), 500
    except Exception as e:
        app_logger.error(f"Error during logout: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

