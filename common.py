import os
import sqlite3
import time
from flask_jwt_extended import create_access_token
from jwt import decode, ExpiredSignatureError
from logs import app_logger

DATABASE_PATH = os.getenv('DATABASE_PATH', 'tokens.db')
DEFAULT_DAILY_LIMIT = int(os.getenv('DEFAULT_DAILY_LIMIT', 200))
DEFAULT_HOURLY_LIMIT = int(os.getenv('DEFAULT_HOURLY_LIMIT', 50))
DEFAULT_MINUTE_LIMIT = int(os.getenv('DEFAULT_MINUTE_LIMIT', 10))

def is_token_revoked(jti):
    try:
        with get_db_connection() as conn:
            # app_logger.debug("Entering with block in is_token_revoked")
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM revoked_tokens WHERE jti = ? AND expires_at > datetime('now')", (jti,))
            result = cursor.fetchone()
            # app_logger.debug("Exiting with block in is_token_revoked")
            return result is not None
    except sqlite3.OperationalError as e:
        app_logger.error(f"OperationalError in is_token_revoked: {str(e)}")
        if 'no such table' in str(e):
            app_logger.error(f"Missing table detected: {str(e)}")
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

def revoke_all_access_tokens_for_user(username, secret, conn=None):
    app_logger.debug(f"Revoking all access tokens for {username}")
    try:
        if conn is None:
            conn = get_db_connection()
            new_conn = True
        else:
            new_conn = False

        cursor = conn.cursor()
        cursor.execute("SELECT jti, jwt, expires_at FROM issued_tokens WHERE username = ?", (username,))
        tokens = cursor.fetchall()

        for (jti, jwt, expires_at) in tokens:
            try:
                decoded_jwt = decode_jwt(jwt, secret, allow_expired=True)
                if decoded_jwt.get('type') == 'access':
                    add_revoked_token_function(jti, username, jwt, expires_at, conn)
                    cursor.execute("DELETE FROM issued_tokens WHERE jti = ?", (jti,))
            except Exception as e:
                app_logger.error(f"Error decoding token {jti} for user {username}: {str(e)}")
                continue

        if new_conn:
            conn.commit()
            conn.close()
            app_logger.debug(f"Revoked all access tokens for user: {username}")

    except Exception as e:
        app_logger.error(f"Error revoking access tokens for user {username}: {str(e)}")
        if new_conn:
            conn.rollback()
            conn.close()
        raise e

def add_revoked_token_function(jti, username, jwt, expires_at, conn=None):
    try:
        if conn is None:
            conn = get_db_connection()
            new_conn = True
        else:
            new_conn = False

        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO revoked_tokens (jti, username, jwt, expires_at) VALUES (?, ?, ?, ?)", (jti, username, jwt, expires_at))
        conn.commit()
        app_logger.debug(f"Successfully added revoked token: {jti} for user {username} with expiry {expires_at}")

        if new_conn:
            conn.close()
            app_logger.debug("Closed database connection in add_revoked_token")
    except Exception as e:
        app_logger.error(f"Error adding revoked token: {jti} for user {username}: {str(e)}")
        raise e

def add_issued_token_function(jti, username, jwt, expires_at, token_type, conn=None):
    try:
        if conn is None:
            conn = get_db_connection()
            new_conn = True
        else:
            new_conn = False

        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO issued_tokens (jti, username, jwt, expires_at, type) VALUES (?, ?, ?, ?, ?)", (jti, username, jwt, expires_at, token_type))
        conn.commit()
        app_logger.debug(f"Successfully added issued {token_type} token: {jti} for user {username} with expiry {expires_at}")

        if new_conn:
            conn.close()
            app_logger.debug("Closed database connection in add_issued_token")
    except Exception as e:
        app_logger.error(f"Error adding issued token: {jti} for user {username}: {str(e)}")
        raise e

def get_db_connection():
    retries = 5
    while retries > 0:
        try:
            conn = sqlite3.connect(DATABASE_PATH, timeout=3)  # Set timeout to 3 seconds
            conn.execute('PRAGMA journal_mode=WAL;')  # Ensure WAL mode is set
            return conn
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                retries -= 1
                time.sleep(1)  # Wait before retrying
            elif "no such table" in str(e):
                print(f"Database missing or corrupted. Re-initializing: {str(e)}")
            else:
                raise
    raise sqlite3.OperationalError("Database is locked or missing, retries exhausted")

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
