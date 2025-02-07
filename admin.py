import logging
from logging.handlers import RotatingFileHandler
import os

# Set up logging to a file
log_file = os.path.expanduser('~/logs/admin_app.log')

# Use RotatingFileHandler to handle log rotation and prevent stale file handles
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

handler = RotatingFileHandler(log_file, maxBytes=5000000, backupCount=5)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Get the root logger and add the handler
root_logger = logging.getLogger()
root_logger.addHandler(handler)

import sqlite3
import os
import shutil
import json
import jwt  # pyjwt package is needed for decoding JWT
from werkzeug.security import generate_password_hash
import argparse
from datetime import datetime
from dotenv import load_dotenv
import time
import requests
from requests.exceptions import SSLError, RequestException
from redis import Redis, exceptions as redis_exceptions


import sys
sys.path.append('/home/bryananthonyobrien/mysite')
from cache import export_community_payloads_to_json, delete_community_payloads, view_community_payloads, create_stage_csv_files, get_redis_client, initialize_cache, print_cache_contents, remove_user_from_cache, initialize_user_cache, suspend_user_cache, unsuspend_user_cache, update_user_credits_in_cache


# Load environment variables from .env file
dotenv_path = '/home/bryananthonyobrien/mysite/.env'
load_dotenv(dotenv_path)

# Debugging - print out the loaded values
print(f"REDIS_HOST: {os.getenv('REDIS_HOST')}")
print(f"REDIS_PORT: {os.getenv('REDIS_PORT')}")
print(f"REDIS_PASSWORD: {os.getenv('REDIS_PASSWORD')}")

# Example of using them
redis_host = os.getenv('REDIS_HOST')
redis_port = os.getenv('REDIS_PORT')
redis_password = os.getenv('REDIS_PASSWORD')

print(f"Connected to Redis at {redis_host}:{redis_port}")


DATABASE_PATH = os.getenv('DATABASE_PATH', 'tokens.db')
BACKUP_PATH = os.getenv('BACKUP_PATH', 'backup.db')

# Load environment variables from the specified .env file
dotenv_path = '/home/bryananthonyobrien/mysite/.env'
load_dotenv(dotenv_path)

# Get JWT secret key
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
if not JWT_SECRET_KEY:
    raise ValueError("No JWT_SECRET_KEY set for admin script")

PAW_USERNAME = os.getenv('PAW_USERNAME')
PAW_API_TOKEN = os.getenv('PAW_API_TOKEN')

JWT_TOKEN = None
REFRESH_TOKEN = None

PERSIST_CLIENTS_API_URL = "https://www.bryanworx.com/persist-now"
LOGIN_URL = os.getenv('LOGIN_URL', 'https://www.bryanworx.com/login')
REFRESH_URL = os.getenv('REFRESH_URL', 'https://www.bryanworx.com/refresh')
SERVER_RUNNING_URL = os.getenv('SERVER_RUNNING_URL', 'https://www.bryanworx.com/health-check')

DEFAULT_DAILY_LIMIT = int(os.getenv('DEFAULT_DAILY_LIMIT', 200))
DEFAULT_HOURLY_LIMIT = int(os.getenv('DEFAULT_HOURLY_LIMIT', 50))
DEFAULT_MINUTE_LIMIT = int(os.getenv('DEFAULT_MINUTE_LIMIT', 10))

# Globals
token = None

# Redis connection configuration
redis_client = Redis(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    password=os.getenv('REDIS_PASSWORD', None),
    db=int(os.getenv('REDIS_DB', 0))
)

def get_cache_status():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM cache_status ORDER BY last_updated DESC LIMIT 1")
            result = cursor.fetchone()
            if result:
                return result[0]
            return "No cache status found."
    except Exception as e:
        logging.error(f"Error fetching cache status: {str(e)}")
        return "Error fetching cache status."

def is_app_running():
    try:
        response = requests.get(f"{SERVER_RUNNING_URL}", timeout=5)
        if response.status_code == 200:
            return True
    except SSLError:
        print("Server is not running due to SSL certificate issues.")
    except RequestException:
        print("Server is not running.")
    return False

def get_db_connection():
    retries = 10  # Increase retries to 10
    while retries > 0:
        try:
            conn = sqlite3.connect(DATABASE_PATH, timeout=10)  # Increase timeout to 10 seconds
            conn.execute('PRAGMA journal_mode=WAL;')  # Enable WAL mode
            return conn
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                retries -= 1
                time.sleep(1)  # Wait before retrying
            else:
                raise
    raise sqlite3.OperationalError("Database is locked, retries exhausted")

def ensure_database_status_table_exists():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS database_status (
                status TEXT,
                command TEXT,
                start_time DATETIME
            )
        """)
        cursor.execute("INSERT OR IGNORE INTO database_status (status) VALUES ('idle')")
        conn.commit()

def reset_database_status():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE database_status SET status = 'idle', command = NULL, start_time = NULL")
            conn.commit()
            logging.info("Database status reset to idle.")
    except sqlite3.Error as e:
        logging.error(f"Error resetting database status: {e}")

def initialize_tables():
    ensure_database_status_table_exists()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                role TEXT DEFAULT 'client',
                login_attempts INTEGER DEFAULT 0,
                last_login_attempt DATETIME,
                credits INTEGER DEFAULT 10,
                user_status TEXT DEFAULT 'active',
                is_logged_in_now BOOLEAN DEFAULT FALSE,
                created DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                username TEXT,
                jwt TEXT,
                expires_at DATETIME,
                reason TEXT,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS issued_tokens (
                jti TEXT PRIMARY KEY,
                username TEXT,
                jwt TEXT,
                expires_at DATETIME,
                type TEXT,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS limits (
                user_id TEXT PRIMARY KEY,
                daily_limit INTEGER DEFAULT 200,
                hourly_limit INTEGER DEFAULT 50,
                minute_limit INTEGER DEFAULT 10,
                FOREIGN KEY (user_id) REFERENCES users (username)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credit_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                change_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                amount INTEGER,
                source TEXT,
                transaction_id TEXT,
                FOREIGN KEY (user_id) REFERENCES users (username)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache_status (
                id INTEGER PRIMARY KEY,
                status TEXT,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_revoked_tokens_jti ON revoked_tokens (jti);
        """)
        conn.commit()


def log_issued_tokens(conn=None):
    try:
        # Use existing connection if provided, else create a new one
        use_conn = conn if conn else get_db_connection()
        with use_conn:
            cursor = use_conn.cursor()
            cursor.execute("SELECT jti, username, jwt, expires_at FROM issued_tokens")
            tokens = cursor.fetchall()

            # Log the full contents of the issued_tokens table
            logging.info("Full contents of issued_tokens table:")
            for token in tokens:
                logging.info(f"jti: {token[0]}, username: {token[1]}, jwt: {token[2]}, expires_at: {token[3]}")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")

def drop_and_create_tables():
    if not check_and_set_busy('reset_schema'):
        return
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DROP TABLE IF EXISTS users")
            cursor.execute("DROP TABLE IF EXISTS revoked_tokens")
            cursor.execute("DROP TABLE IF EXISTS issued_tokens")
            cursor.execute("DROP TABLE IF EXISTS database_status")
            cursor.execute("DROP TABLE IF EXISTS limits")
            cursor.execute("DROP TABLE IF EXISTS credit_changes")
            cursor.execute("DROP TABLE IF EXISTS cache_status")  # Add this line
            cursor.execute("""
                CREATE TABLE users (
                    username TEXT PRIMARY KEY,
                    password TEXT,
                    role TEXT DEFAULT 'client',
                    login_attempts INTEGER DEFAULT 0,
                    last_login_attempt DATETIME,
                    credits INTEGER DEFAULT 10,
                    user_status TEXT DEFAULT 'active',
                    is_logged_in_now BOOLEAN DEFAULT FALSE,
                    created DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE revoked_tokens (
                    jti TEXT PRIMARY KEY,
                    username TEXT,
                    jwt TEXT,
                    expires_at DATETIME,
                    reason TEXT,
                    FOREIGN KEY (username) REFERENCES users (username)
                )
            """)
            cursor.execute("""
                CREATE TABLE issued_tokens (
                    jti TEXT PRIMARY KEY,
                    username TEXT,
                    jwt TEXT,
                    expires_at DATETIME,
                    type TEXT,
                    FOREIGN KEY (username) REFERENCES users (username)
                )
            """)
            cursor.execute("""
                CREATE TABLE database_status (
                    status TEXT,
                    command TEXT,
                    start_time DATETIME
                )
            """)
            cursor.execute("INSERT INTO database_status (status) VALUES ('idle')")
            cursor.execute(f"""
                CREATE TABLE limits (
                    user_id TEXT PRIMARY KEY,
                    daily_limit INTEGER DEFAULT {DEFAULT_DAILY_LIMIT},
                    hourly_limit INTEGER DEFAULT {DEFAULT_HOURLY_LIMIT},
                    minute_limit INTEGER DEFAULT {DEFAULT_MINUTE_LIMIT},
                    FOREIGN KEY (user_id) REFERENCES users (username)
                )
            """)
            cursor.execute("""
                CREATE TABLE credit_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    change_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    amount INTEGER,
                    source TEXT,
                    transaction_id TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (username)
                )
            """)
            cursor.execute("""
                CREATE TABLE cache_status (
                    id INTEGER PRIMARY KEY,
                    status TEXT,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)  # Add this block
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_revoked_tokens_jti ON revoked_tokens (jti);
            """)
            conn.commit()
            logging.info("Tables 'users', 'revoked_tokens', 'issued_tokens', 'database_status', 'limits', 'credit_changes', and 'cache_status' created successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    set_database_status('idle')

    add_user('admin123', 'admin123', 'admin')

    while not is_app_running():
        print("Waiting for app.py to start running...")
        time.sleep(5)  # Wait for 5 seconds before checking again

    while True:
        action = input("app.py is running. Do you want to (1) login_admin_user and (2) persist_client_data? (Y/N): ")
        if action.lower() == 'y':
            login_admin_user()
            persist_client_data()
            break
        elif action.lower() == 'n':
            print("Skipping login and persist data.")
            break
        else:
            print("Invalid input. Please enter 'Y' or 'N'.")


def set_database_status(status, command=None):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            if status == 'busy':
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute("UPDATE database_status SET status = ?, command = ?, start_time = ?", (status, command, datetime.utcnow()))
                cursor.execute("COMMIT")
            else:
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute("UPDATE database_status SET status = ?, command = NULL, start_time = NULL", (status,))
                cursor.execute("COMMIT")
    except sqlite3.Error as e:
        logging.error(f"Error setting database status: {e}")
        cursor.execute("ROLLBACK")

def get_database_status():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status, command, start_time FROM database_status LIMIT 1")
        result = cursor.fetchone()
        return result if result else ('idle', None, None)

def check_and_set_busy(command):
    status, running_command, start_time = get_database_status()
    if status == 'busy':
        elapsed_time = datetime.utcnow() - datetime.fromisoformat(start_time) if start_time else 'unknown'
        print(f"Database is currently busy with command '{running_command}', running for {elapsed_time}. Please try again later.")
        return False
    set_database_status('busy', command)
    return True

def user_exists(username):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            return cursor.fetchone() is not None
    except sqlite3.Error as e:
        logging.error(f"Database error during user existence check: {e}")
        return False

def add_user(username, password, role='client'):
    if not check_and_set_busy('add_user'):
        return
    if len(password) < 8:
        logging.error("Password must be at least 8 characters long.")
        set_database_status('idle')
        return

    if user_exists(username):
        logging.warning(f"User {username} already exists.")
        set_database_status('idle')
        return

    hashed_password = generate_password_hash(password)
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT,
                    role TEXT DEFAULT 'client',
                    login_attempts INTEGER DEFAULT 0,
                    last_login_attempt DATETIME,
                    credits INTEGER DEFAULT 10,
                    user_status TEXT DEFAULT 'active',
                    is_logged_in_now BOOLEAN DEFAULT FALSE,
                    created DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("INSERT INTO users (username, password, role, credits, user_status) VALUES (?, ?, ?, 10, 'active')", (username, hashed_password, role))

            conn.commit()
            logging.info(f"User {username} added successfully with role {role} and 10 initial credits.")

            # Log the initial credits
            cursor.execute("""
                INSERT INTO credit_changes (user_id, amount, source, transaction_id, change_date)
                VALUES (?, ?, 'initial', '0', ?)
            """, (username, 10, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()

            # Set limits for the new user
            cursor.execute("""
                INSERT OR REPLACE INTO limits (user_id, daily_limit, hourly_limit, minute_limit)
                VALUES (?, ?, ?, ?)
            """, (
                username,
                DEFAULT_DAILY_LIMIT,
                DEFAULT_HOURLY_LIMIT,
                DEFAULT_MINUTE_LIMIT
            ))
            conn.commit()

            # Initialize user cache
            initialize_user_cache(username, 10, 'active')

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    set_database_status('idle')



def secure_user_account():
    if not check_and_set_busy('secure_user_account'):
        return

    username = input("Enter username: ")
    if not user_exists(username):
        logging.warning(f"User {username} does not exist.")
        set_database_status('idle')
        return

    new_password = input("Enter new password: ")
    if len(new_password) < 8:
        logging.error("Password must be at least 8 characters long.")
        set_database_status('idle')
        return

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Step 1: Suspend the user
            cursor.execute("UPDATE users SET user_status = 'suspended' WHERE username = ?", (username,))

            # Step 2: Revoke all tokens
            cursor.execute("""
                INSERT INTO revoked_tokens (jti, username, jwt, expires_at, reason)
                SELECT jti, username, jwt, expires_at, 'admin'
                FROM issued_tokens
                WHERE username = ?
            """, (username,))
            cursor.execute("DELETE FROM issued_tokens WHERE username = ?", (username,))

            # Step 3: Change the password
            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))

            # Step 4: Unsuspend the user
            cursor.execute("UPDATE users SET user_status = 'active' WHERE username = ?", (username,))

            conn.commit()
            logging.info(f"User {username}'s account has been secured successfully.")

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        conn.rollback()
    set_database_status('idle')

def remove_user(username):
    if not check_and_set_busy('remove_user'):
        return
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM revoked_tokens WHERE username = ?", (username,))
            cursor.execute("DELETE FROM issued_tokens WHERE username = ?", (username,))
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            cursor.execute("DELETE FROM limits WHERE user_id = ?", (username,))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info(f"User {username} and their tokens removed successfully.")
                remove_user_from_cache(username)  # Remove user from cache
            else:
                logging.warning(f"User {username} not found.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    set_database_status('idle')

def remove_klaviyo_discoveries(username):
    try:
        redis_client = get_redis_client()  # Get Redis client
        discoveries_key = f"klaviyo_discoveries_{username}"

        # Check if there are any discoveries stored for the user
        if redis_client.exists(discoveries_key):
            redis_client.delete(discoveries_key)
            print(f"All Klaviyo discovery records for user '{username}' have been deleted.")
        else:
            print(f"No Klaviyo discovery records found for user '{username}'.")

    except redis_exceptions.ConnectionError as e:
        print(f"Redis connection error: {str(e)}")
    except Exception as e:
        print(f"Error deleting data from Redis: {str(e)}")

def display_discoveries_records(username):
    discoveries_key = f"klaviyo_discoveries_{username}"

    try:
        redis_client = get_redis_client()
        discoveries = redis_client.hgetall(discoveries_key)

        if not discoveries:
            print(f"No Klaviyo discoveries found for user {username}.")
            return

        # Display header
        print(f"{'Timestamp Started':<25} {'Timestamp Completed':<25} {'Profiles Retrieved':<20} {'Directory Exists':<20}")
        print("-" * 100)

        for key, value in discoveries.items():
            discovery = json.loads(value.decode('utf-8'))
            start_time = discovery.get('start_time', 'N/A')
            end_time = discovery.get('end_time', 'N/A')
            profile_count = discovery.get('profile_count', 'N/A')

            # Retrieve the correct directory path from Redis
            directory_name = discovery.get('file_location', None)

            # Additional logging to debug why directory_name might be None
            # print(f"Discovery record: {discovery}")
            # print(f"Extracted directory_name: {directory_name}")

            # Check if the directory exists
            directory_exists = os.path.exists(directory_name) if directory_name else False

            # Display the record with directory status
            print(f"{start_time:<25} {end_time:<25} {profile_count:<20} {'Yes' if directory_exists else 'No':<20}")

    except redis_exceptions.ConnectionError as e:
        print(f"Redis connection error: {str(e)}")
    except Exception as e:
        print(f"Error retrieving data from Redis: {str(e)}")

def list_users():
    if not check_and_set_busy('list_users'):
        return
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT u.username,
                       (SELECT COUNT(*) FROM issued_tokens WHERE username = u.username) as issued_count,
                       (SELECT COUNT(*) FROM revoked_tokens WHERE username = u.username) as revoked_count,
                       u.role,
                       u.credits,
                       u.user_status,
                       u.login_attempts,
                       u.last_login_attempt,
                       u.is_logged_in_now,
                       u.created
                FROM users u
            """)
            users = cursor.fetchall()
            if users:
                print(f"{'Username':<20} {'Issued Tokens':<15} {'Revoked Tokens':<15} {'Role':<10} {'Credits':<10} {'Status':<10} {'Login Attempts':<15} {'Last Login Attempt':<20} {'Logged In Now':<15} {'Created'}")
                for user in users:
                    username = user[0] if user[0] else ''
                    issued_count = user[1] if user[1] is not None else 0
                    revoked_count = user[2] if user[2] is not None else 0
                    role = user[3] if user[3] else ''
                    credits = user[4] if user[4] is not None else 0
                    status = user[5] if user[5] else ''
                    login_attempts = user[6] if user[6] is not None else 0
                    last_login_attempt = user[7] if user[7] else ''
                    is_logged_in_now = 'False' if user[8] is None or user[8] == 0 else 'True'
                    created = user[9] if user[9] else ''
                    print(f"{username:<20} {issued_count:<15} {revoked_count:<15} {role:<10} {credits:<10} {status:<10} {login_attempts:<15} {last_login_attempt:<20} {is_logged_in_now:<15} {created}")
            else:
                print("No users found.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    set_database_status('idle')

def change_password(username, new_password):
    if not check_and_set_busy('change_password'):
        return
    if len(new_password) < 8:
        logging.error("Password must be at least 8 characters long.")
        set_database_status('idle')
        return

    if not user_exists(username):
        logging.warning(f"User {username} does not exist.")
        set_database_status('idle')
        return

    hashed_password = generate_password_hash(new_password)
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info(f"Password for user {username} updated successfully.")
            else:
                logging.warning(f"Password for user {username} not updated.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    set_database_status('idle')

def backup_database():
    if not check_and_set_busy('backup_database'):
        return
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"backup_{timestamp}.db"
        shutil.copyfile(DATABASE_PATH, backup_filename)
        logging.info(f"Database backed up to {backup_filename}.")
    except Exception as e:
        logging.error(f"Error during database backup: {e}")
    set_database_status('idle')

def restore_database():
    if not check_and_set_busy('restore_database'):
        return
    try:
        backups = sorted([f for f in os.listdir() if f.startswith("backup_") and f.endswith(".db")], reverse=True)

        if not backups:
            print("No backups available to restore.")
            set_database_status('idle')
            return

        print("Available backups:")
        for i, backup in enumerate(backups, 1):
            print(f"{i}. {backup}")

        choice = input("Enter the number of the backup to restore (default is the latest): ")

        if choice.isdigit() and 1 <= int(choice) <= len(backups):
            selected_backup = backups[int(choice) - 1]
        else:
            selected_backup = backups[0]  # Default to the latest backup

        shutil.copyfile(selected_backup, DATABASE_PATH)
        logging.info(f"Database restored from {selected_backup}.")
        result = initialize_cache()

    except Exception as e:
        logging.error(f"Error during database restore: {e}")
    set_database_status('idle')

def format_timestamp(ts):
    if ts is None:
        return 'N/A'
    dt = datetime.utcfromtimestamp(ts)
    return dt.strftime('%A, %B %d, %Y %H:%M:%S UTC')

def list_tokens(username):
    if not check_and_set_busy('list_tokens'):
        return
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT jwt, 'issued' as source FROM issued_tokens WHERE username = ?
                UNION ALL
                SELECT jwt, 'revoked' as source FROM revoked_tokens WHERE username = ?
            """, (username, username))
            tokens = cursor.fetchall()
            if tokens:
                for token in tokens:
                    jwt_token, source = token
                    if jwt_token:
                        try:
                            decoded = jwt.decode(jwt_token.encode(), JWT_SECRET_KEY, algorithms=['HS256'])
                            # Add formatted timestamps as comments in the decoded JSON
                            decoded_with_comments = {
                                "fresh": decoded.get("fresh", False),
                                "iat": decoded.get("iat"),  # Issued At
                                "iat_comment": f"Issued At: {format_timestamp(decoded.get('iat'))}",
                                "jti": decoded.get("jti"),
                                "type": decoded.get("type"),
                                "sub": decoded.get("sub"),
                                "nbf": decoded.get("nbf"),  # Not Before
                                "nbf_comment": f"Not Before: {format_timestamp(decoded.get('nbf'))}",
                                "csrf": decoded.get("csrf"),
                                "exp": decoded.get("exp"),  # Expiration
                                "exp_comment": f"Expiration: {format_timestamp(decoded.get('exp'))}",
                                "role": decoded.get("role"),
                                "credits": decoded.get("credits")  # Add credits
                            }
                            print(f"Token from {source} table:")
                            print(jwt_token)
                            print(json.dumps(decoded_with_comments, indent=4))
                            print("\n" + "-"*40 + "\n")
                        except jwt.ExpiredSignatureError:
                            logging.error("Error decoding token: Signature has expired.")
                            print(f"Token from {source} table:")
                            print(jwt_token)
                            print("Token has expired.")
                            print("\n" + "-"*40 + "\n")
                        except jwt.DecodeError as e:
                            logging.error(f"Error decoding token: {e}")
                            print(f"Token from {source} table:")
                            print(jwt_token)
                            print("Error decoding token.")
                            print("\n" + "-"*40 + "\n")
                    else:
                        logging.warning(f"Found a token for user {username} that is None.")
            else:
                print(f"No tokens found for user {username}.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        set_database_status('idle')

def change_user_role(username, new_role):
    if not check_and_set_busy('change_user_role'):
        return

    if new_role not in ['admin', 'client']:
        logging.error("Invalid role. Must be 'admin' or 'client'.")
        set_database_status('idle')
        return

    if not user_exists(username):
        logging.warning(f"User {username} does not exist.")
        set_database_status('idle')
        return

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, username))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info(f"Role for user {username} updated to {new_role}.")
            else:
                logging.warning(f"Role for user {username} not updated.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    set_database_status('idle')

def log_credit_change(cursor, user_id, amount, source, transaction_id):
    try:
        cursor.execute("""
            INSERT INTO credit_changes (user_id, amount, source, transaction_id, change_date)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, amount, source, transaction_id, datetime.utcnow()))
    except sqlite3.Error as e:
        logging.error(f"Database error logging credit change: {e}")
        raise  # Re-raise the exception to be handled in the calling function

def change_user_credits(username, credits, action):
    logging.info(f"Attempting to {action} {credits} credits for user {username}.")
    if not check_and_set_busy('change_user_credits'):
        return "Operation busy, please try again later."

    if not user_exists(username):
        logging.warning(f"User {username} does not exist.")
        set_database_status('idle')
        return f"User {username} does not exist."

    if action not in ['add', 'remove']:
        logging.error("Invalid action. Must be 'add' or 'remove'.")
        set_database_status('idle')
        return "Invalid action. Must be 'add' or 'remove'."

    log_issued_tokens()

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Fetch current credits
            cursor.execute("SELECT credits FROM users WHERE username = ?", (username,))
            current_credits = cursor.fetchone()[0]
            logging.info(f"Current credits for user {username}: {current_credits}")

            if action == 'add':
                new_credits = current_credits + credits
                cursor.execute("UPDATE users SET credits = ? WHERE username = ?", (new_credits, username))
                log_credit_change(cursor, username, credits, 'admin', '0')
            elif action == 'remove':
                new_credits = current_credits - credits
                if new_credits < 0:
                    logging.error(f"Cannot remove {credits} credits from user {username}. This would result in negative credits.")
                    set_database_status('idle')
                    return f"Cannot remove {credits} credits from user {username}. This would result in negative credits."
                cursor.execute("UPDATE users SET credits = ? WHERE username = ?", (new_credits, username))
                log_credit_change(cursor, username, -credits, 'admin', '0')

            conn.commit()

            # Update the cache
            update_user_credits_in_cache(username, new_credits)

            # Log the updated credits
            logging.info(f"Updated credits for user {username}: {new_credits}")

            if cursor.rowcount > 0:
                logging.info(f"Credits for user {username} updated successfully.")
                return "Success"
            else:
                logging.warning(f"Credits for user {username} not updated.")
                return f"Credits for user {username} not updated."
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        conn.rollback()
        return f"Database error: {e}"
    finally:
        set_database_status('idle')

def get_user_role(username):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            if result:
                return result[0]
            else:
                return None
    except sqlite3.Error as e:
        logging.error(f"Database error during role check: {e}")
        return None

def remove_expired_tokens():
    if not check_and_set_busy('remove_expired_tokens'):
        return
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM issued_tokens WHERE expires_at <= datetime('now')")
            cursor.execute("DELETE FROM revoked_tokens WHERE expires_at <= datetime('now')")
            conn.commit()
            logging.info("Expired tokens removed successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    set_database_status('idle')

def get_clients():
    if not check_and_set_busy('get_clients'):
        return
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM limits")
            clients = cursor.fetchall()
            if clients:
                for client in clients:
                    print(f"User ID: {client[0]}")
                    print(f"Daily Limit: {client[1]}")
                    print(f"Hourly Limit: {client[2]}")
                    print(f"Minute Limit: {client[3]}")
                    print("\n" + "-"*40 + "\n")
            else:
                print("No clients found.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    set_database_status('idle')

def get_limits():
    if not check_and_set_busy('get_limits'):
        return
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, daily_limit, hourly_limit, minute_limit FROM limits")
            limits = cursor.fetchall()
            if limits:
                print(f"{'User ID':<20} {'Daily Limit':<12} {'Hourly Limit':<12} {'Minute Limit':<12}")
                for limit in limits:
                    print(f"{limit[0]:<20} {limit[1]:<12} {limit[2]:<12} {limit[3]:<12}")
            else:
                print("No limits found.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    set_database_status('idle')

def set_limits():
    if not check_and_set_busy('set_limits'):
        return
    try:
        user_id = input("Enter user ID: ")
        daily_limit = int(input("Enter daily limit: "))
        hourly_limit = int(input("Enter hourly limit: "))
        minute_limit = int(input("Enter minute limit: "))

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE limits
                SET daily_limit = ?, hourly_limit = ?, minute_limit = ?
                WHERE user_id = ?
            """, (daily_limit, hourly_limit, minute_limit, user_id))
            conn.commit()

            if cursor.rowcount > 0:
                print(f"Limits for user {user_id} updated successfully.")
                logging.info(f"Limits for user {user_id} updated to Daily: {daily_limit}, Hourly: {hourly_limit}, Minute: {minute_limit}")
            else:
                print(f"User {user_id} not found.")
                logging.warning(f"User {user_id} not found when trying to update limits.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    except ValueError:
        logging.error("Invalid input. Please enter numeric values for limits.")
        print("Invalid input. Please enter numeric values for limits.")
    set_database_status('idle')

def is_token_expired(token):
    try:
        if isinstance(token, str):
            token = token.encode('utf-8')
        payload = jwt.decode(token, options={"verify_signature": False})
        exp = payload.get('exp')
        if exp:
            exp_datetime = datetime.fromtimestamp(exp)
            return exp_datetime < datetime.now()
        return False
    except jwt.ExpiredSignatureError:
        return True
    except Exception as e:
        logging.error(f"Error checking token expiration: {e}")
        return True

def refresh_access_token():
    if not check_server_status():
        logging.error("Server is currently loading client data and is not available.")
        return False

    try:
        response = requests.post(REFRESH_URL, json={'refresh_token': REFRESH_TOKEN})
        if response.status_code == 200:
            new_token = response.json().get('access_token')
            global JWT_TOKEN
            JWT_TOKEN = new_token
            logging.info("Access token refreshed successfully")
            return True
        else:
            logging.error(f"Failed to refresh access token: {response.text}")
            return False
    except Exception as e:
        logging.error(f"Error refreshing access token: {e}")
        return False

def check_server_status():
    try:
        response = requests.get("https://www.bryanworx.com/status")
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "ok":
                return True
        return False
    except requests.RequestException as e:
        logging.error(f"Error checking server status: {str(e)}")
        return False

def persist_client_data():
    if not check_and_set_busy('persist_client_data'):
        return

    if not check_server_status():
        logging.error("Server is currently loading client data and is not available.")
        set_database_status('idle')
        return

    if is_token_expired(JWT_TOKEN):
        logging.info("Access token has expired, refreshing...")
        if not refresh_access_token():
            logging.error("Failed to refresh access token, aborting")
            set_database_status('idle')
            return

    headers = {
        'Authorization': f"Bearer {JWT_TOKEN}"
    }

    # Log the JWT token being used
    logging.debug(f"Using JWT Token: {JWT_TOKEN}")

    try:
        response = requests.post(PERSIST_CLIENTS_API_URL, headers=headers)
        if response.status_code == 200:
            print("Client data persisted successfully.")
        else:
            print(f"Failed to persist client data: {response.text}")
    except Exception as e:
        logging.error(f"Error persisting client data: {e}")
    set_database_status('idle')

def login_admin_user():
    global JWT_TOKEN, REFRESH_TOKEN
    login_url = LOGIN_URL
    login_data = {
        "username": "admin123",
        "password": "admin123"
    }
    response = requests.post(login_url, json=login_data)
    if response.status_code == 200:
        data = response.json()
        JWT_TOKEN = data.get("access_token")
        REFRESH_TOKEN = data.get("refresh_token")
        logging.info("Admin user logged in successfully.")
    else:
        logging.error("Admin user login failed.")
    return response

def suspend_user(username):
    if not check_and_set_busy('suspend_user'):
        return

    if not user_exists(username):
        logging.warning(f"User {username} does not exist.")
        set_database_status('idle')
        return

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET user_status = 'suspended' WHERE username = ?", (username,))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info(f"User {username} suspended successfully.")
                # Update cache
                suspend_user_cache(username)
            else:
                logging.warning(f"User {username} not suspended.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    set_database_status('idle')

def unsuspend_user(username):
    if not check_and_set_busy('unsuspend_user'):
        return

    if not user_exists(username):
        logging.warning(f"User {username} does not exist.")
        set_database_status('idle')
        return

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET user_status = 'active' WHERE username = ?", (username,))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info(f"User {username} unsuspended successfully.")
                # Update cache
                unsuspend_user_cache(username)
            else:
                logging.warning(f"User {username} not unsuspended.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    set_database_status('idle')

def list_user_transactions(username):
    if not check_and_set_busy('list_user_transactions'):
        return

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT change_date, amount, source, transaction_id
                FROM credit_changes
                WHERE user_id = ?
                ORDER BY change_date DESC
            """, (username,))
            transactions = cursor.fetchall()
            if transactions:
                print(f"{'Change Date':<20} {'Amount':>10} {'Source':<40} {'Transaction ID':<15}")
                print("-" * 85)
                for transaction in transactions:
                    try:
                        change_date = datetime.strptime(transaction[0], "%Y-%m-%d %H:%M:%S.%f").strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        change_date = datetime.strptime(transaction[0], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
                    amount = f"{transaction[1]:>10}"  # Right-align the amount, including negative values
                    source = f"{transaction[2]:<40}"  # Left-align the source with more space
                    transaction_id = f"{transaction[3]:<15}"  # Left-align the transaction ID with fixed width
                    print(f"{change_date:<20} {amount} {source} {transaction_id}")
            else:
                print(f"No transactions found for user {username}.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    set_database_status('idle')

def revoke_tokens(username, token_type='all', conn=None, lock=True):
    logging.info(f"Revoking {token_type} tokens for user {username}.")
    if lock and not check_and_set_busy('revoke_tokens'):
        return

    try:
        # Use existing connection if provided, else create a new one
        use_conn = conn if conn else get_db_connection()
        with use_conn:
            cursor = use_conn.cursor()
            cursor.execute("SELECT jwt FROM issued_tokens WHERE username = ?", (username,))
            tokens = cursor.fetchall()

            # Filter tokens based on the decoded 'type' claim
            tokens_to_revoke = []
            for token in tokens:
                jwt_token = token[0]
                try:
                    decoded = jwt.decode(jwt_token.encode(), JWT_SECRET_KEY, algorithms=['HS256'])
                    if token_type == 'all' or decoded.get('type') == token_type:
                        tokens_to_revoke.append((decoded['jti'], username, jwt_token, datetime.fromtimestamp(decoded['exp']), 'admin'))
                except jwt.ExpiredSignatureError:
                    logging.warning(f"Token for user {username} has expired and will not be revoked.")

            # Log the number of tokens found
            num_tokens = len(tokens_to_revoke)
            logging.info(f"Found {num_tokens} {token_type} tokens for user {username} to revoke.")

            for token in tokens_to_revoke:
                cursor.execute("""
                    INSERT INTO revoked_tokens (jti, username, jwt, expires_at, reason)
                    VALUES (?, ?, ?, ?, ?)
                """, token)
                cursor.execute("DELETE FROM issued_tokens WHERE jti = ?", (token[0],))

            use_conn.commit()
            logging.info(f"{num_tokens} tokens for user {username} revoked successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        if lock:
            set_database_status('idle')

def remove_user_transactions(username):
    logging.info(f"Attempting to remove all transactions for user {username}.")
    if not check_and_set_busy('remove_user_transactions'):
        return "Operation could not be started. System is busy."

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Delete all transactions for the user
            cursor.execute("DELETE FROM credit_changes WHERE user_id = ?", (username,))
            conn.commit()

            logging.info(f"All transactions for user {username} have been removed.")

            if cursor.rowcount > 0:
                logging.info(f"Transactions for user {username} removed successfully.")
                return "Success"
            else:
                logging.warning(f"No transactions found for user {username}.")
                return f"No transactions found for user {username}."

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        conn.rollback()
        return f"Database error: {e}"

    finally:
        set_database_status('idle')

def interactive_help():
    actions = [
        "Add User",
        "Reset Schema",
        "Remove User",
        "List Users",
        "Change Password",
        "Backup Database",
        "Restore Database",
        "List Tokens",
        "Change User Role",
        "Change User Credits",
        "Remove Expired Tokens",
        "Get Limits",
        "Set Limits",
        "Persist Client Data",
        "Suspend User",
        "Unsuspend User",
        "List User Transactions",
        "Revoke Tokens",
        "Secure User Account",
        "Initialize Cache",
        "Print Cache Contents",
        "Reset Database Status",
        "Remove User Transactions",
        "Reset Klaviyo Status",
        "Display Klaviyo Status",
        "Display Discoveries Records",
        "Remove Klaviyo Discovery Records",
        "Create Staging Files",
        "View Community Payloads",  # View Redis payloads
        "Delete Community Payloads",  # Delete Redis payloads
        "Export Community Payloads to JSON",  # New action to export payloads
        "Exit"
    ]

    while True:
        print("\nSelect an action:")
        for i, action in enumerate(actions, 1):
            print(f"{i}. {action}")

        try:
            choice = int(input("Enter the number of the action you want to perform: "))
        except ValueError:
            print("Invalid choice. Please enter a number.")
            continue

        if choice == 1:
            username = input("Enter username: ")
            password = input("Enter password: ")
            role = input("Enter role (admin/client) [client]: ") or 'client'
            add_user(username, password, role)
        elif choice == 2:
            drop_and_create_tables()
        elif choice == 3:
            username = input("Enter username to remove: ")
            remove_user(username)
        elif choice == 4:
            list_users()
        elif choice == 5:
            username = input("Enter username: ")
            new_password = input("Enter new password: ")
            change_password(username, new_password)
        elif choice == 6:
            backup_database()
        elif choice == 7:
            restore_database()
        elif choice == 8:
            username = input("Enter username: ")
            list_tokens(username)
        elif choice == 9:
            username = input("Enter username: ")
            new_role = input("Enter new role (admin/client): ")
            change_user_role(username, new_role)
        elif choice == 10:
            username = input("Enter username: ")
            action = input("Do you want to add or remove credits? (add/remove): ").strip().lower()
            if action in ['add', 'remove']:
                try:
                    credits = int(input("Enter number of credits: "))
                    result = change_user_credits(username, credits, action)
                    if result != "Success":
                        print(result)  # Print the error message if there's an error
                except ValueError:
                    print("Invalid number of credits. Please enter an integer.")
            else:
                print("Invalid action. Please enter 'add' or 'remove'.")
        elif choice == 11:
            remove_expired_tokens()
        elif choice == 12:
            get_limits()
        elif choice == 13:
            set_limits()
        elif choice == 14:
            persist_client_data()
        elif choice == 15:
            username = input("Enter username to suspend: ")
            suspend_user(username)
        elif choice == 16:
            username = input("Enter username to unsuspend: ")
            unsuspend_user(username)
        elif choice == 17:
            username = input("Enter username to list transactions: ")
            list_user_transactions(username)
        elif choice == 18:
            username = input("Enter username to revoke tokens: ")
            revoke_tokens(username)
        elif choice == 19:
            secure_user_account()
        elif choice == 20:
            result = initialize_cache()
            print(result)
        elif choice == 21:
            print_cache_contents()
        elif choice == 22:
            reset_database_status()
        elif choice == 23:
            username = input("Enter username to remove transactions: ")
            confirm = input(f"Are you sure you want to remove all transactions for {username}? (yes/no): ").strip().lower()
            if confirm == 'yes':
                result = remove_user_transactions(username)
                if result != "Success":
                    print(result)
                else:
                    print(f"All transactions for user {username} have been removed.")
            else:
                print("Operation canceled.")
        elif choice == 24:
            username = input("Enter username to reset Klaviyo status: ")
        elif choice == 25:
            username = input("Enter username to display Klaviyo status: ")
        elif choice == 26:
            username = input("Enter username to display discoveries records: ")
            display_discoveries_records(username)
        elif choice == 27:
            username = input("Enter username to remove Klaviyo discovery records: ")
            remove_klaviyo_discoveries(username)
        elif choice == 28:
            username = input("Enter username to create staging files: ")
            create_stage_csv_files(username)
        elif choice == 29:
            limit = input("Enter the number of community payloads to view (default 10): ")
            limit = int(limit) if limit.isdigit() else 10
            payloads = view_community_payloads(limit)
            if not payloads:
                print("\nNo community payloads found.")
            else:
                print("\nCommunity Payloads:")
                for key, value in payloads.items():
                    print(f"Key: {key}")
                    for field, val in value.items():
                        print(f"  {field.decode('utf-8')}: {val.decode('utf-8')}")
                    print("\n")
        elif choice == 30:
            confirm = input("Are you sure you want to delete all community payloads? (yes/no): ").strip().lower()
            if confirm == 'yes':
                deleted_keys = delete_community_payloads()
                print(f"Deleted {len(deleted_keys)} keys.")
            else:
                print("Operation canceled.")
        elif choice == 31:  # Export community payloads to JSON
            username = input("Enter username for exporting payloads: ")
            export_result = export_community_payloads_to_json(username)
            # Parse the JSON string into a dictionary
            export_result_dict = json.loads(export_result)
            print(f"Exported {export_result_dict['payload_count']} payloads to file: {export_result_dict['file_path']}")
        elif choice == 32:
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    initialize_tables()

    parser = argparse.ArgumentParser(description="Manage users, database schema, and scheduled tasks")
    parser.add_argument('--clear-discover-klaviyo-status', metavar='username', help="Clear Discover Klaviyo status for a user")
    parser.add_argument('--display-klaviyo-status', metavar='username', help="Display Klaviyo status for a user")
    parser.add_argument('--init-tables', action='store_true', help="Initialize database tables")
    parser.add_argument('--display-discoveries-records', metavar='username', help="Display discoveries records for a user")
    parser.add_argument('--add-user', nargs=3, metavar=('username', 'password', 'role'), help="Add a new user")
    parser.add_argument('--reset-schema', action='store_true', help="Drop and recreate tables")
    parser.add_argument('--remove-user', metavar='username', help="Remove a user")
    parser.add_argument('--list-users', action='store_true', help="List all users")
    parser.add_argument('--change-password', nargs=2, metavar=('username', 'new_password'), help="Change user password")
    parser.add_argument('--backup-db', action='store_true', help="Backup the database")
    parser.add_argument('--restore-db', action='store_true', help="Restore the database from a backup")
    parser.add_argument('--list-tokens', metavar='username', help="List tokens for a user")
    parser.add_argument('--change-role', nargs=2, metavar=('username', 'new_role'), help="Change user role")
    parser.add_argument('--change-credits', nargs=3, metavar=('username', 'credits', 'action'), help="Change user credits")
    parser.add_argument('--remove-expired-tokens', action='store_true', help="Remove expired tokens")
    parser.add_argument('--get-limits', action='store_true', help="Get rate limits for all users")
    parser.add_argument('--set-limits', action='store_true', help="Set rate limits for a user")
    parser.add_argument('--persist-data', action='store_true', help="Persist client data")
    parser.add_argument('--suspend-user', metavar='username', help="Suspend a user")
    parser.add_argument('--unsuspend-user', metavar='username', help="Unsuspend a user")
    parser.add_argument('--list-transactions', metavar='username', help="List transactions for a user")
    parser.add_argument('--revoke-tokens', metavar='username', help="Revoke all tokens for a user")
    parser.add_argument('--secure-account', action='store_true', help="Secure user account")
    parser.add_argument('--initialize-cache', action='store_true', help="Initialize the cache")
    parser.add_argument('--print-cache-contents', action='store_true', help="Print cache contents")
    parser.add_argument('--reset-database-status', action='store_true', help="Reset database status")
    parser.add_argument('--remove-discoveries-records', metavar='username', help="Remove all Klaviyo discoveries for a user")
    parser.add_argument('--create_stage_csv_files', metavar='username', help="Create stage.csv files")
    parser.add_argument('--view-community-payloads', action='store_true', help="View community payloads from Redis")
    parser.add_argument('--delete-community-payloads', action='store_true', help="Delete all community payloads from Redis")
    parser.add_argument('--export-community-payloads-to-json', metavar='username', help="Export community payloads to JSON")

    args = parser.parse_args()

    if args.view_community_payloads:
        limit = input("Enter how many payloads to view (default 10): ")
        limit = int(limit) if limit.isdigit() else 10
        view_community_payloads(limit)
    elif args.delete_community_payloads:
        confirm = input("Are you sure you want to delete all community payloads? (yes/no): ").strip().lower()
        if confirm == 'yes':
            deleted_keys = delete_community_payloads()
            print(f"Deleted {len(deleted_keys)} keys.")
    elif args.export_community_payloads_to_json:
        timestamp = int(time.time())
        export_result = export_community_payloads_to_json(args.export_community_payloads_to_json, timestamp)
        print(f"Export complete. Payloads exported: {export_result['num_payloads']}")
        print(f"File location: {export_result['file_path']}")
    elif args.clear_discover_klaviyo_status:
        print("Coming soon")
    elif args.display_klaviyo_status:
        print("Coming soon")
    elif args.init_tables:
        initialize_tables()
    elif args.add_user:
        add_user(*args.add_user)
    elif args.reset_schema:
        drop_and_create_tables()
    elif args.remove_user:
        remove_user(args.remove_user)
    elif args.list_users:
        list_users()
    elif args.change_password:
        change_password(*args.change_password)
    elif args.backup_db:
        backup_database()
    elif args.restore_db:
        restore_database()
    elif args.list_tokens:
        list_tokens(args.list_tokens)
    elif args.change_role:
        change_user_role(*args.change_role)
    elif args.change_credits:
        change_user_credits(args.change_credits[0], int(args.change_credits[1]), args.change_credits[2])
    elif args.remove_expired_tokens:
        remove_expired_tokens()
    elif args.get_limits:
        get_limits()
    elif args.set_limits:
        set_limits()
    elif args.persist_data:
        persist_client_data()
    elif args.suspend_user:
        suspend_user(args.suspend_user)
    elif args.unsuspend_user:
        unsuspend_user(args.unsuspend_user)
    elif args.list_transactions:
        list_user_transactions(args.list_transactions)
    elif args.revoke_tokens:
        revoke_tokens(args.revoke_tokens)
    elif args.secure_account:
        secure_user_account()
    elif args.initialize_cache:
        initialize_cache()
    elif args.print_cache_contents:
        print_cache_contents()
    elif args.reset_database_status:
        reset_database_status()
    elif args.display_discoveries_records:
        display_discoveries_records(args.display_discoveries_records)
    elif args.remove_discoveries_records:
        remove_klaviyo_discoveries(args.remove_discoveries_records)
    elif args.create_stage_csv_files:
        create_stage_csv_files(args.create_stage_csv_files)
    else:
        interactive_help()

