import logging
from logging.handlers import RotatingFileHandler
import os

log_dir = "/root/logs"
log_file = os.path.join(log_dir, "admin_app.log")

# Ensure log directory exists
os.makedirs(log_dir, exist_ok=True)

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
from dotenv import load_dotenv, find_dotenv
import time
import requests
from requests.exceptions import SSLError, RequestException
from redis import Redis, exceptions as redis_exceptions
import redis


import sys
sys.path.append('/home/bryananthonyobrien/mysite')
from cache import export_community_payloads_to_json, delete_community_payloads, view_community_payloads, create_stage_csv_files, get_redis_client, print_cache_contents, remove_user_from_cache, initialize_user_cache, suspend_user_cache, unsuspend_user_cache
from credits import log_credit_change

# Debugging: Print available environment variables
print("Available environment variables:")
for var in ["REDIS_HOST", "REDIS_PORT", "REDIS_PASSWORD", "JWT_SECRET_KEY"]:
    print(f"{var}: {os.getenv(var)}")

# Example of using them
redis_host = os.getenv('REDIS_HOST')
redis_port = os.getenv('REDIS_PORT')
redis_password = os.getenv('REDIS_PASSWORD')

print(f"Connected to Redis at {redis_host}:{redis_port}")

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



def user_exists(username):
    try:
        redis_client = get_redis_client()
        # Check if the 'credits' field exists in the user's hash
        if redis_client.hexists(username, 'credits'):
            return True
        else:
            return False
    except redis.RedisError as e:
        logging.error(f"Redis error during user existence check: {e}")
        return False

def add_user(username, password, role='client'):

    if len(password) < 8:
        logging.error("Password must be at least 8 characters long.")
        return

    if user_exists(username):
        logging.warning(f"User {username} already exists.")
        return

    hashed_password = generate_password_hash(password)

    # Set default limits if not provided
    daily_limit = int(os.getenv('DEFAULT_DAILY_LIMIT', 200))
    hourly_limit = int(os.getenv('DEFAULT_HOURLY_LIMIT', 50))
    minute_limit = int(os.getenv('DEFAULT_MINUTE_LIMIT', 10))

    try:
        # Directly initialize user cache with all the attributes and the limits
        initialize_user_cache(
            username,
            password=hashed_password,
            role=role,
            login_attempts=0,  # Default to 0 login attempts
            last_login_attempt='None',  # No login attempt yet
            credits=10,  # Default to 10 credits
            user_status='active',
            is_logged_in_now=0,  # Default to not logged in
            created=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),  # Set creation timestamp
            daily_limit=daily_limit,  # Pass daily limit
            hourly_limit=hourly_limit,  # Pass hourly limit
            minute_limit=minute_limit  # Pass minute limit
        )

        logging.info(f"User {username} added successfully with role {role} and 10 initial credits.")

    except Exception as e:
        logging.error(f"Error during user creation in Redis: {e}")


def secure_user_account():
    username = input("Enter username: ")

    # Check if user exists in Redis
    redis_client = get_redis_client()
    user_key = username
    if not redis_client.exists(user_key):  # If the user's Redis key doesn't exist
        logging.warning(f"User {username} does not exist.")
        set_database_status('idle')
        return

    new_password = input("Enter new password: ")
    if len(new_password) < 8:
        logging.error("Password must be at least 8 characters long.")
        set_database_status('idle')
        return

    try:
        # Step 1: Suspend the user (Update user status to 'suspended')
        redis_client.hset(user_key, 'user_status', 'suspended')
        logging.info(f"User {username} has been suspended.")

        # Step 2: Revoke all tokens
        issued_tokens_key = "issued_tokens"
        revoked_tokens_key = "revoked_tokens"

        # Fetch all issued tokens for this user (they are stored in the global set)
        tokens = redis_client.smembers(f"{issued_tokens_key}:{username}")
        
        if tokens:
            for token in tokens:
                redis_client.sadd(revoked_tokens_key, token)  # Add token to revoked set
                redis_client.srem(f"{issued_tokens_key}:{username}", token)  # Remove token from issued set

            logging.info(f"All tokens for user {username} have been revoked.")
        else:
            logging.info(f"No tokens found for user {username}.")

        # Step 3: Change the password (set the new password in Redis)
        hashed_password = generate_password_hash(new_password)
        redis_client.hset(user_key, 'password', hashed_password)
        logging.info(f"Password for user {username} updated successfully.")

        # Step 4: Unsuspend the user (Update user status to 'active')
        redis_client.hset(user_key, 'user_status', 'active')
        logging.info(f"User {username} has been unsuspended and is now active.")

        logging.info(f"User {username}'s account has been secured successfully.")

    except redis_exceptions.ConnectionError as e:
        logging.error(f"Redis connection error: {str(e)}")
    except Exception as e:
        logging.error(f"Error securing user account: {str(e)}")
 
def revoke_all_tokens_for_user(username):
    try:
        redis_client = get_redis_client()

        # Global keys for issued and revoked tokens (sets)
        issued_tokens_key = "issued_tokens"
        revoked_tokens_key = "revoked_tokens"

        # Check if the 'revoked_tokens' set exists and create it if it doesn't
        if not redis_client.exists(revoked_tokens_key):
            redis_client.sadd(revoked_tokens_key, '')  # Initialize as an empty set
            print(f"Created global Redis set for {revoked_tokens_key}.")

        # Check if the 'issued_tokens' set exists and create it if it doesn't
        if not redis_client.exists(issued_tokens_key):
            print(f"Global Redis set for {issued_tokens_key} does not exist.")
            return  # Exit if there are no issued tokens for this user

        # Fetch all the issued tokens for the user from the global issued_tokens set
        tokens = redis_client.smembers(issued_tokens_key)

        # Iterate over the tokens and revoke the user's access and refresh tokens
        for jti in tokens:
            try:
                # Decode the token data stored in the set (stored as JSON)
                token_data = jti.decode('utf-8')  # Decode byte string to UTF-8 string

                # Skip empty tokens or malformed tokens
                if not token_data:
                    print(f"Skipping empty token {jti} for user {username}")
                    continue

                try:
                    token_data = json.loads(token_data)  # Decode to JSON
                except json.JSONDecodeError as e:
                    print(f"Error decoding token {jti} for user {username}: {str(e)}. Skipping token.")
                    continue

                jwt_token = token_data.get('jwt')
                expires_at = token_data.get('expires_at')
                token_type = token_data.get('type')

                if jwt_token and expires_at and token_type:
                    # Check if the token type is access or refresh
                    if token_type in ['access', 'refresh']:
                        # Add the token to the global revoked tokens list
                        redis_client.sadd(revoked_tokens_key, jti)  # Adding to global revoked tokens set

                        # Remove the token from the global issued tokens in Redis
                        redis_client.srem(issued_tokens_key, jti)  # Remove JTI from issued set

                        print(f"Revoked and deleted {token_type} token {jti} for user {username}")
                    else:
                        print(f"Token {jti} for user {username} is not an access or refresh token, skipping.")
                else:
                    print(f"Missing data for token {jti} for user {username}, skipping.")

            except Exception as e:
                print(f"Error processing token {jti} for user {username}: {str(e)}")
                continue

        print(f"Revoked all tokens for user: {username}")

    except Exception as e:
        print(f"Error revoking tokens for user {username}: {str(e)}")
        raise e

def remove_user(username):
    try:
        # Call remove_user_transactions if needed (assuming this is separate logic)
        remove_user_transactions(username)

        redis_client = get_redis_client()

        # Define the Redis keys associated with the user
        redis_keys = [
            f"{username}",  # User's main data (hash)
            f"klaviyo_discoveries_{username}",  # Klaviyo discoveries data
            f"memberships_{username}",  # Membership-related data
            f"communities_{username}",  # Community-related data
            f"members_{username}",  # Members data
            f"configuration_{username}",  # User's configuration data
            f"{username}:limits",  # User's limits (hash)
            f"{username}:credit_changes"  # User's credit changes (list)
        ]

        # Revoke all tokens before deleting user data
        revoke_all_tokens_for_user(username)  # This should handle adding tokens to revoked_tokens

        # Iterate over all keys and delete them if they exist
        for redis_key in redis_keys:
            if redis_client.exists(redis_key):
                redis_client.delete(redis_key)
                print(f"Key '{redis_key}' deleted from Redis.")
            else:
                print(f"Key '{redis_key}' does not exist in Redis.")

        # Optionally, delete the user's data from the global revoked and issued token sets
        redis_client.srem("revoked_tokens", username)  # Remove user's tokens from global revoked set
        redis_client.srem("issued_tokens", username)  # Remove user's tokens from global issued set

    except redis_exceptions.ConnectionError as e:
        print(f"Redis connection error: {str(e)}")
    except Exception as e:
        print(f"Error removing user data from Redis: {str(e)}")

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
    try:
        redis_client = get_redis_client()
        # Iterate through all user-related keys in Redis
        user_keys = redis_client.keys('*')  # Fetch all keys or specify patterns like '*:user' or similar

        if user_keys:
            print(f"{'Username':<20} {'Issued Tokens':<15} {'Revoked Tokens':<15} {'Role':<10} {'Credits':<10} {'Status':<10} {'Login Attempts':<15} {'Last Login Attempt':<20} {'Logged In Now':<15} {'Created'}")
            for key in user_keys:
                username = key.decode('utf-8')  # Decode Redis key to string
                
                # Debug: print the key and its type
                key_type = redis_client.type(key).decode('utf-8')

                # Check if the key is a hash type
                if key_type == 'hash':
                    # Fetch user data for the hash
                    user_data = redis_client.hgetall(username)
                    # Decode byte strings to proper values
                    user_data = {k.decode('utf-8'): v.decode('utf-8') if isinstance(v, bytes) else v for k, v in user_data.items()}
                    
                    # Check if the key is a valid user hash (should contain specific attributes)
                    if 'role' in user_data and 'credits' in user_data and 'user_status' in user_data:
                        # Extract user data
                        login_attempts = int(user_data.get('login_attempts', 0))
                        last_login_attempt = user_data.get('last_login_attempt', '')
                        user_status = user_data.get('user_status', 'active')
                        is_logged_in_now = user_data.get('is_logged_in_now', 0)
                        role = user_data.get('role', '')
                        credits = int(user_data.get('credits', 0))
                        created = user_data.get('created', '')

                        # Fetch token counts (issued and revoked) from global sets
                        issued_count = redis_client.scard(f"issued_tokens:{username}")  # Global issued tokens set
                        revoked_count = redis_client.scard(f"revoked_tokens:{username}")  # Global revoked tokens set

                        # Print user information
                        print(f"{username:<20} {issued_count:<15} {revoked_count:<15} {role:<10} {credits:<10} {user_status:<10} {login_attempts:<15} {last_login_attempt:<20} {is_logged_in_now:<15} {created}")
                        
        else:
            print("No users found.")
    except redis_exceptions.ConnectionError as e:
        print(f"Redis connection error: {str(e)}")
    except Exception as e:
        print(f"Error listing users: {str(e)}")

def change_password(username, new_password):
    if len(new_password) < 8:
        logging.error("Password must be at least 8 characters long.")
        return

    # Check if the user exists in Redis by looking for their data
    redis_client = get_redis_client()
    user_data_key = username

    if not redis_client.exists(user_data_key):
        logging.warning(f"User {username} does not exist in Redis.")
        return

    # Generate the hashed password
    hashed_password = generate_password_hash(new_password)
    
    try:
        # Update the password in Redis
        redis_client.hset(user_data_key, 'password', hashed_password)
        logging.info(f"Password for user {username} updated successfully in Redis.")
    except Exception as e:
        logging.error(f"Error updating password for user {username} in Redis: {str(e)}")


def format_timestamp(ts):
    if ts is None:
        return 'N/A'
    dt = datetime.utcfromtimestamp(ts)
    return dt.strftime('%A, %B %d, %Y %H:%M:%S UTC')

def list_tokens(username):
    redis_client = get_redis_client()
    
    try:
        # Fetch tokens from the global issued and revoked tokens sets for the user
        issued_tokens_key = f"issued_tokens:{username}"
        revoked_tokens_key = f"revoked_tokens:{username}"

        # Get issued and revoked tokens from Redis
        issued_tokens = redis_client.smembers(issued_tokens_key)
        revoked_tokens = redis_client.smembers(revoked_tokens_key)

        all_tokens = list(issued_tokens) + list(revoked_tokens)
        
        if all_tokens:
            for token in all_tokens:
                try:
                    # Decode the token data (stored as a JSON string in the set)
                    token_data = json.loads(token.decode('utf-8'))  # Decode byte string to UTF-8 string
                    jwt_token = token_data.get("jwt")

                    if jwt_token:
                        try:
                            decoded = jwt.decode(jwt_token, JWT_SECRET_KEY, algorithms=['HS256'])
                            
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

                            # Print the token and its decoded details
                            print(f"Token from {'issued' if token in issued_tokens else 'revoked'} tokens set:")
                            print(jwt_token)
                            print(json.dumps(decoded_with_comments, indent=4))
                            print("\n" + "-"*40 + "\n")
                        
                        except jwt.ExpiredSignatureError:
                            logging.error("Error decoding token: Signature has expired.")
                            print(f"Token from {'issued' if token in issued_tokens else 'revoked'} tokens set:")
                            print(jwt_token)
                            print("Token has expired.")
                            print("\n" + "-"*40 + "\n")
                        
                        except jwt.DecodeError as e:
                            logging.error(f"Error decoding token: {e}")
                            print(f"Token from {'issued' if token in issued_tokens else 'revoked'} tokens set:")
                            print(jwt_token)
                            print("Error decoding token.")
                            print("\n" + "-"*40 + "\n")
                    
                    else:
                        logging.warning(f"Found a token for user {username} that is None.")
                except Exception as e:
                    logging.error(f"Error processing token for user {username}: {str(e)}")
                    continue
        else:
            print(f"No tokens found for user {username}.")
    
    except Exception as e:
        logging.error(f"Error listing tokens for user {username}: {str(e)}")
        print(f"Error fetching tokens for user {username}.")
    
    finally:
        print(f"Completed")

def change_user_role(username, new_role):
    # Validate the new role
    if new_role not in ['admin', 'client']:
        logging.error("Invalid role. Must be 'admin' or 'client'.")
        set_database_status('idle')
        return

    redis_client = get_redis_client()

    # Check if the user exists in Redis (by checking if their hash exists)
    user_data_key = username
    if not redis_client.exists(user_data_key):
        logging.warning(f"User {username} does not exist.")
        set_database_status('idle')
        return

    try:
        # Update the role field in the user's hash in Redis
        redis_client.hset(user_data_key, "role", new_role)
        
        logging.info(f"Role for user {username} updated to {new_role}.")
    except Exception as e:
        logging.error(f"Error updating role for user {username}: {str(e)}")
 
def change_user_credits_in_admin(username, credits, action):
    logging.info(f"Attempting to {action} {credits} credits for user {username}.")
    
    redis_client = get_redis_client()

    # Check if user exists by verifying if their hash exists in Redis
    user_data_key = username
    if not redis_client.exists(user_data_key):
        logging.warning(f"User {username} does not exist.")
        set_database_status('idle')
        return f"User {username} does not exist."

    if action not in ['add', 'remove']:
        logging.error("Invalid action. Must be 'add' or 'remove'.")
        set_database_status('idle')
        return "Invalid action. Must be 'add' or 'remove'."

    # Fetch the current credits from Redis
    current_credits = int(redis_client.hget(user_data_key, "credits") or 0)
    logging.info(f"Current credits for user {username}: {current_credits}")

    if action == 'add':
        new_credits = current_credits + credits
        redis_client.hset(user_data_key, "credits", new_credits)
        log_credit_change(redis_client, username, credits, 'admin', '0')

    elif action == 'remove':
        new_credits = current_credits - credits
        if new_credits < 0:
            logging.error(f"Cannot remove {credits} credits from user {username}. This would result in negative credits.")
            set_database_status('idle')
            return f"Cannot remove {credits} credits from user {username}. This would result in negative credits."
        redis_client.hset(user_data_key, "credits", new_credits)
        log_credit_change(redis_client, username, -credits, 'admin', '0')

    # Log the updated credits
    logging.info(f"Updated credits for user {username}: {new_credits}")

    return "Success"
    
def get_user_role(username):
    try:
        redis_client = get_redis_client()

        # Check if the user exists in Redis by checking if the user's hash exists
        user_data_key = username
        if redis_client.exists(user_data_key):
            # Fetch the user's role from the Redis hash
            role = redis_client.hget(user_data_key, "role")
            if role:
                return role.decode('utf-8')  # Decode byte string to string
            else:
                return None
        else:
            return None
    except Exception as e:
        app_logger.error(f"Error during role check for user {username}: {e}")
        return None

import json
from datetime import datetime

def remove_expired_tokens():
    try:
        redis_client = get_redis_client()

        # Global keys for issued and revoked tokens (sets)
        issued_tokens_key = "issued_tokens"
        revoked_tokens_key = "revoked_tokens"

        # Get all tokens from the global sets
        issued_tokens = redis_client.smembers(issued_tokens_key)
        revoked_tokens = redis_client.smembers(revoked_tokens_key)

        # Get the current time
        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        # Function to remove expired tokens
        def remove_expired_from_set(tokens, set_key):
            for token in tokens:
                try:
                    # Decode the token from the set
                    token_data = json.loads(token.decode('utf-8'))
                    expires_at = token_data.get('expires_at')

                    if expires_at and expires_at <= current_time:
                        # If token has expired, remove it from the set
                        redis_client.srem(set_key, token)
                        app_logger.debug(f"Removed expired token {token_data['jti']} from {set_key}.")

                except Exception as e:
                    app_logger.error(f"Error processing token {token} in {set_key}: {str(e)}")

        # Remove expired tokens from both sets
        remove_expired_from_set(issued_tokens, issued_tokens_key)
        remove_expired_from_set(revoked_tokens, revoked_tokens_key)

        app_logger.info("Expired tokens removed successfully.")

    except Exception as e:
        app_logger.error(f"Error removing expired tokens: {str(e)}")

def get_clients():
    try:
        redis_client = get_redis_client()

        # You may have a pattern or key prefix for the clients' limits in Redis, e.g., "username:limits"
        # Assuming client limits are stored as hashes under keys like "username:limits"
        # Use Redis keys pattern to get all user limit keys
        client_keys = redis_client.keys("*:limits")  # This will match keys like 'username:limits'

        if client_keys:
            for client_key in client_keys:
                username = client_key.decode('utf-8').split(":")[0]  # Extract username from the key

                # Fetch client limits from Redis (stored as hash)
                client_limits = redis_client.hgetall(client_key)
                client_limits = decode_redis_values(client_limits)  # Decode byte strings if necessary

                # Print client details
                daily_limit = client_limits.get('daily_limit', 'N/A')
                hourly_limit = client_limits.get('hourly_limit', 'N/A')
                minute_limit = client_limits.get('minute_limit', 'N/A')

                print(f"Username: {username}")
                print(f"Daily Limit: {daily_limit}")
                print(f"Hourly Limit: {hourly_limit}")
                print(f"Minute Limit: {minute_limit}")
                print("\n" + "-"*40 + "\n")
        else:
            print("No clients found.")
    except redis_exceptions.ConnectionError as e:
        print(f"Redis connection error: {str(e)}")
    except Exception as e:
        print(f"Error fetching clients: {str(e)}")

def get_limits():
    try:
        redis_client = get_redis_client()

        # Get all keys that match the pattern "username:limits"
        limit_keys = redis_client.keys('*:limits')  # This assumes that keys are named like "username:limits"

        if limit_keys:
            print(f"{'Username':<20} {'Daily Limit':<12} {'Hourly Limit':<12} {'Minute Limit':<12}")
            for key in limit_keys:
                username = key.decode('utf-8').split(":")[0]  # Extract username from key

                # Fetch the limits data for each user from Redis (stored as hash)
                limits = redis_client.hgetall(key)
                limits = decode_redis_values(limits)  # Decode byte strings if necessary

                daily_limit = limits.get('daily_limit', 'N/A')
                hourly_limit = limits.get('hourly_limit', 'N/A')
                minute_limit = limits.get('minute_limit', 'N/A')

                # Print the limits
                print(f"{username:<20} {daily_limit:<12} {hourly_limit:<12} {minute_limit:<12}")
        else:
            print("No limits found.")

    except redis_exceptions.ConnectionError as e:
        print(f"Redis connection error: {str(e)}")
    except Exception as e:
        print(f"Error fetching limits: {str(e)}")

def set_limits():
    try:
        # Get user input for limits
        username = input("Enter username: ")
        daily_limit = int(input("Enter daily limit: "))
        hourly_limit = int(input("Enter hourly limit: "))
        minute_limit = int(input("Enter minute limit: "))

        redis_client = get_redis_client()

        # Define the key for storing limits in Redis as a hash
        limits_key = f"{username}:limits"

        # Set the limits in Redis
        redis_client.hset(limits_key, "daily_limit", daily_limit)
        redis_client.hset(limits_key, "hourly_limit", hourly_limit)
        redis_client.hset(limits_key, "minute_limit", minute_limit)

        print(f"Limits for user {username} updated successfully.")
        logging.info(f"Limits for user {username} updated to Daily: {daily_limit}, Hourly: {hourly_limit}, Minute: {minute_limit}")

    except redis_exceptions.ConnectionError as e:
        print(f"Redis connection error: {str(e)}")
        logging.error(f"Redis connection error: {str(e)}")
    except ValueError:
        print("Invalid input. Please enter numeric values for limits.")
        logging.error("Invalid input. Please enter numeric values for limits.")
    except Exception as e:
        print(f"Error updating limits: {str(e)}")
        logging.error(f"Error updating limits: {str(e)}")


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
    redis_client = get_redis_client()

    # Check if the user exists in Redis
    user_data_key = username
    if not redis_client.exists(user_data_key):
        logging.warning(f"User {username} does not exist.")
        set_database_status('idle')
        return

    try:
        # Suspend the user by setting their 'user_status' to 'suspended' in Redis
        redis_client.hset(user_data_key, 'user_status', 'suspended')
        logging.info(f"User {username} suspended successfully.")

        # Update cache if necessary (you can implement suspend_user_cache logic as needed)
        suspend_user_cache(username)
        
    except redis_exceptions.ConnectionError as e:
        logging.error(f"Redis connection error: {str(e)}")
    except Exception as e:
        logging.error(f"Error suspending user {username}: {str(e)}")

def unsuspend_user(username):
    redis_client = get_redis_client()

    # Check if the user exists in Redis
    user_data_key = username
    if not redis_client.exists(user_data_key):
        logging.warning(f"User {username} does not exist.")
        set_database_status('idle')
        return

    try:
        # Unsuspend the user by setting their 'user_status' to 'active' in Redis
        redis_client.hset(user_data_key, 'user_status', 'active')
        logging.info(f"User {username} unsuspended successfully.")

        # Update cache if necessary (you can implement unsuspend_user_cache logic as needed)
        unsuspend_user_cache(username)

    except redis_exceptions.ConnectionError as e:
        logging.error(f"Redis connection error: {str(e)}")
    except Exception as e:
        logging.error(f"Error unsuspending user {username}: {str(e)}")

def list_user_transactions(username):
    redis_client = get_redis_client()

    try:
        # Define the Redis key for the user's transactions (e.g., a list)
        user_transactions_key = f"{username}:credit_changes"

        # Fetch all transactions for the user (assuming the data is stored in a list)
        transactions = redis_client.lrange(user_transactions_key, 0, -1)

        if transactions:
            print(f"{'Change Date':<20} {'Amount':>10} {'Source':<40} {'Transaction ID':<15}")
            print("-" * 85)

            # Iterate over each transaction, assuming each entry is JSON-formatted
            for transaction in transactions:
                try:
                    # Deserialize the transaction data from JSON (assuming it's stored as a JSON string)
                    transaction_data = json.loads(transaction.decode('utf-8'))

                    change_date = transaction_data.get('change_date', 'N/A')
                    amount = transaction_data.get('amount', 0)
                    source = transaction_data.get('source', '')
                    transaction_id = transaction_data.get('transaction_id', '')

                    # Format and print the transaction data
                    print(f"{change_date:<20} {amount:>10} {source:<40} {transaction_id:<15}")
                
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding transaction data for {username}: {str(e)}")
                    print(f"Error decoding transaction data.")
        else:
            print(f"No transactions found for user {username}.")
    except redis_exceptions.ConnectionError as e:
        logging.error(f"Redis connection error: {str(e)}")
    except Exception as e:
        logging.error(f"Error fetching transactions for user {username}: {str(e)}")

def revoke_tokens(username, token_type='all', redis_client=None, lock=True):
    logging.info(f"Revoking {token_type} tokens for user {username}.")
    
    try:
        # Use provided Redis client or get a new one
        redis_client = redis_client if redis_client else get_redis_client()

        # Define the global Redis keys for issued and revoked tokens
        issued_tokens_key = "issued_tokens"
        revoked_tokens_key = "revoked_tokens"

        # Fetch all issued tokens for the user from Redis (assuming they are stored as JSON in a set)
        tokens = redis_client.smembers(f"{issued_tokens_key}:{username}")
        
        # Filter tokens based on the decoded 'type' claim
        tokens_to_revoke = []
        for token in tokens:
            try:
                token_data = json.loads(token.decode('utf-8'))  # Decode byte string to JSON
                jwt_token = token_data['jwt']
                decoded = decode_jwt(jwt_token, JWT_SECRET_KEY, allow_expired=True)
                
                if token_type == 'all' or decoded.get('type') == token_type:
                    tokens_to_revoke.append((token_data['jti'], username, jwt_token, datetime.fromtimestamp(decoded.get('exp')), 'admin'))
            except jwt.ExpiredSignatureError:
                logging.warning(f"Token for user {username} has expired and will not be revoked.")
            except Exception as e:
                logging.error(f"Error decoding token for user {username}: {str(e)}")

        # Log the number of tokens found
        num_tokens = len(tokens_to_revoke)
        logging.info(f"Found {num_tokens} {token_type} tokens for user {username} to revoke.")

        # Revoke the tokens by adding them to the revoked tokens set and removing from the issued set
        for token in tokens_to_revoke:
            redis_client.sadd(revoked_tokens_key, json.dumps({
                'jti': token[0],
                'username': token[1],
                'jwt': token[2],
                'expires_at': token[3].strftime('%Y-%m-%d %H:%M:%S'),
                'reason': token[4]
            }))
            redis_client.srem(f"{issued_tokens_key}:{username}", token[2])  # Remove token from issued set

        logging.info(f"{num_tokens} tokens for user {username} revoked successfully.")
    
    except Exception as e:
        logging.error(f"Error revoking tokens for user {username}: {str(e)}")
 
def remove_user_transactions(username, redis_client=None):
    logging.info(f"Attempting to remove all transactions for user {username}.")
    try:
        # Use provided Redis client or get a new one
        redis_client = redis_client if redis_client else get_redis_client()

        # Define the Redis key pattern for the user's transactions
        transactions_key = f"{username}:credit_changes"

        # Check if the key exists
        if redis_client.exists(transactions_key):
            # Delete the user's transactions from Redis (if it's a list or set)
            redis_client.delete(transactions_key)
            logging.info(f"All transactions for user {username} have been removed.")
            return "Success"
        else:
            logging.warning(f"No transactions found for user {username}.")
            return f"No transactions found for user {username}."

    except redis_exceptions.ConnectionError as e:
        logging.error(f"Redis connection error: {e}")
        return f"Redis connection error: {e}"

    except Exception as e:
        logging.error(f"Error removing transactions for user {username}: {e}")
        return f"Error removing transactions for user {username}: {e}"


def interactive_help():
    actions = [
        "Add User",
        "Remove User",
        "List Users",
        "Change Password",
        "List Tokens",
        "Change User Role",
        "Change User Credits",
        "Remove Expired Tokens",
        "Get Limits",
        "Set Limits",
        "Suspend User",
        "Unsuspend User",
        "List User Transactions",
        "Revoke Tokens",
        "Secure User Account",
        "Print Cache Contents",
        "Remove User Transactions",
        "Display Discoveries Records",
        "Remove Klaviyo Discovery Records",
        "Create Staging Files",
        "View Community Payloads",  # View Redis payloads
        "Delete Community Payloads",  # Delete Redis payloads
        "Export Community Payloads to JSON",
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
            username = input("Enter username to remove: ")
            remove_user(username)

        elif choice == 3:
            list_users()

        elif choice == 4:
            username = input("Enter username: ")
            new_password = input("Enter new password: ")
            change_password(username, new_password)

        elif choice == 5:
            username = input("Enter username: ")
            list_tokens(username)

        elif choice == 6:
            username = input("Enter username: ")
            new_role = input("Enter new role (admin/client): ")
            change_user_role(username, new_role)

        elif choice == 7:
            username = input("Enter username: ")
            action = input("Do you want to add or remove credits? (add/remove): ").strip().lower()
            if action in ['add', 'remove']:
                try:
                    credits = int(input("Enter number of credits: "))
                    result = change_user_credits_in_admin(username, credits, action)
                    if result != "Success":
                        print(result)  # Print any error message if there's an error
                except ValueError:
                    print("Invalid number of credits. Please enter an integer.")
            else:
                print("Invalid action. Please enter 'add' or 'remove'.")

        elif choice == 8:
            remove_expired_tokens()

        elif choice == 9:
            get_limits()

        elif choice == 10:
            set_limits()

        elif choice == 11:
            username = input("Enter username to suspend: ")
            suspend_user(username)

        elif choice == 12:
            username = input("Enter username to unsuspend: ")
            unsuspend_user(username)

        elif choice == 13:
            username = input("Enter username to list transactions: ")
            list_user_transactions(username)

        elif choice == 14:
            username = input("Enter username to revoke tokens: ")
            revoke_tokens(username)

        elif choice == 15:
            secure_user_account()

        elif choice == 16:
            print_cache_contents()

        elif choice == 17:
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

        elif choice == 18:
            username = input("Enter username to display discoveries records: ")
            display_discoveries_records(username)

        elif choice == 19:
            username = input("Enter username to remove Klaviyo discovery records: ")
            remove_klaviyo_discoveries(username)

        elif choice == 20:
            username = input("Enter username to create staging files: ")
            create_stage_csv_files(username)

        elif choice == 21:
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

        elif choice == 22:
            confirm = input("Are you sure you want to delete all community payloads? (yes/no): ").strip().lower()
            if confirm == 'yes':
                deleted_keys = delete_community_payloads()
                print(f"Deleted {len(deleted_keys)} keys.")
            else:
                print("Operation canceled.")

        elif choice == 23:  # Export community payloads to JSON
            username = input("Enter username for exporting payloads: ")
            export_result = export_community_payloads_to_json(username)
            # Parse the JSON string into a dictionary
            export_result_dict = json.loads(export_result)
            print(f"Exported {export_result_dict['payload_count']} payloads to file: {export_result_dict['file_path']}")

        elif choice == 24:
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please select a valid option.")
            
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="CLI for user & system actions (mirroring the interactive menu)")

    # 1. Add User
    parser.add_argument(
        '--add-user', nargs=3, metavar=('username', 'password', 'role'),
        help="Add a new user"
    )

    # 2. Remove User
    parser.add_argument(
        '--remove-user', metavar='username',
        help="Remove a user"
    )

    # 3. List Users
    parser.add_argument(
        '--list-users', action='store_true',
        help="List all users"
    )

    # 4. Change Password
    parser.add_argument(
        '--change-password', nargs=2, metavar=('username', 'new_password'),
        help="Change user password"
    )

    # 5. List Tokens
    parser.add_argument(
        '--list-tokens', metavar='username',
        help="List tokens for a user"
    )

    # 6. Change User Role
    parser.add_argument(
        '--change-role', nargs=2, metavar=('username', 'new_role'),
        help="Change a user's role (admin or client)"
    )

    # 7. Change User Credits
    parser.add_argument(
        '--change-credits', nargs=3, metavar=('username', 'credits', 'action'),
        help="Change a user's credits (action must be add/remove)"
    )

    # 8. Remove Expired Tokens
    parser.add_argument(
        '--remove-expired-tokens', action='store_true',
        help="Remove expired tokens"
    )

    # 9. Get Limits
    parser.add_argument(
        '--get-limits', action='store_true',
        help="Get rate limits for all users"
    )

    # 10. Set Limits
    parser.add_argument(
        '--set-limits', action='store_true',
        help="Set rate limits for a user"
    )

    # 11. Suspend User
    parser.add_argument(
        '--suspend-user', metavar='username',
        help="Suspend a user"
    )

    # 12. Unsuspend User
    parser.add_argument(
        '--unsuspend-user', metavar='username',
        help="Unsuspend a user"
    )

    # 13. List User Transactions
    parser.add_argument(
        '--list-transactions', metavar='username',
        help="List transactions for a user"
    )

    # 14. Revoke Tokens
    parser.add_argument(
        '--revoke-tokens', metavar='username',
        help="Revoke all tokens for a user"
    )

    # 15. Secure User Account
    parser.add_argument(
        '--secure-account', action='store_true',
        help="Secure a user account"
    )

    # 16. Print Cache Contents
    parser.add_argument(
        '--print-cache-contents', action='store_true',
        help="Print cache contents"
    )

    # 17. Remove User Transactions
    parser.add_argument(
        '--remove-user-transactions', metavar='username',
        help="Remove user transactions"
    )

    # 18. Display Discoveries Records
    parser.add_argument(
        '--display-discoveries-records', metavar='username',
        help="Display 'discoveries' records for a user"
    )

    # 19. Remove Klaviyo Discovery Records
    parser.add_argument(
        '--remove-discoveries-records', metavar='username',
        help="Remove Klaviyo discovery records for a user"
    )

    # 20. Create Staging Files
    parser.add_argument(
        '--create-stage-csv-files', metavar='username',
        help="Create staging CSV files for a user"
    )

    # 21. View Community Payloads
    parser.add_argument(
        '--view-community-payloads', action='store_true',
        help="View community payloads in Redis"
    )

    # 22. Delete Community Payloads
    parser.add_argument(
        '--delete-community-payloads', action='store_true',
        help="Delete all community payloads from Redis"
    )

    # 23. Export Community Payloads to JSON
    parser.add_argument(
        '--export-community-payloads-to-json', metavar='username',
        help="Export community payloads to a JSON file"
    )

    args = parser.parse_args()

    # 21. View Community Payloads
    if args.view_community_payloads:
        limit = input("Enter how many payloads to view (default 10): ")
        limit = int(limit) if limit.isdigit() else 10
        view_community_payloads(limit)

    # 22. Delete Community Payloads
    elif args.delete_community_payloads:
        confirm = input("Are you sure you want to delete all community payloads? (yes/no): ").strip().lower()
        if confirm == 'yes':
            deleted_keys = delete_community_payloads()
            print(f"Deleted {len(deleted_keys)} keys.")

    # 23. Export Community Payloads to JSON
    elif args.export_community_payloads_to_json:
        timestamp = int(time.time())
        export_result = export_community_payloads_to_json(args.export_community_payloads_to_json, timestamp)
        print(f"Export complete. Payloads exported: {export_result['num_payloads']}")
        print(f"File location: {export_result['file_path']}")

    elif args.add_user:
        add_user(*args.add_user)

    elif args.remove_user:
        remove_user(args.remove_user)

    elif args.list_users:
        list_users()

    elif args.change_password:
        change_password(*args.change_password)

    elif args.list_tokens:
        list_tokens(args.list_tokens)

    elif args.change_role:
        change_user_role(*args.change_role)

    elif args.change_credits:
        username, credits_str, action = args.change_credits
        change_user_credits_in_admin(username, int(credits_str), action)

    elif args.remove_expired_tokens:
        remove_expired_tokens()

    elif args.get_limits:
        get_limits()

    elif args.set_limits:
        set_limits()

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

    elif args.print_cache_contents:
        print_cache_contents()

    elif args.remove_user_transactions:
        remove_user_transactions(args.remove_user_transactions)

    elif args.display_discoveries_records:
        display_discoveries_records(args.display_discoveries_records)

    elif args.remove_discoveries_records:
        remove_klaviyo_discoveries(args.remove_discoveries_records)

    elif args.create_stage_csv_files:
        create_stage_csv_files(args.create_stage_csv_files)

    else:
        interactive_help()

