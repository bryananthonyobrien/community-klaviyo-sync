from logs import app_logger
import time
import requests
import urllib.parse
from collections import defaultdict
from dateutil import parser
from datetime import timezone
from mappings import country_mappings
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, get_jwt
from flask_cors import CORS, cross_origin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sslify import SSLify
from dotenv import load_dotenv
from tenacity import retry, wait_fixed, stop_after_attempt
from jwt import ExpiredSignatureError
import os
import sqlite3
import threading
import traceback
from flask_limiter.errors import RateLimitExceeded
from functools import wraps
from klaviyo import get_klaviyo_profile_count, do_klaviyo_discovery, get_redis_client
from community import Community_subscription_create, create_sub_community_tag
import json
import zipfile
from flask import send_file, abort
from flask import Response
import redis
from datetime import datetime, timedelta  # Ensure this import is included
from ipinfo import create_ipinfo_cache_file, load_ipinfo_cache, update_ipinfo_cache_file, is_valid_ip, do_ip_address_look_up


# Import custom modules
from cache import track_api_call, get_user_data, sync_credits_to_db, clash_members_and_profiles, create_stage_csv_files
app_logger.debug("Importing credits module in app.py")
from credits import create_tokens, cancel_payment_function, payment_success_function, create_checkout_session_function, stripe_webhook_function
app_logger.debug("Imported credits module successfully in app.py")
app_logger.debug("Importing common module in app.py")
from common import is_token_revoked, add_issued_token_function, revoke_all_access_tokens_for_user, decode_jwt, add_revoked_token_function, get_db_connection, DEFAULT_DAILY_LIMIT, DEFAULT_HOURLY_LIMIT, DEFAULT_MINUTE_LIMIT
app_logger.debug("Imported common module successfully in app.py")
from login import login_function
from logout import logout_function
from monitoring import test_throughput_function, cpu_usage_function, get_cpu_usage_function, get_file_storage_usage_function

def measure_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"{func.__name__} took {end_time - start_time} seconds")
        return result
    return wrapper

# Load environment variables from the specified .env file
dotenv_path = '/home/bryananthonyobrien/mysite/.env'
load_dotenv(dotenv_path)

app = Flask(__name__, static_url_path='/static', static_folder='static', template_folder='templates')

# Enable CORS for all routes
CORS(app, resources={r"/*": {"origins": "*"}}, methods=["GET", "POST", "DELETE", "PUT"])

is_loading_clients = True

# Use the environment variable
DATABASE_PATH = os.getenv('DATABASE_PATH', 'tokens.db')

# Set up JWT expiration times
access_token_expires_minutes = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES_MINUTES', 15))
refresh_token_expires_days = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES_DAYS', 30))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=access_token_expires_minutes)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=refresh_token_expires_days)

# Load the JWT secret key from the environment variables
jwt_secret_key = os.getenv('JWT_SECRET_KEY')
if not jwt_secret_key:
    raise ValueError("No JWT_SECRET_KEY set for Flask application")

# Use the JWT secret key for both JWT and session secret
app.config['JWT_SECRET_KEY'] = str(jwt_secret_key)
app.config['SECRET_KEY'] = str(jwt_secret_key)  # Set the SECRET_KEY for Flask sessions

# Log the secret keys
app_logger.info(f"JWT_SECRET_KEY set: {app.config['JWT_SECRET_KEY']}")
app_logger.info(f"SECRET_KEY set for Flask sessions: {app.config['SECRET_KEY']}")

# Continue with the rest of your configuration
jwt = JWTManager(app)
app_logger.info("Created JWTManager")

# Initialize Redis client
redis_client = get_redis_client()

# Set up rate limiting using Redis as storage
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=f"redis://:{os.getenv('REDIS_PASSWORD')}@{os.getenv('REDIS_HOST')}:{os.getenv('REDIS_PORT')}/{os.getenv('REDIS_DB', 0)}"
)

# Replace these with your PythonAnywhere username and API token
USERNAME = os.getenv('PAW_USERNAME')
API_TOKEN = os.getenv('PAW_API_TOKEN')

# Ensure the environment variables are set
if not USERNAME or not API_TOKEN:
    raise ValueError("PAW_USERNAME and API_TOKEN must be set in the environment variables")

# Define the API endpoint
API_URL = f'https://www.pythonanywhere.com/api/v0/user/{USERNAME}/cpu/'

# Set up the headers with your API token
HEADERS = {
    'Authorization': f'Token {API_TOKEN}'
}

def datetime_converter(o):
    if isinstance(o, datetime):
        return o.isoformat()
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")

db_lock = threading.Lock()
clients_lock = threading.Lock()

# Fetch user-specific rate limits from the database
def fetch_rate_limit_from_db(user_id):
    app_logger.debug(f"Fetching rate limits from database for user {user_id}")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT daily_limit, hourly_limit, minute_limit FROM limits WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        app_logger.debug(f"Fetched rate limits for user {user_id}: {result}")
        if result:
            return result
        return None

# Dynamically determine rate limits
def get_dynamic_rate_limit():
    user_identity = get_jwt_identity()
    user_rate_limit = fetch_rate_limit_from_db(user_identity)

    if user_rate_limit:
        daily_limit, hourly_limit, minute_limit = user_rate_limit
        return f"{minute_limit} per minute; {hourly_limit} per hour; {daily_limit} per day"
    return "1000 per minute; 5000 per hour; 10000 per day"

@retry(wait=wait_fixed(1), stop=stop_after_attempt(10))
def add_revoked_token(jti, username, jwt, expires_at, conn=None):
    return add_revoked_token_function(jti, username, jwt, expires_at, conn=None)

@retry(wait=wait_fixed(1), stop=stop_after_attempt(10))
def add_issued_token(jti, username, jwt, expires_at, conn=None):
    return add_issued_token_function(jti, username, jwt, expires_at, conn=None)


# Configure JWT to use the revoked token check
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return is_token_revoked(jti)

def get_jti_and_username(jti):
    try:
        with get_db_connection() as conn:
            # app_logger.debug("Entering with block in get_jti_and_username")
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM issued_tokens WHERE jti = ?", (jti,))
            result = cursor.fetchone()
            # app_logger.debug("Exiting with block in get_jti_and_username")
            if result:
                return jti, result[0]
            return None, None
    except sqlite3.OperationalError as e:
        app_logger.error(f"OperationalError in get_jti_and_username: {str(e)}")
        if 'no such table' in str(e):
            app_logger.error(f"Missing table detected: {str(e)}")
            return None, None
    except Exception as e:
        app_logger.error(f"Error getting jti and username: {str(e)}")
        return None, None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    # Only redirect if accessed via the non-www version
    if request.host == 'bryanworx.com':
        return redirect('https://www.bryanworx.com', code=301)
    return render_template('login.html')
    
@app.route('/success', methods=['GET'])
@cross_origin()
def payment_success():
    return payment_success_function()


@measure_time
@app.route('/cancel')
def cancel():
    # Handle cancelled payment
    return cancel_payment_function()

def revoke_all_tokens_for_user(username):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT jti, jwt, expires_at FROM issued_tokens WHERE username = ?", (username,))
            tokens = cursor.fetchall()

            for (jti, jwt, expires_at) in tokens:
                add_revoked_token_function(jti, username, jwt, expires_at, conn)
                cursor.execute("DELETE FROM issued_tokens WHERE jti = ?", (jti,))

            conn.commit()
            app_logger.debug(f"Revoked all tokens for user: {username}")
    except Exception as e:
        app_logger.error(f"Error revoking tokens for user {username}: {str(e)}")

import sys  # Ensure this is imported


def fetch_sms_profiles_for_user(username, chunk_number=1):
    """
    Fetch a specific chunk of SMS profiles for a user from Redis and check if there is a subsequent chunk.

    Args:
        username (str): The user's username.
        chunk_number (int): The chunk number to fetch.

    Returns:
        tuple: A tuple containing a list of profiles in the specified chunk and a boolean indicating if this is the last chunk.
    """
    redis_client = get_redis_client()
    current_key = f"sms_profiles_eligible_to_import_to_community_{username}_{chunk_number}"
    next_key = f"sms_profiles_eligible_to_import_to_community_{username}_{chunk_number + 1}"

    # Fetch SMS profiles for the specified chunk
    sms_profiles_data = redis_client.hgetall(current_key)

    # Check if the fetched data is empty
    if not sms_profiles_data:
        app_logger.warning(f"No SMS profiles found for user {username} in chunk {chunk_number}.")
        return [], True  # Returning an empty list and indicating it as the last chunk

    # Convert bytes to regular strings and then to JSON objects
    sms_profiles = [
        json.loads(profile_data.decode('utf-8'))
        for phone_number, profile_data in sms_profiles_data.items()
    ]

    return sms_profiles

from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Create a global lock for thread safety when updating shared data
lock = threading.Lock()

import csv
from datetime import datetime
import os

from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import time
import os
from datetime import datetime
import traceback

@app.route('/signal_gateway_timeout', methods=['POST'])
@jwt_required()
def signal_gateway_timeout():
    username = get_jwt_identity()
    redis_client = get_redis_client()
    redis_status_key = f"{username}_import_status"

    try:
        # Retrieve the JSON data from Redis
        status_data = redis_client.get(redis_status_key)
        if not status_data:
            return jsonify({'success': False, 'msg': 'No status data found'}), 404

        # Parse the JSON data
        status_data = json.loads(status_data)

        # Update the status to indicate a client timeout and set a 504 code
        status_data['status'] = '504 (Gateway Time-out)'

        # Save the updated status back to Redis
        redis_client.set(redis_status_key, json.dumps(status_data))
        app_logger.info(f"Status set to '504 (Gateway Time-out)' for user {username}")

        return jsonify({'success': True, 'msg': 'Status updated to 504 (Gateway Time-out)'}), 200

    except Exception as e:
        app_logger.error(f"Failed to set status to 504 (Gateway Time-out): {str(e)}")
        return jsonify({'success': False, 'msg': 'Failed to update status', 'error_details': str(e)}), 500

@app.route('/import_all_profiles', methods=['POST'])
@jwt_required()
def preopt_into_community_all():
    username = get_jwt_identity()
    app_logger.info(f"Received request to pre-opt profiles into community for user: {username}")
    app_logger.info(f"Incoming request JSON:\n{json.dumps(request.json, indent=4)}")

    # Initialize Redis and set the import status to "running"
    redis_client = get_redis_client()
    redis_status_key = f"{username}_import_status"
    app_logger.info(f"redis_status_key: {redis_status_key}")

    # Retrieve the JSON data from Redis
    status_data = redis_client.get(redis_status_key)
    if not status_data:
        app_logger.info(f"{redis_status_key} not found")
        return jsonify({'success': False, 'msg': 'Profiles not loaded', 'error_details': 'Click - Create Staging Files'})

    try:
        # Parse the JSON data
        status_data = json.loads(status_data)
        app_logger.info(f"status_data on entry to import_all_profiles:\n{json.dumps(status_data, indent=4)}")
    except json.JSONDecodeError as e:
        app_logger.error(f"Failed to parse JSON data from Redis: {str(e)}")

    # Extract status details from Redis data
    status = status_data.get('status')

    # Reset for a new run
    if status == "completed":
        # Determine if there are multiple chunks
        number_of_chunks = int(status_data.get('number_of_chunks', 1))
        total_profiles = int(status_data.get('total_profiles', 0))
        more_chunks = number_of_chunks > 1

        # Set initial status in Redis
        status_data.update({
            'status': 'initialised',
            'processed_profiles': 0,
            'total_profiles': total_profiles,
            'chunk_number': 1,
            'number_of_chunks': number_of_chunks,
            'number_of_chunks_processed': 0,
            'message': 'Ready to Import',
            'successful_imports': 0,
            'import_started_at': 0,
            'import_ended_at': 0,
            'total_time_taken': 0,
            'more_chunks': more_chunks
        })

        try:
            redis_client.set(redis_status_key, json.dumps(status_data))
            pretty_status_data = json.dumps(status_data, indent=4)  # Pretty format the JSON data
            app_logger.info(f"status_data reset to initial in import_all_profiles:\n{pretty_status_data}")
        except Exception as e:
            app_logger.error(f"Failed to reset to initial status in Redis: {e}")

    processed_profiles = int(status_data.get('processed_profiles', 0))
    total_profiles = int(status_data.get('total_profiles', 0))
    chunk_number = int(request.json.get('chunk_number', int(status_data.get('chunk_number', 1))))
    number_of_chunks = int(status_data.get('number_of_chunks', 1))
    number_of_chunks_processed = int(status_data.get('number_of_chunks_processed', 0))
    successful_imports = int(status_data.get('successful_imports', 0))
    import_started_at = int(status_data.get('import_started_at', 0))
    import_ended_at = int(status_data.get('import_ended_at', 0))
    total_time_taken = int(status_data.get('total_time_taken', 0))
    more_chunks = status_data.get('more_chunks', False)

    csv_filename = f"community_import_{username}.csv"
    user_data_dir = f"/home/bryananthonyobrien/mysite/data/community/imports/{username}"
    csv_file_path = os.path.join(user_data_dir, csv_filename)

    # Calculate timing information
    now = time.time()
    if chunk_number == 1:
        import_started_at = now
        import_ended_at = 0
        total_time_taken = 0
        # Delete the file if it already exists
        if os.path.exists(csv_file_path):
            os.remove(csv_file_path)
            app_logger.info(f"Existing file {csv_file_path} deleted for the first chunk.")
        else:
            app_logger.info(f"No existing file found to delete for {csv_file_path}.")
    else:
        total_time_taken = now - import_started_at

    # Fetch profiles for the specific chunk
    profiles = fetch_sms_profiles_for_user(username, chunk_number)

    # Redis and environment configuration settings
    configuration_key = f"configuration_{username}"
    configuration = redis_client.hgetall(configuration_key)

    test_mode_enabled = configuration.get(b'test_mode_enabled', b'0') == b'1' if configuration else False
    max_workers = int(configuration.get(b'max_community_workers', 10)) if configuration else int(os.getenv('MAX_COMMUNITY_WORKERS', 10))

    app_logger.info(f"Test mode for {username}: {test_mode_enabled}")
    app_logger.info(f"Max workers for {username}: {max_workers}")

    # Update Redis with running status
    redis_client.set(redis_status_key, json.dumps({
        'status': 'running',
        'processed_profiles': processed_profiles,
        'total_profiles': total_profiles,
        'chunk_number': chunk_number,
        'number_of_chunks': number_of_chunks,
        'number_of_chunks_processed': number_of_chunks_processed,
        'message': 'Processing profiles',
        'successful_imports': successful_imports,
        'import_started_at': import_started_at,
        'import_ended_at': 0,
        'total_time_taken': total_time_taken,
        'more_chunks': more_chunks,
        'max_workers': max_workers,
        'test_mode_enabled': test_mode_enabled
    }))

    # Payload for profile processing
    local_payload_structure = {}

    # Retrieve Community keys from Redis
    community_client_id = redis_client.hget(configuration_key, 'COMMUNITY_CLIENT_ID')
    community_api_token = redis_client.hget(configuration_key, 'COMMUNITY_API_TOKEN')
    sub_community = redis_client.hget(configuration_key, 'SUB_COMMUNITY')
    tag = sub_community.decode('utf-8') if sub_community else "Imported from Klaviyo"

    # Decode the keys from Redis or fall back to environment variables
    if community_client_id:
        community_client_id = community_client_id.decode('utf-8')
        app_logger.info(f"COMMUNITY_CLIENT_ID retrieved from Redis for user {username}")
    else:
        community_client_id = os.getenv('COMMUNITY_CLIENT_ID')
        if not community_client_id:
            app_logger.error("COMMUNITY_CLIENT_ID not set in Redis or environment variables.")
            return jsonify({'success': False, 'msg': 'COMMUNITY_CLIENT_ID not found'}), 500

    if community_api_token:
        community_api_token = community_api_token.decode('utf-8')
        app_logger.info(f"COMMUNITY_API_TOKEN retrieved from Redis for user {username}")
    else:
        community_api_token = os.getenv('COMMUNITY_API_TOKEN')
        if not community_api_token:
            app_logger.error("COMMUNITY_API_TOKEN not set in Redis or environment variables.")
            return jsonify({'success': False, 'msg': 'COMMUNITY_API_TOKEN not found'}), 500

    mode = 'all'
    # Use ThreadPoolExecutor to process profiles concurrently
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_profile = {
            executor.submit(process_profile, tag, community_client_id, community_api_token, profile, username, local_payload_structure, mode, test_mode_enabled): profile for profile in profiles
        }

        # Process profiles as they are completed
        for idx, future in enumerate(as_completed(future_to_profile)):
            profile = future_to_profile[future]
            try:
                result = future.result()
                if result and result['status'] == 'success':
                    successful_imports += 1
                processed_profiles += 1

                # Update Redis every 100 profiles or at the end of the chunk
                if processed_profiles % 100 == 0 or processed_profiles == total_profiles:
                    import_ended_at = time.time() if processed_profiles == total_profiles else import_ended_at

                    # Check the status during processing to detect client timeout
                    status_data = json.loads(redis_client.get(redis_status_key))  # Refresh status_data
                    app_logger.info(f"Checking status update in loop:\n{json.dumps(status_data, indent=4)}")


                    if status_data.get('status') == '504 (Gateway Time-out)':
                        # Reset and exit
                        status_data.update({
                            'status': 'initialised',
                            'processed_profiles': 0,
                            'total_profiles': total_profiles,
                            'chunk_number': 1,
                            'number_of_chunks': number_of_chunks,
                            'number_of_chunks_processed': 0,
                            'message': 'Ready to Import',
                            'successful_imports': 0,
                            'import_started_at': 0,
                            'import_ended_at': 0,
                            'total_time_taken': 0,
                            'more_chunks': more_chunks
                        })
                        redis_client.set(redis_status_key, json.dumps(status_data))
                        app_logger.info(f"Process reset due to 504 (Gateway Time-out):\n{json.dumps(status_data, indent=4)}")

                        return jsonify({'success': False, 'msg': 'Process reset due to client timeout'}), 504

                    status_data.update({
                        'status': 'running',
                        'processed_profiles': processed_profiles,
                        'total_profiles': total_profiles,
                        'chunk_number': chunk_number,
                        'number_of_chunks': number_of_chunks,
                        'number_of_chunks_processed': number_of_chunks_processed,
                        'message': 'Processing profiles',
                        'successful_imports': successful_imports,
                        'import_started_at': import_started_at,
                        'import_ended_at': import_ended_at,
                        'total_time_taken': 0,
                        'more_chunks': more_chunks,
                        'max_workers': max_workers,
                        'test_mode_enabled': test_mode_enabled
                    })
                    redis_client.set(redis_status_key, json.dumps(status_data))
                    app_logger.info(f"Redis status update in loop:\n{json.dumps(status_data, indent=4)}")

            except Exception as e:
                app_logger.error(f"Error processing profile {profile}: {str(e)}")
                app_logger.error(traceback.format_exc())

    # Append data to CSV after each chunk
    os.makedirs(user_data_dir, exist_ok=True)
    try:
        with open(csv_file_path, mode='a', newline='') as csv_file:
            fieldnames = ['phone_number', 'status', 'message', 'execution_time']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if chunk_number == 1:
                writer.writeheader()
            for phone_number, result in local_payload_structure.items():
                writer.writerow({
                    'phone_number': phone_number,
                    'status': result.get('status', 'unknown'),
                    'message': result.get('message', '').replace('\n', ' '),
                    'execution_time': result.get('execution_time', '0.0000')
                })
        app_logger.info(f"Data appended to CSV file {csv_filename} with {len(local_payload_structure)} entries.")
    except Exception as e:
        app_logger.error(f"Failed to write to CSV file: {str(e)}")
        redis_client.set(redis_status_key, json.dumps({'status': 'failed', 'error': str(e)}))
        return jsonify({'success': False, 'msg': 'Failed to write to CSV'}), 500

    number_of_chunks_processed += 1
    more_chunks = number_of_chunks_processed < number_of_chunks

    # Final Redis update after last chunk
    if not more_chunks:
        total_time_taken = time.time() - import_started_at
        status_data.update({
            'status': 'completed',
            'processed_profiles': processed_profiles,
            'total_profiles': total_profiles,
            'chunk_number': chunk_number,
            'number_of_chunks': number_of_chunks,
            'number_of_chunks_processed': number_of_chunks_processed,
            'message': 'Processing complete',
            'successful_imports': successful_imports,
            'import_started_at': datetime.fromtimestamp(import_started_at).strftime('%Y-%m-%d %H:%M:%S'),
            'import_ended_at': datetime.fromtimestamp(import_ended_at).strftime('%Y-%m-%d %H:%M:%S'),
            'total_time_taken': total_time_taken,
            'more_chunks': more_chunks,
            'max_workers': max_workers,
            'test_mode_enabled': test_mode_enabled
        })
    else:
        status_data.update({
            'status': 'running',
            'processed_profiles': processed_profiles,
            'total_profiles': total_profiles,
            'chunk_number': chunk_number,
            'number_of_chunks': number_of_chunks,
            'number_of_chunks_processed': number_of_chunks_processed,
            'message': 'Processing complete',
            'successful_imports': successful_imports,
            'import_started_at': import_started_at,
            'import_ended_at': import_ended_at,
            'total_time_taken': total_time_taken,
            'more_chunks': more_chunks,
            'max_workers': max_workers,
            'test_mode_enabled': test_mode_enabled
        })


    redis_client.set(redis_status_key, json.dumps(status_data))
    app_logger.info(f"Final Redis status for chunk:\n{json.dumps(status_data, indent=4)}")

    # Add the status_data to the Redis hash structure with timestamp-based key
    try:
        # Extract start_time from status_data
        start_time = status_data.get("import_started_at", "")
        if start_time:
            # Construct the hash key and field key
            community_imports_key = f"community_imports_{username}"
            field_key = f"community_imports_{username}_{start_time}"

            # Store the status_data in the Redis hash
            redis_client.hset(community_imports_key, field_key, json.dumps(status_data))
            app_logger.info(f"Added status data to Redis hash '{community_imports_key}' with key '{field_key}'")
        else:
            app_logger.warning("No 'import_started_at' found in status_data; unable to store in hash.")
    except Exception as e:
        app_logger.error(f"Failed to add status data to Redis hash: {e}")


    # Prepare and return the response
    response_data = {
        'success': True,
        'status': status_data.get('status', 'completed'),  # Ensure 'status' is included
        'message': status_data.get('message', 'Completed'),  # Ensure 'message' is included
        'processed_profiles': processed_profiles,
        'total_profiles': total_profiles,
        'successful_imports': successful_imports,
        'chunk_number': chunk_number,
        'number_of_chunks': number_of_chunks,
        'number_of_chunks_processed': number_of_chunks_processed,
        'more_chunks': more_chunks,
        'csv_file_path': csv_file_path,
        'max_workers': max_workers,
        'test_mode_enabled': test_mode_enabled
    }


    app_logger.info(f"Response data:\n{json.dumps(response_data, indent=4)}")
    return jsonify(response_data), 200


@app.route('/check_import_status', methods=['GET'])
@jwt_required()
def check_import_status():
    username = get_jwt_identity()
    redis_client = get_redis_client()
    redis_status_key = f"{username}_import_status"

    # Get the status from Redis
    import_status = redis_client.get(redis_status_key)
    if import_status:
        app_logger.info(f"/check_import_status {import_status}")
        import_status = json.loads(import_status)
        return jsonify({'result': import_status}), 200
    else:
        app_logger.info("/check_import_status no_import")
        return jsonify({'result': {'status': 'not_started'}}), 404

def process_profile(tag, community_client_id, community_api_token, profile, username, local_payload_structure, mode, test_mode_enabled=False):
    """
    Function to process each profile.
    We lock access to local_payload_structure to prevent race conditions.

    Args:
        profile (dict): The profile data to process.
        username (str): The username performing the operation.
        local_payload_structure (dict): Shared structure to store payloads.
        test_mode_enabled (bool): If True, skips actual API calls and simulates success.
    """
    global lock  # Reference the global lock

    # Time how long each call to Community_subscription_create takes
    create_start_time = time.time()

    # Create the subscription, passing test_mode_enabled
    result = Community_subscription_create(tag, community_client_id, community_api_token, profile, username, mode='all', test_mode=test_mode_enabled)

    create_end_time = time.time()
    execution_time = create_end_time - create_start_time
    if mode == 'single':
        app_logger.info(f"Community_subscription_create for profile took {execution_time:.4f} seconds")

    # Update the in-memory payload structure safely
    with lock:
        # Assuming each thread adds its result to the shared in-memory structure
        if result and result['status'] == 'success':
            # Add execution_time to the result
            result['execution_time'] = f"{execution_time:.4f}"
            # Update the shared structure inside the lock to prevent race conditions
            local_payload_structure[profile['phone_number']] = result

    return result

@app.route('/sms_profiles_eligible_to_import_to_community', methods=['GET'])
@jwt_required()
def get_sms_profiles():
    username = get_jwt_identity()
    limit = request.args.get('limit', default=10, type=int)  # Get the limit from query parameters, default to 10

    app_logger.info(f"Received request to fetch SMS profiles for user: {username}")

    try:
        app_logger.info(f"Fetching SMS profiles for user: {username}")

        # Construct the key for fetching SMS profiles
        sms_profiles_key = f"sms_profiles_eligible_to_import_to_community_{username}"
        redis_client = get_redis_client()

        # Fetch SMS profiles from Redis
        sms_profiles_data = redis_client.hgetall(sms_profiles_key)

        # Check if the fetched data is empty
        if not sms_profiles_data:
            app_logger.warning(f"No SMS profiles found for user {username}.")
            return jsonify({'success': False, 'msg': 'No SMS profiles found for this user.'}), 404

        # Convert bytes to regular strings and then to JSON objects
        sms_profiles = {
            phone_number.decode('utf-8'): json.loads(profile_data.decode('utf-8'))
            for phone_number, profile_data in sms_profiles_data.items()
        }

        # Limit to the specified number of profiles
        limited_sms_profiles = dict(list(sms_profiles.items())[:limit])  # Slice to the first `limit` items

        # Get the total number of profiles
        total_profiles_count = len(sms_profiles_data)

        # Prepare response data
        response_data = {
            'success': True,
            'sms_profiles': limited_sms_profiles,
            'count': len(limited_sms_profiles),  # Count of SMS profiles returned
            'total_count': total_profiles_count,  # Total number of profiles in Redis
        }

        # Attempt to serialize response data to ensure it's JSON serializable
        try:
            json_response = json.dumps(response_data)  # Serialize the response
            json_size = sys.getsizeof(json_response)  # Get the size in bytes
        except TypeError as te:
            app_logger.error(f"Serialization error: {str(te)}")
            return jsonify({'success': False, 'msg': 'Internal Server Error'}), 500

        # Include the size of the JSON response in the response data
        response_data['json_size_bytes'] = json_size  # Add size to response

        app_logger.info(f"Successfully fetched SMS profiles for user {username}. JSON size: {json_size} bytes.")
        return jsonify(response_data), 200

    except redis.exceptions.ConnectionError as e:
        app_logger.error(f"Redis connection error in get_sms_profiles: {str(e)}")
        return jsonify({'success': False, 'msg': 'Redis connection error.'}), 500
    except Exception as e:
        app_logger.error(f"Error fetching SMS profiles for user {username}: {str(e)}")
        return jsonify({'success': False, 'msg': 'Internal Server Error'}), 500

@app.route('/admin')
@login_required
def admin_panel():
    return render_template('admin.html')

@app.route('/client')
@login_required
def client_panel():
    return render_template('client.html')

@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    app_logger.info(f"Incoming request method: {request.method}")
    if request.method != 'POST':
        app_logger.error(f"Method not allowed: {request.method}")
        return jsonify({"error": "Method not allowed"}), 405
    app_logger.info(f"login: JWT_SECRET_KEY set: {app.config['JWT_SECRET_KEY']}")
    return login_function(app.config['JWT_SECRET_KEY'], app.config['JWT_ACCESS_TOKEN_EXPIRES'], app.config['JWT_REFRESH_TOKEN_EXPIRES'])

@app.route('/create-checkout-session', methods=['POST'])
@cross_origin()
@jwt_required()
def create_checkout_session():
    return create_checkout_session_function()

@measure_time
@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    return stripe_webhook_function()

def get_credits_to_deduct(payload):
    # Default deduction amount
    credits_to_deduct = 1

    # Log the incoming payload
    app_logger.debug(f"Received payload: {payload}")

    # Check for the 'usecase' tag in the payload
    usecase = payload.get('usecase', '').lower()
    app_logger.debug(f"Usecase identified: {usecase}")

    if usecase == 'sync':
        # Call the Klaviyo function to get the number of profiles matching the criteria
        phone_number = "+18329908088"
        app_logger.debug(f"Calling get_klaviyo_profile_count for phone number: {phone_number}")
        credits_to_deduct = get_klaviyo_profile_count(phone_number)
        app_logger.debug(f"Klaviyo profile count returned: {credits_to_deduct}")

    # Log the final credits to deduct
    app_logger.debug(f"Final credits to deduct: {credits_to_deduct}")

    return credits_to_deduct

import csv

import os
import re
import csv
import json
from flask import jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

@app.route('/get_members_data', methods=['GET'])
@jwt_required()
def get_members_data():
    username = get_jwt_identity()
    redis_key = f"members_{username}"
    redis_client = get_redis_client()

    # Define the directory and filename pattern
    directory_path = f"/home/bryananthonyobrien/mysite/data/community/members/{username}"
    filename_pattern = re.compile(r'^members\.(\d{4})_(\d{1,2})_(\d{1,2})\.csv$')

    # Attempt to retrieve the latest file name
    latest_file = "N/A"
    if os.path.exists(directory_path):
        files = [
            f for f in os.listdir(directory_path) if filename_pattern.match(f)
        ]
        if files:
            files.sort(key=lambda x: list(map(int, filename_pattern.match(x).groups())), reverse=True)
            latest_file = files[0]
    else:
        # If the directory does not exist, return 'N/A' for each metric
        return jsonify({
            'msg': 'Directory not found',
            'total_members': 'N/A',
            'members_with_phone': 'N/A',
            'members_deleted': 'N/A',
            'members_live': 'N/A',
            'members_opt_out': 'N/A',
            'members_total': 'N/A',
            'file_name': latest_file,
            'members_loaded_in_redis': False
        }), 200

    # Check if Redis key exists for enabling/disabling buttons
    members_loaded_in_redis = redis_client.exists(redis_key)

    # Initialize metrics
    members_data = {}
    phone_number_count = 0
    members_deleted = 0
    members_live = 0
    members_opt_out = 0

    # Process the latest CSV file if available
    if latest_file != "N/A":
        file_path = os.path.join(directory_path, latest_file)
        try:
            with open(file_path, mode='r') as csvfile:
                csv_reader = csv.DictReader(csvfile)
                for row in csv_reader:
                    member_id = row.get("MEMBER_ID")
                    members_data[member_id] = row

                    # Count members with phone numbers
                    if row.get("PHONE_NUMBER"):
                        phone_number_count += 1

                    # Count members based on status
                    member_status = row.get("SUBSCRIPTION_STATE", "").lower()  # Assuming the SUBSCRIPTION_STATE column exists
                    if member_status == "deleted":
                        members_deleted += 1
                    elif member_status == "live":
                        members_live += 1
                    elif member_status == "opted_out":
                        members_opt_out += 1

            # Total members count
            total_members_count = len(members_data)

            # Return the full structure as requested
            return jsonify({
                'msg': 'File loaded successfully!',
                'total_members': total_members_count,
                'members_with_phone': phone_number_count,
                'members_deleted': members_deleted,
                'members_live': members_live,
                'members_opt_out': members_opt_out,
                'members_total': total_members_count,
                'file_name': latest_file,
                'members_loaded_in_redis': bool(members_loaded_in_redis),
                'members_data': members_data  # Include full members data structure
            }), 200

        except Exception as e:
            app_logger.error(f"Error loading file for user {username}: {str(e)}")
            return jsonify({'msg': 'Internal Server Error'}), 500
    else:
        # If no files match the pattern, return 'N/A' for each metric
        return jsonify({
            'msg': 'No data found',
            'total_members': 'N/A',
            'members_with_phone': 'N/A',
            'members_deleted': 'N/A',
            'members_live': 'N/A',
            'members_opt_out': 'N/A',
            'members_total': 'N/A',
            'file_name': latest_file,
            'members_loaded_in_redis': False,
            'members_data': {}  # Return an empty structure if no data is found
        }), 200

@app.route('/get_members_data_from_file_remove', methods=['GET'])
@jwt_required()
def get_members_data_from_file_remove():
    username = get_jwt_identity()
    directory_path = f"/home/bryananthonyobrien/mysite/data/community/members/{username}"

    # Check if the directory exists
    if not os.path.exists(directory_path):
        # Return 'N/A' for each metric if the directory does not exist
        return jsonify({
            'msg': 'Directory not found',
            'total_members': 'N/A',
            'members_with_phone': 'N/A',
            'members_deleted': 'N/A',
            'members_live': 'N/A',
            'members_opt_out': 'N/A',
            'members_total': 'N/A',
            'file_name': 'N/A'
        }), 200

    # Define the filename pattern for the files
    filename_pattern = re.compile(r'^members\.(\d{4})_(\d{1,2})_(\d{1,2})\.csv$')

    # Find all files in the directory matching the pattern and get the most recent one
    files = [
        f for f in os.listdir(directory_path)
        if filename_pattern.match(f)
    ]

    if not files:
        # Return 'N/A' for each metric if no files match the pattern
        return jsonify({
            'msg': 'No data found',
            'total_members': 'N/A',
            'members_with_phone': 'N/A',
            'members_deleted': 'N/A',
            'members_live': 'N/A',
            'members_opt_out': 'N/A',
            'members_total': 'N/A',
            'file_name': 'N/A'
        }), 200

    # Sort files by date extracted from filename (YYYY_MM_DD) and get the latest
    files.sort(key=lambda x: list(map(int, filename_pattern.match(x).groups())), reverse=True)
    latest_file = files[0]
    file_path = os.path.join(directory_path, latest_file)

    # Initialize metrics
    members_data = {}
    phone_number_count = 0
    members_deleted = 0
    members_live = 0
    members_opt_out = 0

    # Process the CSV file
    try:
        with open(file_path, mode='r') as csvfile:
            csv_reader = csv.DictReader(csvfile)
            for row in csv_reader:
                member_id = row.get("MEMBER_ID")
                members_data[member_id] = row  # Keep track of all rows in memory if needed

                # Count members with phone numbers
                if row.get("PHONE_NUMBER"):
                    phone_number_count += 1

                # Count members based on status
                member_status = row.get("SUBSCRIPTION_STATE", "").lower()  # Assuming the SUBSCRIPTION_STATE column exists
                if member_status == "deleted":
                    members_deleted += 1
                elif member_status == "live":
                    members_live += 1
                elif member_status == "opted_out":
                    members_opt_out += 1

        # Total members count
        total_members_count = len(members_data)

        return jsonify({
            'msg': 'File loaded successfully!',
            'total_members': total_members_count,
            'members_with_phone': phone_number_count,
            'members_deleted': members_deleted,
            'members_live': members_live,
            'members_opt_out': members_opt_out,
            'members_total': total_members_count,
            'file_name': latest_file
        }), 200

    except Exception as e:
        app_logger.error(f"Error loading file for user {username}: {str(e)}")
        return jsonify({'msg': 'Internal Server Error'}), 500

@app.route('/upload_community_communities_file', methods=['POST'])
@jwt_required()
def upload_community_communities_file():
    app_logger.info("upload_community_communities_file entered")

    # Get the current user's identity (username) from the JWT
    username = get_jwt_identity()

    # Check if the file is part of the request
    if 'file' not in request.files:
        return jsonify({'msg': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'msg': 'No selected file'}), 400

    # Get the directory path from the request form data
    directory_path = request.form.get('directoryPath')

    if not directory_path:
        return jsonify({'msg': 'Directory path is required'}), 400

    # Log the input parameters
    app_logger.info(f"User {username} is attempting to upload a file: {file.filename} to directory: {directory_path}")

    # Create the directory if it does not exist
    os.makedirs(directory_path, exist_ok=True)

    # Save the file
    try:
        file_path = os.path.join(directory_path, file.filename)
        file.save(file_path)

        app_logger.info(f"File saved successfully by {username}: {file_path}")

        # Read the CSV file and prepare the data structure for Redis
        community_data = []
        total_community_count = 0

        with open(file_path, mode='r') as csvfile:
            csv_reader = csv.DictReader(csvfile)
            for row in csv_reader:
                # Collect each community's data
                community = {
                    "ID": row.get("COMMUNITY_ID", ""),
                    "Name": row.get("COMMUNITY_NAME", ""),
                    "Count": int(row.get("MEMBER_COUNT", 0))
                }
                community_data.append(community)
                total_community_count += 1

        # Store the communities data in Redis, overwriting any previous data
        redis_client = get_redis_client()
        redis_key = f"communities_{username}"
        redis_client.delete(redis_key)  # Clear previous data if any

        try:
            # Store each community in Redis
            for community in community_data:
                redis_client.hset(redis_key, community["ID"], json.dumps(community))

            # Store metadata in Redis
            redis_client.hset(redis_key, "total_community_count", total_community_count)
            redis_client.hset(redis_key, "file_name", file.filename)
            communities_loaded_in_redis = True
        except Exception as redis_error:
            app_logger.error(f"Error storing data in Redis for {username}: {str(redis_error)}")
            communities_loaded_in_redis = False

        # Log the total count
        app_logger.info(f"User {username} uploaded {total_community_count} communities.")

        # Prepare the response payload
        response_payload = {
            'msg': 'File uploaded successfully!',
            'file_name': file.filename,
            'total_community_count': total_community_count,
            'communities_loaded_in_redis': communities_loaded_in_redis,
            'community_data': community_data  # Include the full communities data
        }

        return jsonify(response_payload), 200
    except Exception as e:
        app_logger.error(f"Error saving file by {username}: {str(e)}")
        return jsonify({'msg': 'Internal Server Error'}), 500  # General message for security


@app.route('/upload_community_members_file', methods=['POST'])
@jwt_required()
def upload_community_members_file():
    app_logger.info("upload_community_members_file entered")
    # Get the current user's identity (username) from the JWT
    username = get_jwt_identity()

    # Check if the file is part of the request
    if 'file' not in request.files:
        return jsonify({'msg': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'msg': 'No selected file'}), 400

    # Get the directory path from the request form data
    directory_path = request.form.get('directoryPath')

    if not directory_path:
        return jsonify({'msg': 'Directory path is required'}), 400

    # Log the input parameters
    app_logger.info(f"User {username} is attempting to upload a file: {file.filename} to directory: {directory_path}")

    # Create the directory if it does not exist
    os.makedirs(directory_path, exist_ok=True)

    # Save the file
    try:
        file_path = os.path.join(directory_path, file.filename)
        file.save(file_path)

        app_logger.info(f"File saved successfully by {username}: {file_path}")

        # Read the CSV file and prepare the data structure for Redis
        members_data = {}
        phone_number_count = 0
        members_deleted = 0
        members_live = 0
        members_opt_out = 0

        with open(file_path, mode='r') as csvfile:
            csv_reader = csv.DictReader(csvfile)
            for row in csv_reader:
                # Store each member as a dictionary
                member_id = row.get("MEMBER_ID")  # Using MEMBER_ID as the unique key for storage
                members_data[member_id] = {
                    "MEMBER_ID": member_id,
                    "LEADER_ID": row.get("LEADER_ID", ""),
                    "CHANNEL": row.get("CHANNEL", ""),
                    "PHONE_NUMBER": row.get("PHONE_NUMBER", ""),
                    "SUBSCRIPTION_STATE": row.get("SUBSCRIPTION_STATE", "").lower(),
                    "FIRST_NAME": row.get("FIRST_NAME", ""),
                    "LAST_NAME": row.get("LAST_NAME", ""),
                    "EMAIL": row.get("EMAIL", ""),
                    "DATE_OF_BIRTH": row.get("DATE_OF_BIRTH", ""),
                    "GENDER": row.get("GENDER", ""),
                    "CITY": row.get("CITY", ""),
                    "ZIP_CODE": row.get("ZIP_CODE", ""),
                    "STATE": row.get("STATE", ""),
                    "STATE_CODE": row.get("STATE_CODE", ""),
                    "COUNTRY": row.get("COUNTRY", ""),
                    "COUNTRY_CODE": row.get("COUNTRY_CODE", ""),
                    "DEVICE_TYPE": row.get("DEVICE_TYPE", ""),
                    "FIRST_ACTIVATED_AT": row.get("FIRST_ACTIVATED_AT", ""),
                }

                # Count members with phone numbers
                if row.get("PHONE_NUMBER"):
                    phone_number_count += 1

                # Count members based on status
                member_status = row.get("SUBSCRIPTION_STATE", "").lower()
                if member_status == "deleted":
                    members_deleted += 1
                elif member_status == "live":
                    members_live += 1
                elif member_status == "opted_out":
                    members_opt_out += 1

        # Calculate total members count
        total_members_count = len(members_data)

        # Store the members data in Redis, overwriting any previous data
        redis_client = get_redis_client()
        redis_key = f"members_{username}"  # Unique key for members data
        redis_client.delete(redis_key)  # Clear previous data if any

        # Try to store the new members data in Redis and set metadata
        try:
            redis_client.hset(redis_key, mapping={k: json.dumps(v) for k, v in members_data.items()})
            redis_client.hset(redis_key, "total_members_count", total_members_count)
            redis_client.hset(redis_key, "file_name", file.filename)
            members_loaded_in_redis = True
        except Exception as redis_error:
            app_logger.error(f"Error storing data in Redis for {username}: {str(redis_error)}")
            members_loaded_in_redis = False

        # Log the counts
        app_logger.info(f"User {username} uploaded {total_members_count} members with {phone_number_count} having a phone number.")
        app_logger.info(f"Members Status Breakdown: {members_deleted} deleted, {members_live} live, {members_opt_out} opted out.")

        # Prepare the response payload
        response_payload = {
            'msg': 'File uploaded successfully!',
            'total_members': total_members_count,
            'members_with_phone': phone_number_count,
            'members_deleted': members_deleted,
            'members_live': members_live,
            'members_opt_out': members_opt_out,
            'members_total': total_members_count,
            'file_name': file.filename,
            'members_loaded_in_redis': members_loaded_in_redis,
            'members_data': members_data  # Include the full members data
        }

        return jsonify(response_payload), 200
    except Exception as e:
        app_logger.error(f"Error saving file by {username}: {str(e)}")
        return jsonify({'msg': 'Internal Server Error'}), 500  # General message for security

@app.route('/upload_memberships_file', methods=['POST'])
@jwt_required()
def upload_memberships_file():
    app_logger.info(f"/upload_memberships_file: {request}")

    username = get_jwt_identity()

    if 'file' not in request.files:
        return jsonify({'msg': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'msg': 'No selected file'}), 400

    directory_path = request.form.get('directoryPath')
    if not directory_path:
        return jsonify({'msg': 'Directory path is required'}), 400

    app_logger.info(f"User {username} is attempting to upload a file: {file.filename} to directory: {directory_path}")

    os.makedirs(directory_path, exist_ok=True)

    try:
        file_path = os.path.join(directory_path, file.filename)
        file.save(file_path)
    except Exception as e:
        app_logger.error(f"file failure: {e}")
        return jsonify({'msg': 'Error saving file'}), 500

    membership_data = defaultdict(lambda: {
        "COMMUNITY_NAME": "",
        "members": [],
        "member_count": 0,
        "oldest_joined_at": None,
        "most_recent_joined_at": None,
        "daily_join_counters": []
    })

    try:
        with open(file_path, mode='r') as csvfile:
            csv_reader = csv.DictReader(csvfile)
            for row in csv_reader:
                community_id = row.get("COMMUNITY_ID")
                community_name = row.get("COMMUNITY_NAME")
                joined_at_str = row.get("JOINED_AT")
                if community_id and joined_at_str:
                    joined_at = parser.isoparse(joined_at_str)
                    member_info = {"MEMBER_ID": row["MEMBER_ID"], "JOINED_AT": joined_at_str}
                    community = membership_data[community_id]

                    if not community["COMMUNITY_NAME"]:
                        community["COMMUNITY_NAME"] = community_name

                    community["members"].append(member_info)
                    community["member_count"] += 1

                    if community["oldest_joined_at"] is None or joined_at < community["oldest_joined_at"]:
                        community["oldest_joined_at"] = joined_at
                    if community["most_recent_joined_at"] is None or joined_at > community["most_recent_joined_at"]:
                        community["most_recent_joined_at"] = joined_at

        for community_id, data in membership_data.items():
            oldest = data["oldest_joined_at"]
            most_recent = data["most_recent_joined_at"]

            data["days_since_last_member_joined"] = (datetime.now(timezone.utc) - most_recent).days

            date_range = (most_recent - oldest).days + 1
            daily_counters = [0] * date_range

            for member in data["members"]:
                joined_date = parser.isoparse(member["JOINED_AT"])
                day_index = (joined_date - oldest).days
                daily_counters[day_index] += 1

            data["daily_join_counters"] = [{"date": (oldest + timedelta(days=i)).isoformat(), "count": count}
                                           for i, count in enumerate(daily_counters) if count > 0]

            data["oldest_joined_at"] = oldest.isoformat()
            data["most_recent_joined_at"] = most_recent.isoformat()

        redis_client = get_redis_client()
        redis_key = f"memberships_{username}"
        redis_client.delete(redis_key)  # Clear previous data if any

        # Store membership data and metadata in Redis
        redis_client.hset(redis_key, mapping={k: json.dumps(v) for k, v in membership_data.items()})
        redis_client.hset(redis_key, "total_membership_count", sum(data["member_count"] for data in membership_data.values()))
        redis_client.hset(redis_key, "file_name", file.filename)

        response_payload = {
            'msg': 'Memberships file uploaded successfully!',
            'total_membership_count': sum(data["member_count"] for data in membership_data.values()),
            'file_name': file.filename,
            'memberships_loaded_in_redis': True,
            'membership_data': membership_data
        }

        return jsonify(response_payload), 200
    except Exception as e:
        app_logger.error(f"Error processing memberships file: {str(e)}")
        return jsonify({'msg': 'Error processing file'}), 500

@app.route('/get_community_data', methods=['GET'])
@jwt_required()
def get_community_data():
    # Get the current user's identity (username) from the JWT
    username = get_jwt_identity()

    # Retrieve the data type from the query parameter
    data_type = request.args.get("data")
    if not data_type:
        return jsonify({'msg': 'Data type not specified'}), 400  # Bad Request if no data type provided

    app_logger.info(f"/get_community_data called for user: {username} and data type: {data_type}")

    # Define the Redis key dynamically based on the data type and username
    redis_key = f"{data_type}_{username}"

    # Initialize the Redis client
    redis_client = get_redis_client()

    try:
        # Check the Redis type of the key before fetching
        key_type = redis_client.type(redis_key).decode('utf-8')
        app_logger.info(f"Redis key type for {redis_key}: {key_type}")

        # Handle 'memberships' data type as a hash
        if data_type == 'memberships':
            if key_type == 'hash':
                # Fetch as hash
                data = redis_client.hgetall(redis_key)
                if not data:
                    app_logger.info(f"{data_type}_{username} not found - returning empty response.")
                    return jsonify({f'{data_type}_data': None}), 200

                # Extract metadata fields if they exist
                file_name = data.get(b"file_name").decode('utf-8') if b"file_name" in data else None
                total_membership_count = data.get(b"total_membership_count").decode('utf-8') if b"total_membership_count" in data else None

                # Extract membership data, excluding metadata fields
                membership_data = {
                    key.decode('utf-8'): json.loads(value.decode('utf-8'))
                    for key, value in data.items() if key not in {b"file_name", b"total_membership_count"}
                }

                # Prepare response payload including metadata
                data = {
                    'file_name': file_name,
                    'total_membership_count': total_membership_count,
                    'membership_data': membership_data
                }
            else:
                app_logger.info(f"{data_type}_{username} not found or not of type 'hash' - returning empty response.")
                return jsonify({f'{data_type}_data': None}), 200

        # Handle other data types assumed to be 'hash'
        else:
            if key_type == 'hash':
                # Fetch as hash
                data = redis_client.hgetall(redis_key)
                if not data:
                    app_logger.info(f"{data_type}_{username} not found - returning empty response.")
                    return jsonify({f'{data_type}_data': None}), 200

                # Extract metadata fields if they exist
                file_name = data.get(b"file_name").decode('utf-8') if b"file_name" in data else None
                total_community_count = data.get(b"total_community_count").decode('utf-8') if b"total_community_count" in data else None

                # Extract community data, excluding metadata fields
                community_data = {
                    key.decode('utf-8'): json.loads(value.decode('utf-8'))
                    for key, value in data.items() if key not in {b"file_name", b"total_community_count"}
                }

                # Prepare response payload including metadata
                data = {
                    'file_name': file_name,
                    'total_community_count': total_community_count,
                    'community_data': community_data
                }
            else:
                app_logger.info(f"{data_type}_{username} not found or not of type 'hash' - returning empty response.")
                return jsonify({f'{data_type}_data': None}), 200

        # Prepare the response payload
        response_payload = {
            f'{data_type}_data': data
        }

        # Pretty log the response payload
        # pretty_payload = json.dumps(response_payload, indent=4)
        # app_logger.info(f"{data_type}_{username} response payload:\n{pretty_payload}")

        # Return the data as JSON
        return jsonify(response_payload), 200

    except Exception as e:
        app_logger.error(f"Error fetching {data_type} data for {username}: {str(e)}")
        return jsonify({'msg': f'Failed to retrieve {data_type} data'}), 500

@app.route('/unload_community_data', methods=['POST'])
@jwt_required()
def unload_community_data():
    # Get the current user's identity (username) from the JWT
    username = get_jwt_identity()

    # Retrieve the data type from the request body
    data = request.json.get("data")
    if not data:
        return jsonify({'msg': 'Data type not specified'}), 400  # Bad Request if no data type provided

    app_logger.info(f"/unload_community_data called for user: {username} and data type: {data}")

    # Define the Redis key dynamically based on the data type and username
    redis_key = f"{data}_{username}"

    # Initialize the Redis client
    redis_client = get_redis_client()

    try:
        # Delete the Redis data associated with the key
        redis_client.delete(redis_key)

        app_logger.info(f"Redis data unloaded successfully for user: {username} and data type: {data}")

        # Return a success message
        return jsonify({'msg': f'{data} data unloaded successfully!'}), 200
    except Exception as e:
        app_logger.error(f"Error unloading Redis data for {username} and data type: {data}: {str(e)}")
        return jsonify({'msg': f'Failed to unload {data} data'}), 500  # General error message

@measure_time
@app.route('/redis_status', methods=['GET'])
def redis_status():
    try:
        # Log the attempt to check Redis status
        app_logger.info("Checking Redis status...")

        # Get Redis client and perform a simple ping to check connectivity
        redis_client = get_redis_client()
        redis_client.ping()  # PING command to verify Redis connectivity

        # Log successful ping
        app_logger.info("Redis is reachable.")

        # Fetch memory statistics using Redis INFO command
        memory_info = redis_client.info('memory')

        # Log the memory info for debugging
        app_logger.info("Redis memory info: %s", memory_info)

        # Prepare the response with memory stats
        response = {
            'status': 'OK',
            'used_memory': memory_info.get('used_memory'),
            'used_memory_human': memory_info.get('used_memory_human'),
        }

        # Return the JSON response with memory stats
        return jsonify(response), 200

    except Exception as e:
        # Log the error
        app_logger.error("Error connecting to Redis: %s", str(e))
        return jsonify({'status': 'BAD', 'error': str(e)}), 500


# Paths to JSON files
json_file_path = "/home/bryananthonyobrien/logs/community_member_events.json"
json_file_path_outbound_messages = "/home/bryananthonyobrien/logs/community_outbound_message_events.json"
json_file_path_inbound_messages = "/home/bryananthonyobrien/logs/community_inbound_message_events.json"

# Ensure the logs directory exists
os.makedirs(os.path.dirname(json_file_path), exist_ok=True)

@app.route('/webhook_receiver_outbound_messages', methods=['POST'])
def webhook_receiver_outbound_messages():
    # Try to parse JSON data or fallback to form data
    data = request.get_json(silent=True) or request.form.to_dict()
    app_logger.info(f"webhook_receiver_outbound_messages: Received data: {data}")

    # Attempt to extract client_id from the correct location in the payload
    client_id = data.get("data", {}).get("object", {}).get("member", {}).get("client_id")
    if not client_id:
        app_logger.info("client_id not found in payload. Continuing without client_id.")

    try:
        # Save the data to a JSON file (appending)
        try:
            with open(json_file_path_outbound_messages, "a") as json_file:
                json_file.write(json.dumps(data) + "\n")
        except Exception as file_error:
            app_logger.info(f"Error writing to JSON file: {file_error}")

        # If client_id is present, store event in Redis
        if client_id:
            redis_client = get_redis_client()
            redis_key = f"community_outbound_message_events_{client_id}"
            redis_client.rpush(redis_key, json.dumps(data))
            app_logger.info(f"Outbound Message Event data for client_id {client_id} appended to Redis list '{redis_key}'.")
        else:
            app_logger.info("Event processed without client_id, data saved to file only.")

        return jsonify({"message": "Outbound Message Event received and processed"}), 200

    except Exception as e:
        app_logger.info(f"Error processing webhook: {str(e)}")
        return jsonify({"error": "Failed to process event"}), 500


@app.route('/webhook_receiver_inbound_messages', methods=['POST'])
def webhook_receiver_inbound_messages():
    # Try to parse JSON data or fallback to form data
    data = request.get_json(silent=True) or request.form.to_dict()
    app_logger.info(f"webhook_receiver_inbound_messages: Received data: {data}")

    # Attempt to extract client_id from the correct location in the payload
    client_id = data.get("data", {}).get("object", {}).get("member", {}).get("client_id")
    if not client_id:
        app_logger.info("client_id not found in payload. Continuing without client_id.")

    try:
        # Save the data to a JSON file (appending)
        try:
            with open(json_file_path_inbound_messages, "a") as json_file:
                json_file.write(json.dumps(data) + "\n")
        except Exception as file_error:
            app_logger.info(f"Error writing to JSON file: {file_error}")

        # If client_id is present, store event in Redis
        if client_id:
            redis_client = get_redis_client()
            redis_key = f"community_inbound_message_events_{client_id}"
            redis_client.rpush(redis_key, json.dumps(data))
            app_logger.info(f"Inbound Message Event data for client_id {client_id} appended to Redis list '{redis_key}'.")
        else:
            app_logger.info("Event processed without client_id, data saved to file only.")

        return jsonify({"message": "Inbound Message Event received and processed"}), 200

    except Exception as e:
        app_logger.info(f"Error processing webhook: {str(e)}")
        return jsonify({"error": "Failed to process event"}), 500

@app.route('/webhook_receiver', methods=['POST'])
def webhook_receiver():
    # Determine if data is JSON or form data
    data = request.get_json(silent=True) or request.form.to_dict()
    app_logger.info(f"webhook_receiver: {data}")

    # Extract client_id from the payload
    client_id = data.get("data", {}).get("object", {}).get("client_id")
    if not client_id:
        app_logger.info("client_id not found in payload")
        return jsonify({"error": "client_id missing from payload"}), 200

    app_logger.info(f"Webhook event received for client_id: {client_id}")

    try:
        # Save the data to a JSON file (appending)
        try:
            with open(json_file_path, "a") as json_file:
                json_file.write(json.dumps(data) + "\n")
        except Exception as file_error:
            app.logger.error(f"Error writing to JSON file for client_id {client_id}: {file_error}")

        # Store the event in Redis for the specific client_id
        redis_client = get_redis_client()
        redis_key = f"community_member_events_{client_id}"
        redis_client.rpush(redis_key, json.dumps(data))
        app_logger.info(f"Member Event data for client_id {client_id} appended to Redis list '{redis_key}'.")

        return jsonify({"message": "Member Event received and processed"}), 200

    except Exception as e:
        app.logger.error(f"Error processing webhook for client_id {client_id}: {str(e)}")
        return jsonify({"error": "Failed to process event"}), 500

@app.route('/get_events/<client_id>', methods=['GET'])
def get_events(client_id):
    try:
        # Retrieve events for the specified client_id
        redis_client = get_redis_client()

        # Define the Redis keys for the 3 structures
        redis_keys = {
            "member_events": f"community_member_events_{client_id}",
            "inbound_messages": f"community_inbound_message_events_{client_id}",
            "outbound_messages": f"community_outbound_message_events_{client_id}"
        }

        results = {}

        for key_name, redis_key in redis_keys.items():
            # Fetch all entries in the Redis list
            data = redis_client.lrange(redis_key, 0, -1)  # Retrieve all entries

            # Get the number of events
            num_events = len(data)

            # Estimate memory usage (if MEMORY USAGE is supported)
            memory_usage = redis_client.memory_usage(redis_key) or 0

            # Convert to JSON and log only the first event
            events = [json.loads(event) for event in data]
            first_event = events[0] if events else None  # Get the first event or None if empty

            # Log details, including the first event
            app_logger.info(f"get_events: {client_id} - {key_name} - Number of events: {num_events}, Memory used: {memory_usage} bytes")
            if first_event:
                app_logger.info(f"First event for {key_name}:\n" + json.dumps(first_event, indent=4))

            # Store the results for this key
            results[key_name] = {
                "events": events,
                "num_events": num_events,
                "memory_usage_bytes": memory_usage
            }

        # Prepare the response data
        response_data = {
            "client_id": client_id,
            "results": results
        }

        # Log the response in a pretty JSON format
        app_logger.info("Response JSON (with truncated events):\n" + json.dumps({
            "client_id": client_id,
            "results": {key: {**value, "events": value["events"][:1]} for key, value in results.items()}
        }, indent=4))

        # Return the response
        return jsonify(response_data), 200

    except Exception as e:
        app_logger.error(f"Error in get_events: {str(e)}")
        return jsonify({"error": "Failed to retrieve events"}), 500

@app.route('/get_events_old/<client_id>', methods=['GET'])
def get_events_old(client_id):
    try:
        # Retrieve events for the specified client_id
        redis_client = get_redis_client()
        redis_key = f"community_member_events_{client_id}"
        data = redis_client.lrange(redis_key, 0, -1)  # Fetch all entries in the list

        # Get the number of events
        num_events = len(data)

        # Estimate memory usage (if MEMORY USAGE is supported)
        memory_usage = redis_client.memory_usage(redis_key) or 0

        # Log details
        app_logger.info(f"get_events: {client_id} - Number of events: {num_events}, Memory used: {memory_usage} bytes")

        # Convert to JSON
        events = [json.loads(event) for event in data]

        # Return JSON response including metrics
        return jsonify({
            "client_id": client_id,
            "events": events,
            "num_events": num_events,
            "memory_usage_bytes": memory_usage
        }), 200
    except Exception as e:
        app_logger.error(f"Error in get_events: {str(e)}")
        return jsonify({"error": "Failed to retrieve events"}), 500

@app.route('/load_events_from_file/<client_id>', methods=['POST'])
def load_events_from_file(client_id):
    json_file_path = "/home/bryananthonyobrien/logs/community_member_events.json"
    redis_client = get_redis_client()
    added_records = 0
    skipped_records = 0

    try:
        # Define Redis keys
        redis_key = f"community_member_events_{client_id}"
        redis_id_set_key = f"{redis_key}_ids"

        # Clear existing data in Redis
        redis_client.delete(redis_key)
        redis_client.delete(redis_id_set_key)
        app_logger.info(f"Cleared existing data for client_id {client_id} from Redis")

        # Load all existing IDs into memory (after clearing, this should be empty)
        existing_ids = set()
        app_logger.info(f"Loaded {len(existing_ids)} existing event IDs from Redis for client_id {client_id}")

        # Initialize batch processing
        pipeline = redis_client.pipeline()

        # Read the JSON file in chunks
        with open(json_file_path, "r") as json_file:
            batch = []
            batch_size = 1000  # Process 1000 lines at a time
            processed_lines = 0

            for line in json_file:
                processed_lines += 1
                try:
                    # Parse each line into a JSON object
                    data = json.loads(line.strip())
                    event_client_id = data.get("data", {}).get("object", {}).get("client_id")
                    event_id = data.get("id")  # Extract unique event ID

                    # Skip if client_id does not match or if required fields are missing
                    if event_client_id != client_id or not event_id:
                        continue

                    # Check if the event ID already exists in memory
                    if event_id in existing_ids:
                        skipped_records += 1
                        continue

                    # Add event to the batch
                    batch.append((event_id, data))
                    existing_ids.add(event_id)  # Add to the in-memory set immediately

                    # If batch size is reached, process it
                    if len(batch) >= batch_size:
                        for event_id, event_data in batch:
                            pipeline.rpush(redis_key, json.dumps(event_data))
                            pipeline.sadd(redis_id_set_key, event_id)
                        pipeline.execute()  # Execute batch
                        added_records += len(batch)
                        batch = []  # Clear the batch

                    # Log progress every 1000 lines
                    if processed_lines % 1000 == 0:
                        app_logger.info(f"Processed {processed_lines} lines. Added: {added_records}, Skipped: {skipped_records}")

                except json.JSONDecodeError as e:
                    app_logger.error(f"Error decoding JSON line: {line}. Error: {str(e)}")
                    continue

            # Process any remaining events in the batch
            if batch:
                for event_id, event_data in batch:
                    pipeline.rpush(redis_key, json.dumps(event_data))
                    pipeline.sadd(redis_id_set_key, event_id)
                pipeline.execute()
                added_records += len(batch)

            # Calculate memory usage for the Redis key
            memory_usage = redis_client.memory_usage(redis_key) or 0

            app_logger.info(f"Processing complete for client_id {client_id}. Added: {added_records}, Skipped: {skipped_records}, Memory used: {memory_usage} bytes")

        return jsonify({
            "message": f"File processed for client_id {client_id}",
            "added_records": added_records,
            "skipped_records": skipped_records,
            "memory_usage": memory_usage  # Include memory usage in response
        }), 200

    except Exception as e:
        app_logger.error(f"Error loading events from file for client_id {client_id}: {str(e)}")
        return jsonify({"error": "Failed to process the file"}), 500

@app.route('/load_all_events_from_files/<client_id>', methods=['POST'])
def load_all_events_from_files(client_id):
    # Define file paths and Redis key prefixes for all event types
    event_types = {
        "member_events": {
            "file_path": "/home/bryananthonyobrien/logs/community_member_events.json",
            "redis_key_prefix": "community_member_events",
            "client_id_path": lambda data: data.get("data", {}).get("object", {}).get("client_id")  # Member events structure
        },
        "inbound_messages": {
            "file_path": "/home/bryananthonyobrien/logs/community_inbound_message_events.json",
            "redis_key_prefix": "community_inbound_message_events",
            "client_id_path": lambda data: data.get("data", {}).get("object", {}).get("member", {}).get("client_id")  # Inbound messages structure
        },
        "outbound_messages": {
            "file_path": "/home/bryananthonyobrien/logs/community_outbound_message_events.json",
            "redis_key_prefix": "community_outbound_message_events",
            "client_id_path": lambda data: data.get("data", {}).get("object", {}).get("member", {}).get("client_id")  # Outbound messages structure
        }
    }

    redis_client = get_redis_client()
    results = {}

    try:
        for event_type, config in event_types.items():
            file_path = config["file_path"]
            redis_key = f"{config['redis_key_prefix']}_{client_id}"
            redis_id_set_key = f"{redis_key}_ids"
            get_client_id = config["client_id_path"]

            added_records = 0
            skipped_records = 0

            # Clear existing data in Redis
            redis_client.delete(redis_key)
            redis_client.delete(redis_id_set_key)
            app_logger.info(f"Cleared existing data for client_id {client_id} from Redis for {event_type}")

            # Initialize batch processing
            pipeline = redis_client.pipeline()

            # Read the JSON file in chunks
            with open(file_path, "r") as json_file:
                batch = []
                batch_size = 1000  # Process 1000 lines at a time
                processed_lines = 0

                for line in json_file:
                    processed_lines += 1
                    try:
                        # Parse each line into a JSON object
                        data = json.loads(line.strip())
                        event_client_id = get_client_id(data)  # Use the appropriate path for each event type
                        event_id = data.get("id")  # Extract unique event ID

                        # Skip if client_id does not match or if required fields are missing
                        if event_client_id != client_id or not event_id:
                            continue

                        # Add event to the batch
                        batch.append((event_id, data))

                        # If batch size is reached, process it
                        if len(batch) >= batch_size:
                            for event_id, event_data in batch:
                                pipeline.rpush(redis_key, json.dumps(event_data))
                                pipeline.sadd(redis_id_set_key, event_id)
                            pipeline.execute()  # Execute batch
                            added_records += len(batch)
                            batch = []  # Clear the batch

                        # Log progress every 1000 lines
                        if processed_lines % 1000 == 0:
                            app_logger.info(f"Processed {processed_lines} lines for {event_type}. Added: {added_records}, Skipped: {skipped_records}")

                    except json.JSONDecodeError as e:
                        app_logger.error(f"Error decoding JSON line: {line}. Error: {str(e)}")
                        continue

                # Process any remaining events in the batch
                if batch:
                    for event_id, event_data in batch:
                        pipeline.rpush(redis_key, json.dumps(event_data))
                        pipeline.sadd(redis_id_set_key, event_id)
                    pipeline.execute()
                    added_records += len(batch)

                # Calculate memory usage for the Redis key
                memory_usage = redis_client.memory_usage(redis_key) or 0

                app_logger.info(f"Processing complete for client_id {client_id} and {event_type}. Added: {added_records}, Skipped: {skipped_records}, Memory used: {memory_usage} bytes")

            results[event_type] = {
                "added_records": added_records,
                "skipped_records": skipped_records,
                "memory_usage": memory_usage
            }

        # Create the response object
        response_data = {
            "message": f"Files processed for client_id {client_id}",
            "results": results
        }

        # Log the response in a pretty JSON format
        app_logger.info("Response JSON:\n" + json.dumps(response_data, indent=4))

        # Return the response
        return jsonify(response_data), 200

    except Exception as e:
        app_logger.error(f"Error loading events from files for client_id {client_id}: {str(e)}")
        return jsonify({"error": "Failed to process the files"}), 500

@app.route('/clear_events/<client_id>', methods=['DELETE'])
def clear_events(client_id):
    try:
        # Get the Redis client
        redis_client = get_redis_client()

        # Define Redis key prefixes for the three event types
        event_types = ["community_member_events", "community_inbound_message_events", "community_outbound_message_events"]

        # Track whether any keys were deleted
        any_keys_deleted = False

        # Loop through each event type to clear keys
        for event_type in event_types:
            redis_key = f"{event_type}_{client_id}"
            redis_id_set_key = f"{redis_key}_ids"

            # Delete the Redis key and its associated ID set
            events_deleted = redis_client.delete(redis_key)
            ids_deleted = redis_client.delete(redis_id_set_key)

            # Log the result
            if events_deleted or ids_deleted:
                app_logger.info(f"Cleared {event_type} for client_id: {client_id}")
                any_keys_deleted = True

        # Provide appropriate feedback
        if any_keys_deleted:
            return jsonify({"message": "Events cleared successfully for all event types"}), 200
        else:
            # No keys existed for the client_id
            app_logger.info(f"No events found to clear for client_id: {client_id}")
            return jsonify({"message": "No events found to clear"}), 200
    except Exception as e:
        app_logger.error(f"Error in clear_events: {str(e)}")
        return jsonify({"error": "Failed to clear events"}), 500

@app.route('/delete_klaviyo_discovery', methods=['DELETE'])
@jwt_required()
def delete_klaviyo_discovery():
    app_logger.info("delete_klaviyo_discovery")

    try:
        # Get the current user's identity (username) from the JWT
        username = get_jwt_identity()
        app_logger.info(f"User identified: {username}")

        # Retrieve the file_location from the request body
        request_data = request.json
        if not request_data:
            app.logger.error("Request body is missing or not in JSON format.")
            return jsonify({'msg': 'Invalid request format. JSON expected.'}), 400

        file_location = request_data.get("file_location")
        if not file_location:
            app.logger.error("Payload missing 'file_location'. Received payload: %s", request_data)
            return jsonify({'msg': 'File location not specified'}), 400

        app_logger.info(f"Payload received: {request_data}")
        app_logger.info(f"/delete_klaviyo_discovery called for user: {username} and file location: {file_location}")

        redis_client = get_redis_client()
        redis_pattern = f"klaviyo_discoveries_{username}"
        app_logger.info(f"Looking for keys with pattern: {redis_pattern}")

        for key in redis_client.scan_iter(redis_pattern):
            try:
                entry_data = redis_client.hgetall(key)
                if entry_data:
                    for field, value in entry_data.items():
                        try:
                            entry = json.loads(value)  # Parse each field as JSON
                            redis_file_location = entry.get("file_location")
                            app_logger.info(f"Comparing request file_location: '{file_location}' with Redis file_location: '{redis_file_location}' in field '{field}'")

                            if redis_file_location == file_location:
                                redis_client.hdel(key, field)  # Delete only the matched field
                                app_logger.info(f"Deleted Redis field '{field}' in hash '{key}' for user: {username}")
                                return jsonify({'msg': 'Klaviyo discovery deleted successfully'}), 200

                        except json.JSONDecodeError as json_err:
                            app_logger.info(f"Failed to decode JSON in field '{field}' of key '{key}': {json_err}")
                            continue

            except redis.exceptions.RedisError as redis_err:
                app_logger.info(f"Redis error while processing key '{key}': {redis_err}")
                return jsonify({'msg': 'Failed to access Redis data for key processing'}), 500

        app_logger.info("No matching Klaviyo discovery found for specified file location.")
        return jsonify({'msg': 'No matching Klaviyo discovery found for the specified file location'}), 404

    except redis.exceptions.RedisError as redis_err:
        app_logger.info(f"Redis error: {redis_err}")
        return jsonify({'msg': 'Redis server error occurred'}), 500
    except json.JSONDecodeError as json_err:
        app_logger.info(f"JSON decoding error: {json_err}")
        return jsonify({'msg': 'Failed to decode JSON in request'}), 400
    except Exception as e:
        app_logger.info(f"General error in delete_klaviyo_discovery: {e}")
        return jsonify({'msg': 'An unexpected error occurred'}), 500

@app.route('/import_status', methods=['GET'])
@jwt_required()
def import_status():
    username = get_jwt_identity()

    try:
        # Get Redis client
        redis_client = get_redis_client()
        status_key = f"{username}_import_status"

        app_logger.info(f"Fetching import status from Redis with key: {status_key}")

        # Retrieve the JSON string from Redis
        import_status_data = redis_client.get(status_key)

        # Check if the data exists
        if not import_status_data:
            # No records found, set default values
            response = {
                "status": "not started",
                "processed_profiles": 0,
                "total_profiles": 0,
                "chunk_number": 0,
                "number_of_chunks": 0,
                "message": "No import process found",
                "successful_imports": 0,
                "import_started_at": 0,
                "import_ended_at": 0,
                "total_time_taken": 0,
                "more_chunks": False,
                "max_workers": 0,
                "test_mode_enabled": False,
            }
            app_logger.info(f"No import status found in Redis for user {username}, setting to 'not started'.")
        else:
            # Parse the JSON string
            import_status = json.loads(import_status_data.decode('utf-8'))

            # Construct the response using data from the parsed JSON
            response = {
                "status": import_status.get("status", "unknown"),
                "processed_profiles": import_status.get("processed_profiles", 0),
                "total_profiles": import_status.get("total_profiles", 0),
                "chunk_number": import_status.get("chunk_number", 1),
                "number_of_chunks": import_status.get("number_of_chunks", 1),
                "message": import_status.get("message", "No message"),
                "successful_imports": import_status.get("successful_imports", 0),
                "import_started_at": import_status.get("import_started_at", 0),
                "import_ended_at": import_status.get("import_ended_at", 0),
                "total_time_taken": import_status.get("total_time_taken", 0),
                "more_chunks": import_status.get("more_chunks", False),
                "max_workers": import_status.get("max_workers", 0),
                "test_mode_enabled": import_status.get("test_mode_enabled", False),
            }

        app_logger.info(f"Import status response for user {username}: {response}")

        return jsonify(response), 200

    except Exception as e:
        app_logger.error(f"Error fetching import status for user {username}: {str(e)}")
        return jsonify({"error": "Failed to retrieve import status"}), 500


@app.route('/klaviyo_status', methods=['GET'])
@jwt_required()
def klaviyo_status():
    username = get_jwt_identity()

    try:
        # Get Redis client
        redis_client = get_redis_client()
        status_key = f"klaviyo_discoveries_{username}"

        app_logger.info(f"Fetching all Redis entries with pattern: {status_key}")

        # Retrieve all entries in the hash
        all_discoveries = redis_client.hgetall(status_key)

        # Check if there are any entries in the hash
        if not all_discoveries:
            # No records found, set default values
            current_status = 'not started'
            profile_count = 0
            app_logger.info(f"No status found in Redis for user {username}, setting to 'not started'.")
        else:
            # Decode and find the most recent entry by sorting based on the timestamp in each key
            most_recent_key = max(all_discoveries.keys(), key=lambda k: k.decode('utf-8').split('_')[-1])
            most_recent_data = json.loads(all_discoveries[most_recent_key].decode('utf-8'))
            current_status = most_recent_data.get('status', 'unknown')
            profile_count = most_recent_data.get('profile_count', 0)

        # Determine button status based on current Klaviyo process status
        if current_status == 'running':
            discover_button_status = "disabled"
        elif current_status in ('complete', 'failed'):
            discover_button_status = "enabled"
        else:
            discover_button_status = "enabled"  # Default case

        # Fetch user data (e.g., credits, service count, etc.)
        user_data, cache_status = get_user_data(username)

        # Build the response object
        response = {
            "klaviyo_status": current_status,
            "credits": user_data.get('credits', 0),
            "cache_status": cache_status,
            "service_count": user_data.get('api_calls', 0),
            "user_status": user_data.get('user_status', 'active'),
            "profile_count": profile_count,
            "discover_button_status": discover_button_status,
            'message': 'Klaviyo discovery status checked successfully.'
        }

        app_logger.info(f"Klaviyo status response for user {username}: {response}")

        return jsonify(response), 200

    except Exception as e:
        app_logger.error(f"Error fetching Klaviyo status for user {username}: {str(e)}")
        return jsonify({"error": "Failed to retrieve Klaviyo status"}), 500




@app.route('/set_klaviyo_read_profile_api_key', methods=['POST'])
@jwt_required()
def set_klaviyo_read_profile_api_key():
    username = get_jwt_identity()
    app_logger.info(f"Received request to set Klaviyo Read Profile API Key for user: {username}")

    try:
        redis_client = get_redis_client()
        data = request.get_json()
        api_key = data.get('klaviyo_read_profile_api_key')

        if not api_key:
            return jsonify({"error": "Invalid Klaviyo API key value. Must be a non-empty string."}), 400

        config_key = f"configuration_{username}"
        redis_client.hset(config_key, 'KLAVIYO_READ_PROFILE_API_KEY', api_key)

        app_logger.info(f"KLAVIYO_READ_PROFILE_API_KEY for {username} set successfully.")
        return jsonify({"message": "Klaviyo API key updated successfully"}), 200

    except Exception as e:
        app_logger.error(f"Error setting Klaviyo API key for user {username}: {str(e)}")
        return jsonify({"error": "Failed to update Klaviyo API key"}), 500

@app.route('/set_sub_community', methods=['POST'])
@jwt_required()
def set_sub_community():
    username = get_jwt_identity()
    app_logger.info(f"Received request to set Sub Community for user: {username}")

    try:
        redis_client = get_redis_client()
        data = request.get_json()
        sub_community = data.get('sub_community')

        if not sub_community:
            return jsonify({"error": "Invalid Sub Community. Must be a non-empty string."}), 400

        # Update the SUB_COMMUNITY in Redis
        config_key = f"configuration_{username}"
        redis_client.hset(config_key, 'SUB_COMMUNITY', sub_community)
        app_logger.info(f"SUB_COMMUNITY for {username} set successfully.")

        # Call create_sub_community_tag to create a tag for the new sub-community
        tag_created = create_sub_community_tag(username, test_mode=False)
        if not tag_created:
            return jsonify({"error": "Failed to create sub-community tag"}), 500

        return jsonify({"message": "Sub Community updated and tag created successfully"}), 200

    except Exception as e:
        app_logger.error(f"Error setting Sub Community for user {username}: {str(e)}")
        return jsonify({"error": "Failed to update Sub Community"}), 500

@app.route('/set_community_client_id', methods=['POST'])
@jwt_required()
def set_community_client_id():
    username = get_jwt_identity()
    app_logger.info(f"Received request to set Community Client ID for user: {username}")

    try:
        redis_client = get_redis_client()
        data = request.get_json()
        client_id = data.get('community_client_id')

        if not client_id:
            return jsonify({"error": "Invalid Community Client ID. Must be a non-empty string."}), 400

        config_key = f"configuration_{username}"
        redis_client.hset(config_key, 'COMMUNITY_CLIENT_ID', client_id)

        app_logger.info(f"COMMUNITY_CLIENT_ID for {username} set successfully.")
        return jsonify({"message": "Community Client ID updated successfully"}), 200

    except Exception as e:
        app_logger.error(f"Error setting Community Client ID for user {username}: {str(e)}")
        return jsonify({"error": "Failed to update Community Client ID"}), 500

@app.route('/set_community_api_token', methods=['POST'])
@jwt_required()
def set_community_api_token():
    username = get_jwt_identity()
    app_logger.info(f"Received request to set Community API Token for user: {username}")

    try:
        redis_client = get_redis_client()
        data = request.get_json()
        api_token = data.get('community_api_token')

        if not api_token:
            return jsonify({"error": "Invalid Community API Token. Must be a non-empty string."}), 400

        config_key = f"configuration_{username}"
        redis_client.hset(config_key, 'COMMUNITY_API_TOKEN', api_token)

        app_logger.info(f"COMMUNITY_API_TOKEN for {username} set successfully.")
        return jsonify({"message": "Community API token updated successfully"}), 200

    except Exception as e:
        app_logger.error(f"Error setting Community API token for user {username}: {str(e)}")
        return jsonify({"error": "Failed to update Community API token"}), 500

@app.route('/set_max_workers', methods=['POST'])
@jwt_required()
def set_max_community_workers():
    username = get_jwt_identity()
    app_logger.info(f"Received request to set max community workers for user: {username}")

    try:
        # Get Redis client
        redis_client = get_redis_client()

        # Retrieve the data from the request body (JSON format expected)
        data = request.get_json()

        # Get the max_workers value from the request, with a default of 10 if not provided
        max_workers = data.get('max_workers', 10)

        # Ensure max_workers is an integer
        if not isinstance(max_workers, int) or max_workers <= 0:
            return jsonify({"error": "Invalid max_workers value. Must be a positive integer."}), 400

        # Store max_workers in the configuration hash
        config_key = f"configuration_{username}"
        redis_client.hset(config_key, 'max_community_workers', max_workers)

        app_logger.info(f"max_community_workers for {username} set to {max_workers} in the configuration hash.")

        # Return success response
        return jsonify({"message": "Max workers updated successfully", "max_workers": max_workers}), 200

    except Exception as e:
        app_logger.error(f"Error setting max community workers for user {username}: {str(e)}")
        return jsonify({"error": "Failed to update max workers"}), 500

@app.route('/set_test_mode', methods=['POST'])
@jwt_required()
def set_test_mode():
    username = get_jwt_identity()

    try:
        # Get Redis client
        redis_client = get_redis_client()

        # Redis key for configuration hash
        config_key = f"configuration_{username}"

        # Get the request data (assume it contains a boolean 'test_mode')
        data = request.get_json()
        test_mode_enabled = data.get('test_mode', False)

        app_logger.info(f"Setting test mode for user {username} in the configuration hash.")

        # Store test_mode_enabled in the configuration hash
        redis_client.hset(config_key, 'test_mode_enabled', '1' if test_mode_enabled else '0')

        # Log the status update
        app_logger.info(f"Test mode for user {username} set to {test_mode_enabled} in configuration hash.")

        # Return a success response
        return jsonify({"message": "Test mode updated successfully", "test_mode": test_mode_enabled}), 200

    except Exception as e:
        app_logger.error(f"Error setting test mode for user {username}: {str(e)}")
        return jsonify({"error": "Failed to update test mode"}), 500

@app.route('/get_configuration', methods=['GET'])
@jwt_required()
def get_configuration():
    username = get_jwt_identity()
    app_logger.info(f"Fetching configuration for user: {username}")

    try:
        redis_client = get_redis_client()
        config_key = f"configuration_{username}"

        # Fetch values from Redis hash
        klaviyo_api_key = redis_client.hget(config_key, 'KLAVIYO_READ_PROFILE_API_KEY') or ''
        community_client_id = redis_client.hget(config_key, 'COMMUNITY_CLIENT_ID') or ''
        community_api_token = redis_client.hget(config_key, 'COMMUNITY_API_TOKEN') or ''
        max_workers = redis_client.hget(config_key, 'max_community_workers') or ''
        sub_community = redis_client.hget(config_key, 'SUB_COMMUNITY') or ''

        # Return the configuration values as JSON
        return jsonify({
            "klaviyo_api_key": klaviyo_api_key.decode('utf-8') if klaviyo_api_key else '',
            "community_client_id": community_client_id.decode('utf-8') if community_client_id else '',
            "community_api_token": community_api_token.decode('utf-8') if community_api_token else '',
            "max_workers": int(max_workers) if max_workers else '',
            "sub_community": sub_community.decode('utf-8') if sub_community else ''
        }), 200

    except Exception as e:
        app_logger.error(f"Error fetching configuration for user {username}: {str(e)}")
        return jsonify({"error": "Failed to retrieve configuration"}), 500

@app.route('/download_directory', methods=['GET'])
@jwt_required()
def download_directory():
    directory = request.args.get('directory')

    # Check if the directory exists
    if not os.path.exists(directory):
        return abort(404, "Directory not found")

    # Archive the directory and send it as a zip file
    zip_filename = f'{os.path.basename(directory)}.zip'

    # Create a temporary zip file
    with zipfile.ZipFile(zip_filename, 'w') as zip_file:
        for foldername, subfolders, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                zip_file.write(file_path, os.path.relpath(file_path, directory))

    # Stream the zip file as the response
    def generate():
        with open(zip_filename, 'rb') as f:
            yield from f

    # Return the streaming response
    response = Response(generate(), content_type='application/zip')
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Disposition'] = f'attachment; filename={zip_filename}'

    # Clean up the zip file after sending the response
    @response.call_on_close
    def remove_file():
        try:
            os.remove(zip_filename)
        except Exception as e:
            app.logger.error(f"Error removing zip file: {e}")

    return response

from flask import jsonify, request
import requests
import json

@app.route('/create_community_list', methods=['POST'])
@jwt_required()
def create_community_list():
    username = get_jwt_identity()
    app_logger.info(f"Received request to create community list for user: {username}")

    try:
        redis_client = get_redis_client()
        api_key = fetch_klaviyo_api_key(redis_client, username)
        if not api_key:
            return jsonify({"error": "Klaviyo API key not found"}), 400

        payload_data = request.get_json()
        community_name = extract_community_name(payload_data)

        existing_list = find_existing_list(api_key, community_name)
        if existing_list:
            return jsonify(existing_list), 409

        new_list_response = create_klaviyo_list(api_key, community_name)
        if new_list_response.status_code == 201:
            response_json = new_list_response.json()
            app_logger.info(f"Community list created successfully: {json.dumps(response_json, indent=4)}")
            return jsonify(response_json), 201
        else:
            return handle_error_response(new_list_response)

    except Exception as e:
        app_logger.error(f"Error creating community list for {username}: {str(e)}")
        return jsonify({'success': False, 'msg': 'Internal Server Error'}), 500


def fetch_klaviyo_api_key(redis_client, username):
    config_key = f"configuration_{username}"
    api_key = redis_client.hget(config_key, 'KLAVIYO_READ_PROFILE_API_KEY')
    if api_key:
        return api_key.decode('utf-8')
    app_logger.info(f"Klaviyo API key not found in Redis for user {username}")
    return None


def extract_community_name(payload_data):
    community_name = payload_data.get('data', {}).get('attributes', {}).get('name', 'Default Community List')
    app_logger.info(f"Community name extracted: {community_name}")
    return community_name


def find_existing_list(api_key, community_name):
    base_url = "https://a.klaviyo.com/api/lists"
    headers = {
        'Authorization': f'Klaviyo-API-Key {api_key}',
        'Content-Type': 'application/json',
        'Revision': '2024-10-15'
    }
    all_lists = []
    params = {}  # Initial empty params

    try:
        while True:
            response = requests.get(base_url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                lists = data.get("data", [])
                all_lists.extend(lists)

                # Check if a matching list exists in the current page
                for lst in lists:
                    if lst["attributes"]["name"] == community_name:
                        app_logger.info(f"List '{community_name}' already exists with ID: {lst['id']}")
                        return lst

                # Check for a 'next' link to continue pagination
                next_page = data.get("links", {}).get("next")
                if next_page:
                    next_cursor = urllib.parse.parse_qs(urllib.parse.urlparse(next_page).query).get('page[cursor]', [None])[0]
                    if next_cursor:
                        params = {"page[cursor]": next_cursor}  # Set the cursor for the next page
                    else:
                        break  # If no cursor, exit the loop
                else:
                    break  # No 'next' link, end of pagination
            else:
                app_logger.error(f"Failed to check existing lists: {response.text}")
                return None

        # If no matching list was found after all pages
        app_logger.info(f"No matching list found for {community_name}.")
        return None
    except Exception as e:
        app_logger.error(f"Error in find_existing_list: {str(e)}")
        return None


def create_klaviyo_list(api_key, community_name):
    payload = {
        "data": {
            "type": "list",
            "attributes": {
                "name": community_name
            }
        }
    }
    app_logger.info(f"Creating new Klaviyo list with payload: {json.dumps(payload, indent=4)}")

    return requests.post(
        "https://a.klaviyo.com/api/lists",
        headers={
            'Authorization': f'Klaviyo-API-Key {api_key}',
            'Content-Type': 'application/json',
            'Revision': '2024-10-15'
        },
        json=payload
    )


def handle_error_response(response):
    error_message = response.json().get('errors', [{'detail': 'Unknown error'}])[0].get('detail', 'Unknown error') \
        if response.headers.get("Content-Type") in ["application/json", "application/vnd.api+json"] else response.text
    app_logger.error(f"Failed to create community list: {error_message}")
    return jsonify({'success': False, 'msg': error_message}), response.status_code

def set_field_with_precedence(properties, location, field_name):
    property_value = properties.get(field_name)
    location_value = location.get(field_name)

    # Validate the values and convert types if needed
    if property_value and not isinstance(property_value, str):
        app_logger.info(f"Unexpected type in properties for {field_name}: {type(property_value)} - {property_value}")
        property_value = str(property_value)
    if location_value and not isinstance(location_value, str):
        app_logger.info(f"Unexpected type in location for {field_name}: {type(location_value)} - {location_value}")
        location_value = str(location_value)

    # Log conflicts if both values are present
    # if property_value and location_value:
    #     app_logger.info(f"Both {field_name} values found - property: {property_value} and location: {location_value}. Taking value from properties.")

    # Return the value and indicate if a choice was made between both values
    if property_value and location_value:
        return property_value, "properties", True  # Both values were available, choice made from properties
    elif property_value:
        return property_value, "properties", False  # Only property_value available
    elif location_value:
        return location_value, "location", False  # Only location_value available
    else:
        return "", "none", False  # No value found

def is_likely_to_be_a_phone_number(phone_number):
    # Strip unwanted characters (e.g., spaces, parentheses, etc.)
    phone_number = re.sub(r'[\(\)\+\-\s]', '', phone_number)

    # Check if the remaining string has at least 10 digits but no more than 14 digits
    return phone_number.isdigit() and 10 <= len(phone_number) <= 14

def do_ip_address_look_up_old(ip):
    try:
        # Make the request to ipinfo.io
        ipinfo_url = f"http://ipinfo.io/{ip}?token=c3a12271a0687f"
        response = requests.get(ipinfo_url)

        # If the request is successful, extract and return country and postal
        if response.status_code == 200:
            ip_data = response.json()  # Convert the response to JSON

            # Log the full IP data in pretty format
            # app_logger.info(f"IPinfo Response for IP {ip}:\n{json.dumps(ip_data, indent=4)}")

            # Extract country and postal from the response
            country = ip_data.get("country")
            postal = ip_data.get("postal")

            # Return country and postal as a dictionary
            return {"country": country, "postal": postal}
        else:
            app_logger.error(f"Error fetching IP info for {ip}: {response.status_code}")
            return None  # Return None if the request fails

    except Exception as e:
        app_logger.error(f"Error occurred while fetching IP info for {ip}: {str(e)}")
        return None  # Return None if an exception occurs

@app.route('/load_profiles', methods=['POST'])
@jwt_required()
def load_profiles():
    username = get_jwt_identity()
    redis_client = get_redis_client()  # Assume this function is defined elsewhere

    # Define the file path for IP cache
    ipinfo_cache_file_path = f"/home/bryananthonyobrien/mysite/data/ipinfo/{username}/cache.csv"

    # Check if the file exists
    if not os.path.exists(ipinfo_cache_file_path):
        # Create the IP info cache file and log
        app_logger.info(f"Creating the IP info cache file {ipinfo_cache_file_path}")
        create_ipinfo_cache_file(ipinfo_cache_file_path)
        ipinfo_cache = {}  # Initialize an empty cache since file is created
    else:
        # Load the IP info cache file if it exists and log
        app_logger.info(f"Loading the IP info cache file from {ipinfo_cache_file_path}")
        ipinfo_cache = load_ipinfo_cache(ipinfo_cache_file_path)

    # Extract directory from the request
    directory = request.json.get('directory')

    # Validate that the directory is a string and exists
    if not isinstance(directory, str) or not os.path.exists(directory):
        app_logger.error(f"Invalid directory provided by user {username}: {directory}")
        return jsonify({"msg": "Valid directory is required"}), 400

    app_logger.info(f"/load_profiles called for {username} with directory: {directory}")

    profiles_data = {}
    csv_file_path = os.path.join(directory, f"{username}_profiles.csv")  # Define the CSV file path

    # Initialize counters for profiles with and without phone numbers
    counts = {
        "with_phone": 0,
        "without_phone": 0,
    }

    dummy_email_counter = 0  # Counter for profiles with dummy emails
    duplicate_emails = 0  # Counter for profiles with duplicate emails
    seen_emails = set()  # To track unique emails
    number_zip_sourced_from_properties = 0
    number_zip_sourced_from_properties_by_choice = 0
    number_zip_sourced_from_properties_only_option = 0
    number_zip_sourced_from_location = 0
    number_zip_sourced_from_location_by_choice = 0
    number_zip_sourced_from_location_only_option = 0
    number_zip_codes_from_none = 0
    potential_location_data_from_ip_address = 0
    actual_location_data_from_ip_address = 0;

    n_profiles_in_json = 0
    n_iterations = 0
    last_n = 0
    try:
        # Iterate through each JSON file in the specified directory
        for filename in os.listdir(directory):
            if filename.endswith('.json'):
                with open(os.path.join(directory, filename)) as f:
                    data = json.load(f)
                    for profile in data['data']:
                        n_start = len(profiles_data)
                        n_profiles_in_json += 1
                        attributes = profile['attributes']
                        location = attributes.get('location', {})
                        properties = attributes.get('properties', {})

                        # Extract required fields including Birthday and Gender
                        profile_data = {
                            "email": attributes.get('email'),
                            "phone_number": attributes.get('phone_number'),
                            "first_name": attributes.get('first_name'),
                            "last_name": attributes.get('last_name'),
                            "city": location.get('city'),
                            "country": location.get('country'),
                            "region": location.get('region'),
                            "zip": location.get('zip'),
                            "address1": location.get('address1'),
                            "address2": location.get('address2'),
                            "latitude": location.get('latitude'),
                            "longitude": location.get('longitude'),
                            "created": attributes.get('created'),
                            "updated": attributes.get('updated'),
                            "last_event_date": attributes.get('last_event_date'),
                            "ip": location.get('ip') if location.get('ip') is not None else "",
                            "dummy_email": False,  # Initialize dummy_email flag as False
                            "birthday": "",  # Initialize birthday as empty
                            "gender": ""  # Initialize gender as empty
                        }
                        # Extract and convert Birthday
                        birthday_str = properties.get('Birthday')  # Get birthday from properties
                        if birthday_str:
                            try:
                                # Try parsing the birthday in known formats
                                for date_format in ("%m/%d/%Y", "%Y-%m-%d", "%m-%d-%Y", "%Y/%m/%d"):
                                    try:
                                        birthday_date = datetime.strptime(birthday_str, date_format)
                                        profile_data["birthday"] = birthday_date.strftime("%Y-%m-%d")  # Store in YYYY-MM-DD format
                                        break  # Exit loop once a valid format is found
                                    except ValueError:
                                        continue  # Try the next format
                                else:
                                    # If no format matches, log and set to empty string
                                    app_logger.info(f"On iteration {n_iterations} - Invalid birthday format for profile: {profile_data['email']}, original: {birthday_str}")
                                    profile_data["birthday"] = ""
                            except Exception as e:
                                app_logger.error(f"Unexpected error parsing birthday for profile {profile_data['email']}: {e}")
                                profile_data["birthday"] = ""
                        else:
                            profile_data["birthday"] = ""  # Set to empty if no birthday provided

                        # Extract and normalize Gender
                        gender_str = properties.get('Gender')  # Get gender from properties
                        if gender_str:
                            normalized_gender = gender_str.strip().lower()  # Normalize to lower case
                            if normalized_gender in ['f', 'female']:
                                profile_data["gender"] = 'female'
                            elif normalized_gender in ['m', 'male']:
                                profile_data["gender"] = 'male'
                            elif normalized_gender in ['no-answer']:
                                profile_data["gender"] = 'no-answer'
                            elif normalized_gender in ['non-binary']:
                                profile_data["gender"] = 'non-binary'
                            else:
                                profile_data["gender"] = ''  # Leave blank if the gender doesn't match expected values
                                app_logger.info(f"On iteration {n_iterations} - Invalid gender format for profile: {profile_data['gender']}, original: {gender_str}")
                        else:
                           profile_data["gender"] = ''  # Leave blank if no gender provided

                        # Use email as key (or any unique identifier) to store profiles
                        email = profile_data.get("email")

                        # Ensure email is a string or generate a dummy email
                        if not email or not isinstance(email, str):
                            # Generate a dummy email if email is missing or invalid
                            epoch_time_us = int(time.time() * 1_000_000)  # Get current epoch time in microseconds
                            email = f"dummy{epoch_time_us}@bryanworx.com"
                            profile_data["email"] = email
                            profile_data["dummy_email"] = True  # Set dummy_email flag to True
                            dummy_email_counter += 1  # Increment dummy email counter

                        # Check if email is already seen
                        if email in seen_emails:
                            duplicate_emails += 1  # Increment duplicate email counter
                            app_logger.info(f"On iteration {n_iterations} - Duplicate email found: {email}, profile: {profile_data}")
                            continue  # Skip processing duplicate emails


                        # Add email to the seen_emails set
                        try:
                            seen_emails.add(email)  # Attempt to add email
                        except TypeError as e:
                            app_logger.info(f"Failed to add email to seen_emails: {email} - {str(e)}")
                            app_logger.info(f"Error loading profiles for user {username}. Profile data: {profile} - Error: {str(e)}")
                            continue


                        first_name = profile_data.get("first_name")
                        if not first_name:
                            # Check if the 'name' property is available
                            full_name = properties.get("name", "").strip()
                            if full_name:
                                # Split the full name into first name and last name
                                name_parts = full_name.split(maxsplit=1)
                                # profile_data["first_name"] = name_parts[0]  # Always set first name
                                app_logger.info(f"first_name set to {name_parts[0]}")
                                if len(name_parts) > 1:  # Only set last name if there is content after the first name
                                    profile_data["last_name"] = name_parts[1]
                                    # app_logger.info(f"last_name set to {name_parts[1]}")

                        # Example code to handle precedence
                        location = attributes.get("location", {})
                        properties = attributes.get("properties", {})

                        # Other fields with precedence
                        profile_data["country"], profile_data["country_source"], profile_data["country_choice_made"] = set_field_with_precedence(properties, location, "country")
                        profile_data["city"], profile_data["city_source"], profile_data["city_choice_made"] = set_field_with_precedence(properties, location, "city")
                        profile_data["region"], profile_data["region_source"], profile_data["region_choice_made"] = set_field_with_precedence(properties, location, "region")
                        profile_data["zip"], profile_data["zip_source"], profile_data["zip_choice_made"] = set_field_with_precedence(properties, location, "zip")

                        # Log the final values

                        # app_logger.info(f"city set to {profile_data['city']}")
                        # app_logger.info(f"region set to {profile_data['region']}")
                        # app_logger.info(f"zip set to {profile_data['zip']}")
                        # app_logger.info(f"country set to {profile_data['country']}")

                        # Count profiles with and without phone numbers (only unique profiles)
                        has_phone_number = bool(profile_data["phone_number"])
                        if has_phone_number:
                            counts["with_phone"] += 1
                        else:
                            counts["without_phone"] += 1

                        if profile_data["phone_number"] and profile_data["zip"] and is_likely_to_be_a_phone_number(profile_data["phone_number"]):
                            if profile_data["zip_source"] == 'properties':
                                number_zip_sourced_from_properties += 1
                                if profile_data["zip_choice_made"]:
                                    number_zip_sourced_from_properties_by_choice += 1
                                else:
                                    number_zip_sourced_from_properties_only_option += 1
                            elif profile_data["zip_source"] == 'location':
                                number_zip_sourced_from_location += 1
                                if profile_data["zip_choice_made"]:
                                    number_zip_sourced_from_location_by_choice += 1
                                else:
                                    number_zip_sourced_from_location_only_option += 1
                            else:
                                number_zip_codes_from_none += 1
                        elif profile_data["phone_number"] and profile_data["ip"] and is_likely_to_be_a_phone_number(profile_data["phone_number"]):
                            potential_location_data_from_ip_address += 1
                            ip_info = do_ip_address_look_up(profile_data["ip"], username, ipinfo_cache_file_path, ipinfo_cache)
                            if ip_info:
                                country_from_ip = ip_info.get("country")
                                postal_from_ip = ip_info.get("postal")
                                if country_from_ip and postal_from_ip:
                                    actual_location_data_from_ip_address += 1
                                    profile_data["zip"] = postal_from_ip
                                    if not profile_data.get("country"):
                                	    profile_data["country"] = country_from_ip
                                    profile_data["zip_source"] = 'ip'

                                # app_logger.info(f"Country: {country_from_ip}, Postal: {postal_from_ip}")
                            else:
                                app_logger.info(f"Failed to retrieve IP info for {profile_data['ip']}")


                        profiles_data[profile_data["email"]] = profile_data  # Store the profile by email
                        n_iterations += 1
                        n_end = len(profiles_data)
                        if (n_start == n_end):
                            app_logger.info(f"On iteration {n_iterations} number of profiles has remained at {n_start}. Profile: {profile_data}")


        update_ipinfo_cache_file(ipinfo_cache_file_path, ipinfo_cache)


        # Delete existing profiles for the user
        profiles_key = f"profiles_{username}"
        redis_client.delete(profiles_key)

        app_logger.info(f"Number of profiles in profiles_data: {len(profiles_data)}")

        # Store the new profiles data structure in Redis
        redis_client.hmset(profiles_key, {email: json.dumps(profile) for email, profile in profiles_data.items()})

        # Get the number of elements in the Redis hash
        profiles_count = redis_client.hlen(profiles_key)
        app_logger.info(f"{profiles_count} of {n_profiles_in_json} profiles loaded successfully for {username} with {n_iterations} iterations")

        # Create CSV file after profiles are loaded successfully
        with open(csv_file_path, mode='w', newline='') as csvfile:
            fieldnames = profiles_data[next(iter(profiles_data))].keys()  # Get fieldnames from the first profile
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for profile in profiles_data.values():
                writer.writerow(profile)

        app_logger.debug(f"CSV file created successfully at {csv_file_path}")

        # Prepare response with counts and CSV file path
        response_data = {
            "success": True,
            "message": "Profiles loaded successfully.",
            "total_profiles": len(profiles_data),
            "csv_file_path": csv_file_path,  # Add the CSV file path to the response
            "username": username,  # Include the username in the response
            "number_of_dummy_emails_generated": dummy_email_counter,  # Number of dummy emails generated
            "duplicate_emails": duplicate_emails,  # Add duplicate email count
            "counts": {
                "with_phone": counts["with_phone"],
                "without_phone": counts["without_phone"],
                "number_zip_sourced_from_properties": number_zip_sourced_from_properties,
                "number_zip_sourced_from_properties_by_choice": number_zip_sourced_from_properties_by_choice,
                "number_zip_sourced_from_properties_only_option": number_zip_sourced_from_properties_only_option,
                "number_zip_sourced_from_location": number_zip_sourced_from_location,
                "number_zip_sourced_from_location_by_choice": number_zip_sourced_from_location_by_choice,
                "number_zip_sourced_from_location_only_option": number_zip_sourced_from_location_only_option,
                "number_zip_codes_from_none": number_zip_codes_from_none,
                "potential_location_data_from_ip_address": potential_location_data_from_ip_address,
                "actual_location_data_from_ip_address": actual_location_data_from_ip_address
            }
        }

        pretty_status_data = json.dumps(response_data, indent=4)
        app_logger.debug(f"/load_profiles : Response Data:\n{pretty_status_data}")


        return jsonify(response_data), 200

    except Exception as e:
        app_logger.error(f"Error loading profiles: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/load_failed_profiles', methods=['GET'])
@jwt_required()
def load_failed_profiles():
    username = get_jwt_identity()  # Get the username from the token
    csv_file_path = request.args.get('file_path')  # Retrieve the file path from query parameters

    app_logger.info(f"/load_failed_profiles for user: {username} with file path: {csv_file_path}")

    # Validate the file path
    if not csv_file_path or not os.path.exists(csv_file_path):
        return jsonify({"error": "File not found"}), 404

    try:
        # Columns to exclude
        exclude_columns = {
            "MEMBER_ID", "LEADER_ID", "CHANNEL", "PHONE_NUMBER", "SUBSCRIPTION_STATE",
            "FIRST_NAME", "LAST_NAME", "EMAIL", "DATE_OF_BIRTH", "GENDER", "CITY",
            "ZIP_CODE", "STATE", "STATE_CODE", "COUNTRY", "COUNTRY_CODE", "DEVICE_TYPE",
            "FIRST_ACTIVATED_AT", "Already a Member", "Channel"
        }

        # Read the CSV file and filter out excluded columns
        profiles = []
        with open(csv_file_path, mode='r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                filtered_row = {
                    key: value.strip() for key, value in row.items() if key not in exclude_columns
                }
                profiles.append(filtered_row)

        app_logger.info(f"Loaded {len(profiles)} profiles from CSV for user: {username}")

        # Return the structured data as JSON
        return jsonify({
            "message": "Profiles loaded successfully",
            "profiles": profiles
        }), 200

    except Exception as e:
        app_logger.error(f"Error processing CSV file for user {username}: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route('/load_passed_profiles', methods=['GET'])
@jwt_required()
def load_passed_profiles():
    username = get_jwt_identity()  # Get the username from the token
    csv_file_path = request.args.get('file_path')  # Retrieve the file path from query parameters

    app_logger.info(f"/load_passed_profiles for user: {username} with file path: {csv_file_path}")

    # Validate the file path
    if not csv_file_path or not os.path.exists(csv_file_path):
        return jsonify({"error": "File not found"}), 404

    try:
        # Columns to exclude
        exclude_columns = {
            "MEMBER_ID", "LEADER_ID", "CHANNEL", "PHONE_NUMBER", "SUBSCRIPTION_STATE",
            "FIRST_NAME", "LAST_NAME", "EMAIL", "DATE_OF_BIRTH", "GENDER", "CITY",
            "ZIP_CODE", "STATE", "STATE_CODE", "COUNTRY", "COUNTRY_CODE", "DEVICE_TYPE",
            "FIRST_ACTIVATED_AT", "Already a Member", "Drop Reason"
        }

        # Read the CSV file and filter out excluded columns
        profiles = []
        with open(csv_file_path, mode='r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                filtered_row = {
                    key: value.strip() for key, value in row.items() if key not in exclude_columns
                }
                profiles.append(filtered_row)

        app_logger.info(f"Loaded {len(profiles)} profiles from CSV for user: {username}")

        # Return the structured data as JSON
        return jsonify({
            "message": "Profiles loaded successfully",
            "profiles": profiles
        }), 200

    except Exception as e:
        app_logger.error(f"Error processing CSV file for user {username}: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


@app.route('/download_csv', methods=['GET'])
@jwt_required()
def download_csv():
    username = get_jwt_identity()  # Get the username from the token
    csv_file_path = request.args.get('file_path')  # Retrieve the file path from query parameters
    app_logger.info(f"/download_csv for user: {username} {csv_file_path}")

    # Check if the file path is provided and if the file exists
    if not csv_file_path or not os.path.exists(csv_file_path):
        return jsonify({"error": "Not Found"}), 404

    return send_file(csv_file_path, as_attachment=True)

@app.route('/preopt_into_community', methods=['POST'])
@jwt_required()
def preopt_into_community():
    username = get_jwt_identity()
    app_logger.info(f"Received request to pre-opt into community for user: {username}")

    try:
        app_logger.info(f"/preopt_into_community initiated by {username}")

        # Get Redis client
        redis_client = get_redis_client()

        # Redis key for configuration
        config_key = f"configuration_{username}"

        # Check if test mode is enabled for the user
        test_mode_value = redis_client.hget(config_key, "test_mode_enabled")


        # If test_mode_key doesn't exist, default to False (not in test mode)
        if test_mode_value is None:
            app_logger.info(f"Test mode key not found for user {username}, defaulting to False.")
            test_mode_enabled = False
        else:
            # Convert the stored Redis value ('1' or '0') to a boolean
            test_mode_enabled = test_mode_value == b'1'
            app_logger.info(f"Test mode for user {username} is set to {test_mode_enabled}")

        # Get the JSON data from the request
        payload = request.get_json()

        # Log the payload to make sure it's received correctly
        app_logger.info(f"Received payload: {payload}")

        # Call the function to log the JSON structure and pass test mode
        result = do_preopt_into_community(redis_client, payload, username, test_mode_enabled)

        # Prepare response data based on the result of Community_subscription_create
        if result and result.get("status") == "success":
            response_data = {
                'success': True,
                'msg': 'Pre-opt data logged successfully.'
            }
            app_logger.info(f"User {username} completed pre-opt into community. Results: {response_data}")
            return jsonify(response_data), 200
        else:
            error_message = result.get("message", "Unknown error") if result else "Failed to create subscription"
            app_logger.error(f"Failed to process subscription: {error_message}")
            return jsonify({'success': False, 'msg': error_message}), 400

    except Exception as e:
        app_logger.error(f"Error processing pre-opt into community for {username}: {str(e)}")
        return jsonify({'success': False, 'msg': 'Internal Server Error'}), 500


def do_preopt_into_community(redis_client, data, username, test_mode_enabled=False):

    configuration_key = f"configuration_{username}"

    # Retrieve Community keys from Redis
    community_client_id = redis_client.hget(configuration_key, 'COMMUNITY_CLIENT_ID')
    community_api_token = redis_client.hget(configuration_key, 'COMMUNITY_API_TOKEN')
    sub_community = redis_client.hget(configuration_key, 'SUB_COMMUNITY')
    tag = sub_community.decode('utf-8') if sub_community else "Imported from Klaviyo"

    # Decode the keys from Redis or fall back to environment variables
    if community_client_id:
        community_client_id = community_client_id.decode('utf-8')
        app_logger.info(f"COMMUNITY_CLIENT_ID retrieved from Redis for user {username}")
    else:
        community_client_id = os.getenv('COMMUNITY_CLIENT_ID')
        if not community_client_id:
            app_logger.error("COMMUNITY_CLIENT_ID not set in Redis or environment variables.")
            return {'status': 'error', 'message': 'COMMUNITY_CLIENT_ID not found.'}

    if community_api_token:
        community_api_token = community_api_token.decode('utf-8')
        app_logger.info(f"COMMUNITY_API_TOKEN retrieved from Redis for user {username}")
    else:
        community_api_token = os.getenv('COMMUNITY_API_TOKEN')
        if not community_api_token:
            app_logger.error("COMMUNITY_API_TOKEN not set in Redis or environment variables.")
            return {'status': 'error', 'message': 'COMMUNITY_API_TOKEN not found.'}


    try:
        # Log the JSON structure passed to the function
        app_logger.info(f"Pre-opt into community data: {data}")
        app_logger.info(f"Test mode is {'enabled' if test_mode_enabled else 'disabled'} for user: {username}")

        # Call the Community_subscription_create function with the necessary data and test_mode flag
        result = Community_subscription_create(tag, community_client_id, community_api_token, data, username, test_mode=test_mode_enabled)
        app_logger.info(f"RESPONSE from Community_subscription_create: {result}")

        # Log the result of the subscription creation
        if result is not None:
            app_logger.info(f"Subscription created successfully: {result}")
        else:
            app_logger.error("Failed to create subscription.")

        return result

    except Exception as e:
        app_logger.error(f"Exception in do_preopt_into_community: {str(e)}")
        return {'status': 'error', 'message': 'An error occurred while processing pre-opt.'}

@app.route('/get_chunk_data', methods=['POST'])
@jwt_required()
def get_chunk_data():
    username = get_jwt_identity()
    data = request.get_json()
    chunk_key = data.get("chunk_key")

    if not chunk_key:
        app_logger.info("No chunk_key provided in the request.")
        return jsonify({"error": "chunk_key is required"}), 400

    try:
        # Get Redis client
        redis_client = get_redis_client()

        app_logger.info(f"Fetching Redis data for chunk: {chunk_key}")

        # Retrieve the Redis hash for the specified chunk
        chunk_data = redis_client.hgetall(chunk_key)

        # Check if data exists for the given chunk key
        if not chunk_data:
            app_logger.info(f"No data found in Redis for chunk {chunk_key}")
            return jsonify({"error": f"No data found for chunk {chunk_key}"}), 404

        # Decode each entry and parse the JSON profile data
        decoded_chunk_data = {}
        for k, v in chunk_data.items():
            phone_number = k.decode('utf-8')
            profile_data = v.decode('utf-8')
            try:
                # Parse profile data as JSON
                decoded_chunk_data[phone_number] = json.loads(profile_data)
            except json.JSONDecodeError:
                app_logger.warning(f"Failed to parse JSON for phone number {phone_number}")
                decoded_chunk_data[phone_number] = profile_data  # Keep as raw string if parsing fails

        app_logger.info(f"Chunk data retrieved for {chunk_key}")

        return jsonify(decoded_chunk_data), 200

    except Exception as e:
        app_logger.info(f"Error retrieving chunk data for {chunk_key}: {str(e)}")
        return jsonify({"error": "Failed to retrieve chunk data"}), 500


@app.route('/create_stage_csv_files', methods=['POST'])
@jwt_required()
def create_stage_csv_route():
    username = get_jwt_identity()

    app_logger.info(f"Received request to create staging files for user: {username}")

    try:
        app_logger.info(f"/create_stage_csv_files initiated by {username}")

        # Call the function to create CSV files
        result = create_stage_csv_files(username, silent=True)

        # Log the result for debugging
        app_logger.info(f"Result from create_stage_csv_files: {result}")

        # Check if result is None
        if result is None:
            app_logger.warning(f"No profiles found for user {username}.")
            return jsonify({'success': False, 'msg': 'No profiles found for user'}), 404

        # Prepare response data
        response_data = {
            'success': True,
            'data': result
        }

        # Attempt to serialize response data to ensure it's JSON serializable
        try:
            json.dumps(response_data)  # Attempt to serialize
        except TypeError as te:
            app_logger.error(f"Serialization error: {str(te)}")
            return jsonify({'success': False, 'msg': 'Internal Server Error'}), 500

        app_logger.info(f"User {username} completed CSV creation. Results: {response_data}")
        return jsonify(response_data), 200

    except Exception as e:
        app_logger.error(f"Error processing CSV creation for {username}: {str(e)}")
        return jsonify({'success': False, 'msg': 'Internal Server Error'}), 500

@app.route('/clash_members_profiles_works', methods=['POST'])
@jwt_required()
def clash_members_profiles_works():
    # Get the current user's identity (username) from the JWT
    username = get_jwt_identity()

    try:
        app_logger.info(f"/clash_members_profiles initiated by {username}")

        # Get Redis client
        redis_client = get_redis_client()

        # Check if profiles_{username} exists
        profiles_key = f"profiles_{username}"
        if not redis_client.exists(profiles_key):
            # If the profiles data does not exist, respond with a 422 and an indicator for the frontend
            app_logger.info(f"Profiles data not found for user {username}. Prompting user to load profiles.")
            return jsonify({
                'success': False,
                'msg': 'Profiles data not found. Please load or discover profiles first.',
                'profiles_missing': True  # Indicator for the frontend that profiles are missing
            }), 422

        # Proceed with the rest of the function if profiles exist
        members_key = f"members_{username}"
        if not redis_client.exists(members_key):
            app_logger.info(f"Members data not found for user {username}.")
            return jsonify({
                'success': False,
                'msg': 'Members data not found. Please load members first.',
                'members_missing': True  # Indicator for the frontend that members are missing
            }), 422

        # Call the clash_members_and_profiles function
        try:
            clash_result = clash_members_and_profiles(username)
        except Exception as clash_error:
            app_logger.info(f"Error in clash_members_and_profiles function for user {username}: {str(clash_error)}")
            return jsonify({'success': False, 'msg': 'Internal processing error in clash_members_and_profiles'}), 500

        if not clash_result.get('success', False):
            return jsonify({'success': False, 'msg': clash_result.get('message', 'Error in processing')}), 500

        # Prepare and return the response with clash results, including MEMBER_IDs by state
        response_data = {
            'success': True,
            'counts': {
                'matched_members': clash_result.get('matched_members', 0),
                'non_matched_members': clash_result.get('non_matched_members', 0),
                'live': clash_result.get('matched_subscription_state_counts', {}).get('live', 0),
                'opted_out': clash_result.get('matched_subscription_state_counts', {}).get('opted_out', 0),
                'deleted': clash_result.get('subscription_state_counts', {}).get('deleted', 0),
                'non_matched_live': clash_result.get('non_matched_subscription_state_counts', {}).get('live', 0),
                'non_matched_opted_out': clash_result.get('non_matched_subscription_state_counts', {}).get('opted_out', 0)
            },
            'metadata': {
                'file_name': clash_result.get('metadata', {}).get('file_name'),
                'total_members_count': clash_result.get('metadata', {}).get('total_members_count')
            },
            'member_ids_by_state': {
                'live': clash_result.get('member_ids_by_state', {}).get('live', []),
                'non_matched_live': clash_result.get('member_ids_by_state', {}).get('non_matched_live', []),
                'opted_out': clash_result.get('member_ids_by_state', {}).get('opted_out', []),
                'non_matched_opted_out': clash_result.get('member_ids_by_state', {}).get('non_matched_opted_out', [])
            }
        }

        app_logger.info(f"User {username} completed clashing. Results: {response_data}")
        return jsonify(response_data), 200

    except Exception as e:
        app_logger.info(f"Error processing clash members and profiles for {username}: {str(e)}")
        return jsonify({'success': False, 'msg': 'Internal Server Error'}), 500

@app.route('/clash_members_profiles', methods=['POST'])
@jwt_required()
def clash_members_profiles():
    # Get the current user's identity (username) from the JWT
    username = get_jwt_identity()

    try:
        app_logger.info(f"/clash_members_profiles initiated by {username}")

        # Get Redis client
        redis_client = get_redis_client()

        # Check if profiles_{username} exists
        profiles_key = f"profiles_{username}"
        if not redis_client.exists(profiles_key):
            # If the profiles data does not exist, respond with a 422 and an indicator for the frontend
            app_logger.info(f"Profiles data not found for user {username}. Prompting user to load profiles.")
            return jsonify({
                'success': False,
                'msg': 'Profiles data not found. Please load or discover profiles first.',
                'profiles_missing': True  # Indicator for the frontend that profiles are missing
            }), 422

        # Proceed with the rest of the function if profiles exist
        members_key = f"members_{username}"
        if not redis_client.exists(members_key):
            app_logger.info(f"Members data not found for user {username}.")
            return jsonify({
                'success': False,
                'msg': 'Members data not found. Please load members first.',
                'members_missing': True  # Indicator for the frontend that members are missing
            }), 422

        # Call the clash_members_and_profiles function
        try:
            clash_result = clash_members_and_profiles(username)
        except Exception as clash_error:
            app_logger.info(f"Error in clash_members_and_profiles function for user {username}: {str(clash_error)}")
            return jsonify({'success': False, 'msg': 'Internal processing error in clash_members_and_profiles'}), 500

        if not clash_result.get('success', False):
            return jsonify({'success': False, 'msg': clash_result.get('message', 'Error in processing')}), 500

        # Prepare and return the response with clash results, including MEMBER_IDs by state
        response_data = {
            'success': True,
            'counts': {
                'matched_members': clash_result.get('matched_members', 0),
                'non_matched_members': clash_result.get('non_matched_members', 0),
                'live': clash_result.get('matched_subscription_state_counts', {}).get('live', 0),
                'opted_out': clash_result.get('matched_subscription_state_counts', {}).get('opted_out', 0),
                'deleted': clash_result.get('subscription_state_counts', {}).get('deleted', 0),
                'non_matched_live': clash_result.get('non_matched_subscription_state_counts', {}).get('live', 0),
                'non_matched_opted_out': clash_result.get('non_matched_subscription_state_counts', {}).get('opted_out', 0)
            },
            'metadata': {
                'file_name': clash_result.get('metadata', {}).get('file_name'),
                'total_members_count': clash_result.get('metadata', {}).get('total_members_count')
            },
            'member_ids_by_state': {
                'live': clash_result.get('member_ids_by_state', {}).get('live', []),
                'non_matched_live': clash_result.get('member_ids_by_state', {}).get('non_matched_live', []),
                'opted_out': clash_result.get('member_ids_by_state', {}).get('opted_out', []),
                'non_matched_opted_out': clash_result.get('member_ids_by_state', {}).get('non_matched_opted_out', []),
                'deleted': clash_result.get('member_ids_by_state', {}).get('deleted', [])  # Include deleted members
            }
        }

        app_logger.info(f"User {username} completed clashing. Results: {response_data}")
        return jsonify(response_data), 200

    except Exception as e:
        app_logger.info(f"Error processing clash members and profiles for {username}: {str(e)}")
        return jsonify({'success': False, 'msg': 'Internal Server Error'}), 500


@app.route('/klaviyo_discoveries', methods=['GET'])
@jwt_required()
def get_klaviyo_discoveries():
    username = get_jwt_identity()
    redis_client = get_redis_client()

    discoveries_key = f"klaviyo_discoveries_{username}"
    discoveries = redis_client.hgetall(discoveries_key)

    app_logger.info(f"/klaviyo_discoveries called for {username}")

    if not discoveries:
        app_logger.info("No Klaviyo discoveries found")
        # Return an empty list instead of a message
        return jsonify([]), 200

    # Transform the discoveries into a list and check if the directory exists
    discoveries_list = []
    for value in discoveries.values():
        discovery = json.loads(value.decode('utf-8'))
        file_location = discovery.get('file_location', None)
        discovery['directory_exists'] = os.path.exists(file_location) if file_location else False
        discoveries_list.append(discovery)

    # Log the JSON before returning it
    app_logger.info(f"Returning Klaviyo discoveries: {json.dumps(discoveries_list, indent=2)}")

    return jsonify(discoveries_list), 200

@app.route('/discover_klaviyo_profiles', methods=['POST'])
@jwt_required()
@cross_origin()
@limiter.limit(get_dynamic_rate_limit)
def discover_klaviyo_profiles():
    app_logger.debug("/discover_klaviyo_profiles")
    claims = get_jwt()

    # Initialize response data
    response_data = {}

    # Verify that an access token is being used
    if claims.get('type') != 'access':
        return jsonify({"msg": "Only access tokens are allowed"}), 401

    username = get_jwt_identity()

    try:
        user_data, cache_status = get_user_data(username)

        # Check if user is suspended
        if user_data.get('user_status') == 'suspended':
            app_logger.error(f"Suspended user {username} attempted to initiate 'discover klaviyo'")
            return jsonify({"msg": "User is suspended", "user_status": "suspended"}), 403

        try:
            # Set status to "running" in Redis
            app_logger.info(f"Initiating 'discover klaviyo' for user {username} in sync mode")

            # Perform the discovery in sync mode
            discovery_result = do_klaviyo_discovery("sync", username)

            # Capture the number of profiles if provided in the result
            if 'total_profiles' in discovery_result:
                response_data['total_profiles'] = discovery_result['total_profiles']

            response_data.update(discovery_result)
            status_code = 200

        finally:
            # Refresh user data to include the latest credit count and API call count
            user_data, cache_status = get_user_data(username)
            response_data.update({
                "credits": user_data['credits'],
                "cache_status": cache_status,
                "service_count": user_data['api_calls'],
                "user_status": user_data.get('user_status', 'active')
            })

        return jsonify(response_data), status_code

    except Exception as e:
        app_logger.error(f"Error in 'discover klaviyo profiles' for user {username}: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/persist-now', methods=['POST'])
@jwt_required()
def persist_now():
    # Check if the user is an admin
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({"msg": "Only admins can access this endpoint"}), 403

    return jsonify({"msg": "Clients data persisted"}), 200

@app.route('/cpu-usage', methods=['GET'])
@jwt_required()
def cpu_usage():
    return cpu_usage_function(USERNAME, API_TOKEN)

@app.errorhandler(ExpiredSignatureError)
def handle_expired_error(e):
    try:
        token = request.headers.get('Authorization').split()[1]
        app_logger.info(f"handle_expired_error: JWT_SECRET_KEY set: {app.config['JWT_SECRET_KEY']}")
        decoded_token = decode_jwt(token, app.config['JWT_SECRET_KEY'], allow_expired=True)  # Allow expired tokens
        jti = decoded_token['jti']
        expires_at = datetime.utcfromtimestamp(decoded_token['exp'])

        jti, username = get_jti_and_username(jti)

        if jti and username:
            # Revoke the expired token
            with get_db_connection() as conn:
                add_revoked_token_function(jti, username, token, expires_at, conn)

            # Remove the expired token from the issued_tokens table
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM issued_tokens WHERE jti = ?", (jti,))
                conn.commit()
                app_logger.debug(f"Removed expired token: {jti} for user {username}")

            return jsonify({"msg": "Token has expired and has been logged out"}), 401
        else:
            return jsonify({"msg": "Token information not found"}), 401

    except sqlite3.OperationalError:
        app_logger.error("Error handling expired token")
        return jsonify({"error": "Database error. Please try again later."}), 500
    except Exception as exc:
        app_logger.error(f"Error handling expired token: {str(exc)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/logout', methods=['POST'])
@cross_origin()
@jwt_required()  # Make JWT required
def logout():
    return logout_function()

@app.route('/dashboard')
@login_required
def dashboard():
    if session['role'] == 'admin':
        return render_template('admin.html')
    elif session['role'] == 'client':
        return render_template('client.html')
    return 'Unauthorized', 403

@app.route('/test-throughput', methods=['POST'])
@jwt_required()
def test_throughput():
    return test_throughput_function()

@limiter.request_filter
def get_user_limits():
    return "5 per minute; 10 per day; 100 per month"  # Default rate limits

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
@limiter.limit("5 per minute; 10 per day; 100 per month")
def refresh():
    app_logger.debug("/refresh")
    try:
        current_user = get_jwt_identity()

        # Retrieve the user's role, credits, and limits from the database
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT role, credits FROM users WHERE username = ?", (current_user,))
            user_result = cursor.fetchone()
            if user_result is None:
                return jsonify({"msg": "User does not exist"}), 404

            role, credits = user_result

            cursor.execute("SELECT daily_limit, hourly_limit, minute_limit FROM limits WHERE user_id = ?", (current_user,))
            limits_result = cursor.fetchone()
            if limits_result:
                daily_limit, hourly_limit, minute_limit = limits_result
            else:
                daily_limit = DEFAULT_DAILY_LIMIT
                hourly_limit = DEFAULT_HOURLY_LIMIT
                minute_limit = DEFAULT_MINUTE_LIMIT

        # Revoke any existing access tokens before creating new ones
        with get_db_connection() as conn:
            app_logger.info(f"refresh: JWT_SECRET_KEY set: {app.config['JWT_SECRET_KEY']}")
            revoke_all_access_tokens_for_user(current_user, app.config['JWT_SECRET_KEY'], conn)

        access_token, refresh_token = create_tokens(current_user, role, daily_limit, hourly_limit, minute_limit, str(app.config['JWT_SECRET_KEY']), app.config['JWT_ACCESS_TOKEN_EXPIRES'], app.config['JWT_REFRESH_TOKEN_EXPIRES'],check_existing_refresh=True)

        expired_tokens = []
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT jti, username, expires_at FROM issued_tokens WHERE expires_at <= datetime('now')")
            expired_tokens = cursor.fetchall()

            for jti, username, expires_at in expired_tokens:
                add_revoked_token_function(jti, username, "", expires_at, conn)

            cursor.executemany("DELETE FROM issued_tokens WHERE jti = ?", [(jti,) for jti, username, expires_at in expired_tokens])
            conn.commit()

        return jsonify(access_token=access_token), 200
    except RateLimitExceeded as e:
        app_logger.error(f"Rate limit exceeded: {str(e)}")
        return jsonify({"error": "Rate limit exceeded", "retry_after": e.description["retry_after"]}), 429
    except sqlite3.OperationalError as e:
        app_logger.error(f"OperationalError during token refresh: {str(e)}")
        if 'no such table' in str(e):
            app_logger.error(f"Missing table detected: {str(e)}")
            return jsonify({"error": "Internal Server Error"}), 500
    except Exception as e:
        app_logger.error(f"Error during token refresh: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/revoke', methods=['POST'])
@jwt_required()
def revoke():
    app_logger.debug("/revoke")
    try:
        if not request.is_json or request.json.get('username') is None:
            return jsonify({"msg": "Invalid request"}), 400
        username = request.json.get('username')
        current_user_role = get_jwt()["role"]

        if current_user_role != "admin":
            return jsonify({"msg": "Only admins can revoke tokens"}), 403

        app_logger.debug(f"Revoking tokens for user: {username}")

        with get_db_connection() as conn:
            app_logger.debug("Entering with block in revoke")
            cursor = conn.cursor()
            app_logger.debug("Database connection opened and cursor created")
            cursor.execute("SELECT jti, jwt, expires_at FROM issued_tokens WHERE username = ?", (username,))
            tokens = cursor.fetchall()
            app_logger.debug(f"Tokens fetched for user {username}: {tokens}")

            if not tokens:
                app_logger.debug(f"No tokens found for user: {username}")
                return jsonify({"msg": f"No tokens found for user {username}"}), 404

            for (jti, jwt, expires_at) in tokens:
                try:
                    app_logger.debug(f"Revoking token: {jti} for user: {username}")
                    add_revoked_token_function(jti, username, jwt, expires_at, conn)
                    app_logger.debug(f"Revoked token: {jti} for user: {username}")
                    cursor.execute("DELETE FROM issued_tokens WHERE jti = ?", (jti,))
                    app_logger.debug(f"Deleted token: {jti} from issued_tokens for user: {username}")
                except Exception as e:
                    app_logger.error(f"Error revoking token {jti} for user {username}: {str(e)}")
                    continue

            conn.commit()
            app_logger.debug("Database changes committed")
        app_logger.debug("Exiting with block in revoke")

        return jsonify({"msg": f"All tokens for {username} have been revoked"}), 200

    except sqlite3.OperationalError as e:
        app_logger.error(f"Database error during revoke: {str(e)}")
        return jsonify({"error": "Database error. Please try again later."}), 500
    except Exception as e:
        app_logger.error(f"Error during revoke: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/app', methods=['GET', 'POST'])
@cross_origin()
def app_route():
    if request.method == 'GET':
        app_logger.debug("Serving API key form")
        return render_template('api_key_form.html')
    elif request.method == 'POST':
        api_key = request.form.get('api_key')
        if (api_key == os.getenv('API_KEY')):
            app_logger.debug("Valid API key entered, serving instructions page")
            return render_template('instructions.html')
        else:
            app_logger.debug("Invalid API key entered")
            return jsonify({"error": "Unauthorized"}), 401

def validate_and_process():
    try:
        raw_data = request.get_data(as_text=True)
        app_logger.debug(f"Request payload: {raw_data}")

        if not request.is_json:
            error_message = "Request must be JSON"
            # app_logger.error(error_message)
            return jsonify({"error": error_message}), 400

        # data = request.get_json()
        # app_logger.debug(f"Received data: {json.dumps(data, indent=4)}")

        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        # log_message = f"{timestamp} - Payload received and logged\n{json.dumps(data, indent=4)}"
        # app_logger.debug(log_message)

        return jsonify({"result": True, "timestamp": timestamp}), 200

    except ExpiredSignatureError as e:
        app_logger.error(f"Token has expired: {str(e)}")
        return jsonify({"error": "Token has expired"}), 401  # Correct status code

    except RateLimitExceeded as e:
        retry_after = e.description['retry_after'] if 'retry_after' in e.description else 60  # Default to 60 seconds if not specified
        app_logger.error(f"Rate limit exceeded: Retry after {retry_after} seconds")
        response = jsonify({"error": "Rate limit exceeded", "retry_after": retry_after})
        response.headers['Retry-After'] = retry_after
        return response, 429

    except Exception as e:
        app_logger.error(f"Error processing payload: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

@app.errorhandler(429)
def ratelimit_error(e):
    retry_after = e.description['retry_after'] if 'retry_after' in e.description else 60  # Default to 60 seconds if not specified
    app_logger.error(f"Rate limit exceeded: Retry after {retry_after} seconds")
    response = jsonify({"error": "Rate limit exceeded", "retry_after": retry_after})
    response.headers['Retry-After'] = retry_after
    return response, 429

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad Request"}), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not Found"}), 404

@app.errorhandler(Exception)
def handle_exception(e):
    app_logger.error(f"Unexpected error: {str(e)}")
    app_logger.error(traceback.format_exc())
    return jsonify({"error": "Internal Server Error"}), 500

sslify = SSLify(app)
app_logger.info("Created SSLify")

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://js.stripe.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "frame-src 'self' https://js.stripe.com; "
        "img-src 'self' data:; "
        "object-src 'none';"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/file-storage-usage', methods=['GET'])
@jwt_required()
def get_file_storage_usage():
    return get_file_storage_usage_function()

def get_cpu_usage():
    return get_cpu_usage_function(USERNAME, API_TOKEN)

@measure_time
@app.route('/health-check', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"}), 200

@measure_time
@app.route('/status', methods=['GET'])
def status():
    if is_loading_clients:
        return jsonify({"status": "error", "message": "The server is currently loading client data and is not available."}), 503
    else:
        return jsonify({"status": "ok", "message": "The server is running and available."}), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
