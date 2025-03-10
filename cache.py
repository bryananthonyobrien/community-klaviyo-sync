import os
from flask_caching import Cache
import threading
from redis import Redis
from logs import app_logger  # Ensure this import is correct and does not cause circular imports
from redis import exceptions as redis_exceptions
from common import decode_redis_values  
from datetime import datetime
import sqlite3
import csv
import json
import re
import redis
from collections import defaultdict
import math

# Initialize the cache
cache = Cache()

# Default cache status
cache_status = "Cache Available"

# Configure Redis cache
cache_config = {
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_HOST': os.getenv('REDIS_HOST', 'localhost'),
    'CACHE_REDIS_PORT': os.getenv('REDIS_PORT', 6379),
    'CACHE_REDIS_PASSWORD': os.getenv('REDIS_PASSWORD', None),
    'CACHE_REDIS_DB': os.getenv('REDIS_DB', 0)
}

def get_redis_client():
    return Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        password=os.getenv('REDIS_PASSWORD', None),
        db=int(os.getenv('REDIS_DB', 0))
    )

def initialize_user_cache(username, password, role='client', login_attempts=0, last_login_attempt='None', credits=10, user_status='active', is_logged_in_now=0, created='None', daily_limit=200, hourly_limit=50, minute_limit=10):
    try:
        redis_client = get_redis_client()

        # Use per-user revoked_tokens and issued_tokens sets
        revoked_tokens_key = f"revoked_tokens:{username}"
        issued_tokens_key = f"issued_tokens:{username}"

        # 🔄 Cleanup expired revoked tokens BEFORE initializing
        if redis_client.exists(revoked_tokens_key):
            revoked_tokens = redis_client.smembers(revoked_tokens_key)
            current_time = datetime.utcnow()
            valid_tokens = set()

            for jti in revoked_tokens:
                try:
                    token_data = json.loads(jti.decode('utf-8'))  # Convert from bytes & parse JSON
                    expires_at = token_data.get('expires_at')

                    # If there's no expiration, assume it's a permanent token (skip it)
                    if not expires_at:
                        valid_tokens.add(jti)
                        continue

                    expiry_time = datetime.fromisoformat(expires_at)
                    
                    if expiry_time > current_time:
                        valid_tokens.add(jti)  # Keep valid tokens
                    else:
                        app_logger.info(f"🗑️ Removing expired revoked token {jti} for user {username} (expired at {expires_at})")

                except (json.JSONDecodeError, ValueError) as e:
                    app_logger.warning(f"⚠️ Error decoding revoked token for {username}, skipping: {str(e)}")

            # Replace revoked tokens with only the valid ones
            redis_client.delete(revoked_tokens_key)
            if valid_tokens:
                redis_client.sadd(revoked_tokens_key, *valid_tokens)
                app_logger.info(f"✅ Cleaned revoked tokens for {username}. Preserved {len(valid_tokens)} valid tokens.")
            else:
                app_logger.info(f"✅ Cleaned all expired revoked tokens for {username}.")

        else:
            redis_client.sadd(revoked_tokens_key, '')  # Initialize if it doesn't exist
            app_logger.info(f"Created per-user Redis set for {revoked_tokens_key}.")

        # ✅ Preserve issued tokens (Do NOT delete)
        if not redis_client.exists(issued_tokens_key):
            redis_client.sadd(issued_tokens_key, '')  # Initialize with an empty value
            app_logger.info(f"Created per-user Redis set for {issued_tokens_key}.")
        else:
            app_logger.info(f"⚠️ Found issued tokens for {username}.")

        # Prepare the user data dictionary with all necessary attributes
        user_data = {
            "password": password,  # Store the hashed password
            "role": role,
            "login_attempts": login_attempts,
            "last_login_attempt": last_login_attempt if last_login_attempt else '',
            "credits": credits,
            "user_status": user_status,
            "is_logged_in_now": is_logged_in_now,
            "created": created if created else datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }

        # Store all this data in Redis using hset (for hash values)
        redis_client.hset(username, mapping=user_data)  # Store user data in Redis

        # Store the user's limits in Redis hash
        limits = {
            "daily_limit": daily_limit,
            "hourly_limit": hourly_limit,
            "minute_limit": minute_limit
        }
        redis_client.hmset(f"{username}:limits", limits)

        # Initialize the user's credit_changes as an empty list (if no changes yet)
        redis_client.delete(f"{username}:credit_changes")  # Clean up if it exists already
        redis_client.lpush(
            f"{username}:credit_changes",
            json.dumps({
                "username": username,
                "amount": credits,
                "source": "initial",
                "transaction_id": "0",
                "change_date": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            })
        )

        # Log the initialization of the user's cache in Redis
        app_logger.info(f"Cache initialized for user: {username} with all attributes.")
        app_logger.info(f"Limits set for user {username}: Daily={daily_limit}, Hourly={hourly_limit}, Minute={minute_limit}")
        app_logger.info(f"Initial credits set for user {username}.")

    except Exception as e:
        app_logger.error(f"❌ Error initializing cache for user {username}: {str(e)}")
     
def suspend_user_cache(username):
    try:
        redis_client = get_redis_client()
        # Update the cache to reflect that the user is suspended
        if redis_client.exists(username):
            redis_client.hmset(username, {'user_status': 'suspended'})  # Changed status to user_status
            app_logger.info(f"Cache updated for suspended user: {username}")
        else:
            app_logger.info(f"User {username} not found in cache when trying to suspend.")
    except Exception as e:
        app_logger.info(f"Error suspending user cache for {username}: {str(e)}")

def unsuspend_user_cache(username):
    try:
        redis_client = get_redis_client()
        # Update the cache to reflect that the user is active
        if redis_client.exists(username):
            redis_client.hmset(username, {'user_status': 'active'})  # Changed status to user_status
            app_logger.info(f"Cache updated for unsuspended user: {username}")
        else:
            app_logger.info(f"User {username} not found in cache when trying to unsuspend.")
    except Exception as e:
        app_logger.info(f"Error unsuspending user cache for {username}: {str(e)}")

def convert_to_epoch(timestamp_str):
    """Converts ISO formatted timestamp to epoch time."""
    try:
        # If the timestamp includes a 'Z' (common in some formats), remove it
        if timestamp_str.endswith('Z'):
            timestamp_str = timestamp_str[:-1]

        # Convert the timestamp to datetime and then to epoch (as an integer)
        dt = datetime.fromisoformat(timestamp_str)
        return int(dt.timestamp())  # Returns epoch as a long (integer)
    except ValueError:
        return 'N/A'  # Return 'N/A' if conversion fails

def calculate_time_stats(time_differences):
    if not time_differences:
        return None, None, None, None, None  # Handle empty list

    total_time = sum(time_differences)
    average_time = total_time / len(time_differences)
    min_time = min(time_differences)
    max_time = max(time_differences)

    return average_time, min_time, max_time

def format_time_difference(time_diff_seconds):
    days = time_diff_seconds // (24 * 3600)
    time_diff_seconds %= (24 * 3600)
    hours = time_diff_seconds // 3600
    time_diff_seconds %= 3600
    minutes = time_diff_seconds // 60
    seconds = time_diff_seconds % 60
    return f"{int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds"

from collections import defaultdict

def clash_members_and_profiles(username):
    app_logger.info(f"Entered clash_members_and_profiles {username}")
    try:
        redis_client = get_redis_client()

        # Keys for members and profiles
        members_key = f"members_{username}"
        profiles_key = f"profiles_{username}"

        # Check if both keys exist in Redis and specify which ones are missing
        missing_keys = []
        if not redis_client.exists(members_key):
            missing_keys.append('members')
        if not redis_client.exists(profiles_key):
            missing_keys.append('profiles')

        # If any keys are missing, log an error and return the details
        if missing_keys:
            missing_keys_str = " and ".join(missing_keys)
            app_logger.info(f"Missing data: {missing_keys_str} key(s) for user {username}.")
            return {
                'success': False,
                'message': f"Data not found for user: missing {missing_keys_str} key(s).",
                'missing_keys': missing_keys
            }

        app_logger.info("Fetch all members and profiles")
        members_data = redis_client.hgetall(members_key)
        profiles_data = redis_client.hgetall(profiles_key)

        # Initialize metadata variables
        file_name = None
        total_members_count = None

        def normalize_phone_number(phone_number):
            """Normalize phone number by removing non-digit characters."""
            if isinstance(phone_number, str):
                return re.sub(r'\D', '', phone_number)
            return ''

        # Create a mapping of phone numbers to profiles
        profiles_by_phone = {}
        for profile_key, profile_data in profiles_data.items():
            try:
                profile = json.loads(profile_data.decode('utf-8'))
                phone_number = normalize_phone_number(profile.get('phone_number', ''))
                if phone_number:
                    profiles_by_phone[phone_number] = profile
            except json.JSONDecodeError as json_error:
                app_logger.info(f"JSON decoding error for profile {profile_key}: {json_error}")
            except Exception as e:
                app_logger.info(f"Unexpected error processing profile {profile_key}: {str(e)}")

        # Initialize statistics and MEMBER_ID sets
        matched_members = 0
        non_profile_members = 0
        subscription_state_counts = defaultdict(int)
        matched_subscription_state_counts = defaultdict(int)
        non_matched_subscription_state_counts = defaultdict(int)

        member_ids_by_state = {
            'live': set(),
            'non_matched_live': set(),
            'opted_out': set(),
            'non_matched_opted_out': set(),
            'deleted': set()  # New set for deleted members
        }

        app_logger.info("Iterate over members and attempt to find matching profiles by phone number")
        for member_key, member_data in members_data.items():
            # Check for metadata keys and store their values
            if member_key == b'file_name':
                file_name = member_data.decode('utf-8')
                continue
            elif member_key == b'total_members_count':
                total_members_count = int(member_data)
                continue

            try:
                member = json.loads(member_data.decode('utf-8'))
                member_phone = normalize_phone_number(member.get('PHONE_NUMBER', ''))
                subscription_state = member.get('SUBSCRIPTION_STATE', 'unknown')
                member_id = member.get('MEMBER_ID')

                # Count total subscription states
                subscription_state_counts[subscription_state] += 1

                # Handle deleted members
                if subscription_state == 'deleted':
                    member_ids_by_state['deleted'].add(member_id)
                    continue

                # Check for a matching profile by phone number
                if member_phone in profiles_by_phone:
                    matched_members += 1
                    matched_subscription_state_counts[subscription_state] += 1
                    # Add MEMBER_ID to relevant matched set
                    if subscription_state == "live":
                        member_ids_by_state['live'].add(member_id)
                    elif subscription_state == "opted_out":
                        member_ids_by_state['opted_out'].add(member_id)
                else:
                    non_profile_members += 1
                    non_matched_subscription_state_counts[subscription_state] += 1
                    # Add MEMBER_ID to relevant non-matched set
                    if subscription_state == "live":
                        member_ids_by_state['non_matched_live'].add(member_id)
                    elif subscription_state == "opted_out":
                        member_ids_by_state['non_matched_opted_out'].add(member_id)

            except json.JSONDecodeError as json_error:
                app_logger.info(f"JSON decoding error for member {member_key}: {json_error}")
            except KeyError as key_error:
                app_logger.info(f"Missing expected key {str(key_error)} in member data for {member_key}")
            except Exception as e:
                app_logger.info(f"Unexpected error processing member {member_key}: {str(e)}")

        app_logger.info("Prepare response data with success True")
        response_data = {
            'success': True,
            'metadata': {
                'file_name': file_name,
                'total_members_count': total_members_count
            },
            'matched_members': matched_members,
            'non_matched_members': non_profile_members,
            'subscription_state_counts': dict(subscription_state_counts),
            'matched_subscription_state_counts': dict(matched_subscription_state_counts),
            'non_matched_subscription_state_counts': dict(non_matched_subscription_state_counts),
            'member_ids_by_state': {
                'live': list(member_ids_by_state['live']),
                'non_matched_live': list(member_ids_by_state['non_matched_live']),
                'opted_out': list(member_ids_by_state['opted_out']),
                'non_matched_opted_out': list(member_ids_by_state['non_matched_opted_out']),
                'deleted': list(member_ids_by_state['deleted'])  # Include deleted members
            }
        }

        app_logger.info(f"Clash members and profiles result for {username}")
        return response_data

    except redis.exceptions.ConnectionError as e:
        app_logger.info(f"Redis connection error: {str(e)}")
        return {'success': False, 'message': 'Redis connection error'}

    except Exception as e:
        app_logger.info(f"Error in clash_members_and_profiles: {str(e)}")
        return {'success': False, 'message': 'Internal server error'}

def load_profiles_into_redis(profiles, base_redis_key, username):
    """
    Load profiles into Redis in chunks of 1000 under keys with an index suffix.
    Deletes any pre-existing keys matching the base pattern before loading new data.
    """
    app_logger.info(f"load_profiles_into_redis entered with {base_redis_key}")
    redis_client = get_redis_client()
    app_logger.info("after calling get_redis_client")
    app_logger.info(f"Number of profiles to load: {len(profiles)}")
    chunk_size = 1000
    app_logger.info(f"chunk_size: {chunk_size}")

    try:
        num_chunks = math.ceil(len(profiles) / chunk_size)
        app_logger.info(f"Calculated num_chunks: {num_chunks}")
    except Exception as e:
        app_logger.info(f"Error calculating num_chunks: {e}")
        return  # Exit early if there's an error calculating chunks

    # Error handling around drop_old_redis_keys
    try:
        app_logger.info("Calling drop_old_redis_keys")
        drop_old_redis_keys(f"{base_redis_key}_*")
        app_logger.info("Finished drop_old_redis_keys")
    except Exception as e:
        app_logger.info(f"Error during drop_old_redis_keys: {e}")
        return  # Exit early if we can't drop old keys to avoid loading redundant data

    # Load each chunk of profiles into Redis under a separate key
    for i in range(num_chunks):
        chunk_start = i * chunk_size
        chunk_end = chunk_start + chunk_size
        profile_chunk = profiles[chunk_start:chunk_end]

        app_logger.info(f"Processing chunk {i + 1} with {len(profile_chunk)} profiles.")

        # Construct the Redis key for the current chunk
        redis_key = f"{base_redis_key}_{i + 1}"

        # Prepare the chunk data for Redis
        profiles_data = {}
        for profile in profile_chunk:
            try:
                # Clean the phone number before storing it
                phone_number = profile.get('phone_number', '')
                cleaned_phone_number = clean_phone_number(phone_number)

                if not cleaned_phone_number:
                    app_logger.info(f"Skipping profile due to invalid phone number: {phone_number}")
                    continue  # Skip if the phone number is invalid after cleaning

                # Update the profile with the cleaned phone number
                profile['phone_number'] = cleaned_phone_number

                # Use the cleaned phone number as the field name in Redis
                profiles_data[cleaned_phone_number] = json.dumps(profile)
            except Exception as e:
                app_logger.info(f"Error processing profile {profile}: {e}")

        # Store the chunk of profiles in Redis under the specific chunk key
        try:
            redis_client.hset(redis_key, mapping=profiles_data)  # Store all profiles in one operation for this chunk
            record_count = len(profiles_data)
            app_logger.info(f"Data loaded into Redis with key {redis_key}. Total records created: {record_count}.")
        except Exception as e:
            app_logger.info(f"Error storing data in Redis for key {redis_key}: {e}")
            return  # Exit early if storing in Redis fails

    # Determine if there are multiple chunks
    more_chunks = num_chunks > 1

    # Redis and environment configuration settings
    configuration_key = f"configuration_{username}"
    configuration = redis_client.hgetall(configuration_key)

    test_mode_enabled = configuration.get(b'test_mode_enabled', b'0') == b'1' if configuration else False
    max_workers = int(configuration.get(b'max_community_workers', 10)) if configuration else int(os.getenv('MAX_COMMUNITY_WORKERS', 10))

    app_logger.info(f"Test mode for {username}: {test_mode_enabled}")
    app_logger.info(f"Max workers for {username}: {max_workers}")

    # Set initial status in Redis
    redis_status_key = f"{username}_import_status"
    status_data = {
        'status': 'initialised',
        'processed_profiles': 0,
        'total_profiles': len(profiles),
        'chunk_number': 1,
        'number_of_chunks': num_chunks,
        'number_of_chunks_processed': 0,
        'message': 'Ready to Import',
        'successful_imports': 0,
        'import_started_at': 0,
        'import_ended_at': 0,
        'total_time_taken': 0,
        'more_chunks': more_chunks,
        'max_workers': max_workers,
        'test_mode_enabled': test_mode_enabled
    }

    try:
        redis_client.set(redis_status_key, json.dumps(status_data))
        pretty_status_data = json.dumps(status_data, indent=4)  # Pretty format the JSON data
        app_logger.info(f"Initial status set in Redis under key {redis_status_key}:\n{pretty_status_data}")
    except Exception as e:
        app_logger.info(f"Failed to set initial status in Redis: {e}")

    app_logger.info("load_profiles_into_redis completed and returning")

# Function to clean, normalize, drop leading 0, prepend '1' if the number is 10 digits long, and validate US numbers
def clean_phone_number(phone):
    # Remove all non-digit characters
    cleaned_phone = re.sub(r'\D', '', phone)

    # Check if the phone starts with '0' after cleaning and drop it
    if cleaned_phone.startswith('0'):
        cleaned_phone = cleaned_phone[1:]

    # If the cleaned phone number is exactly 10 digits long, prepend '1'
    if len(cleaned_phone) == 10:
        cleaned_phone = '1' + cleaned_phone

    # Validate if it's a US phone number and check for proper structure
    if len(cleaned_phone) == 11 and cleaned_phone.startswith('1'):  # Check if it's a valid US number format
        area_code = cleaned_phone[1:4]  # First three digits after '1'
        central_office_code = cleaned_phone[4:7]  # Next three digits
        subscriber_number = cleaned_phone[7:]  # Last four digits

        # Area code must follow the rules: first digit 2-9, second digit 0-8
        if not (area_code[0] in '23456789' and area_code[1] in '012345678'):
            app_logger.info(f"Invalid US phone number due to area code: {cleaned_phone}")
            return None  # Invalid number due to area code rules

        # Central office code must start with 2-9
        if not central_office_code[0] in '23456789':
            app_logger.info(f"Invalid US phone number due to central office code: {cleaned_phone}")
            return None  # Invalid number due to central office code rules

        # Extra validation: Check for parts that are all zeros (e.g., central office code like '000')
        if area_code == '000' or central_office_code == '000' or subscriber_number == '0000':
            app_logger.info(f"Invalid US phone number due to all-zero section: {cleaned_phone}")
            return None  # Invalid number due to having an all-zero part

    # app_logger.info(f"clean_phone_number {phone} --> {cleaned_phone}")

    return cleaned_phone

def drop_old_redis_keys(pattern):
    """
    Drops all Redis keys that match the given pattern.
    """
    try:
        redis_client = get_redis_client()

        # Fetch all keys matching the pattern
        matching_keys = redis_client.keys(pattern)

        if not matching_keys:
            app_logger.info(f"No matching keys found for pattern: {pattern}")
            return

        # Delete all matching keys
        for key in matching_keys:
            redis_client.delete(key)
            app_logger.info(f"Deleted key: {key.decode('utf-8')}")

    except redis.exceptions.ConnectionError as e:
        priapp_logger.infont(f"Redis connection error: {str(e)}")
    except Exception as e:
        app_logger.info(f"Error dropping keys: {str(e)}")

def create_stage_csv_files(username, silent=False):
    """
    Extracts profiles with unmatched phone numbers (where a phone number exists in profiles but is not found in members),
    and writes them to a CSV file. Invalid phone numbers (non-digit, except for a leading '+'), numbers that are too short,
    numbers that are too long, and older duplicates will be written to stage1_dropped.csv. A reason for dropping will also be logged.
    The stage1.csv will also include a 'channel' column with values 'SMS' or 'WhatsApp', and an 'already a member' column
    indicating if the phone number is present in members_.

    Parameters:
    - username: The user identifier for retrieving profiles and members from Redis.
    - silent: If True, suppresses output to stdout and returns file names and statistics instead.
    """
    app_logger.info(f"Entered create_stage_csv_files: {username}")

    redis_client = get_redis_client()
    profiles_key = f"profiles_{username}"
    members_key = f"members_{username}"

    # Fetch metadata from members hash
    file_name = redis_client.hget(members_key, "file_name").decode('utf-8') if redis_client.hexists(members_key, "file_name") else "Unknown"
    total_members_count = int(redis_client.hget(members_key, "total_members_count").decode('utf-8')) if redis_client.hexists(members_key, "total_members_count") else 0

    # Other Counters and dictionaries
    drop_counts = {
        'Invalid format': 0,
        'Too short': 0,
        'Too long': 0,
        'Older duplicate': 0,
        'Invalid length for +1': 0
    }
    channel_counts = {
        'SMS': 0,
        'WhatsApp': 0
    }
    unique_phone_numbers = {}
    already_member_counts = {
        'TRUE': {'total': 0, 'channel': {}, 'subscription_state': {}},
        'FALSE': {'total': 0, 'channel': {}, 'subscription_state': {}}
    }
    deleted_subscription_count = 0  # Counter for deleted subscription states

    # List to hold records that contribute to the total for already_member 'FALSE' in SMS
    not_members_sms_records = []

    try:
        profiles = redis_client.hgetall(profiles_key)
        members = redis_client.hgetall(members_key)

        if not members:
            app_logger.info(f"Cannot find members: {members_key}")
        else:
            app_logger.info(f"Found members: {members_key}")

        if not profiles:
            app_logger.info(f"Cannot find profiles: {profiles_key}")
            if not silent:
                print(f"No profiles found for user {username}.")
            return None, None, None  # No files created if there are no profiles
        else:
            app_logger.info(f"Found profiles: {profiles_key}")

        # Prepare the path to save the CSV files
        app_logger.info("Prepare the path to save the CSV files")
        user_directory = f"/home/bryananthonyobrien/mysite/data/klayvio/{username}"
        os.makedirs(user_directory, exist_ok=True)
        valid_csv_file_path = os.path.join(user_directory, 'stage1.csv')
        dropped_csv_file_path = os.path.join(user_directory, 'stage1_dropped.csv')

        app_logger.info("Define members fieldnames")
        members_fieldnames = [
            'Phone Number',
            'MEMBER_ID',
            'LEADER_ID',
            'CHANNEL',
            'SUBSCRIPTION_STATE',
            'FIRST_NAME',
            'LAST_NAME',
            'EMAIL',
            'DATE_OF_BIRTH',
            'GENDER',
            'CITY',
            'ZIP_CODE',
            'STATE',
            'STATE_CODE',
            'COUNTRY',
            'COUNTRY_CODE',
            'DEVICE_TYPE',
            'FIRST_ACTIVATED_AT'
        ]

        # Open the CSV files for writing
        app_logger.info("Open the CSV files for writing")

        with open(valid_csv_file_path, mode='w', newline='') as valid_csv_file, \
             open(dropped_csv_file_path, mode='w', newline='') as dropped_csv_file:

            # Updated fieldnames for valid CSV including member fields
            app_logger.info("Updated fieldnames for valid CSV including member fields")
            fieldnames = [
                'Email', 'Phone Number', 'First Name', 'Last Name', 'City', 'Country', 'Region', 'Zip', 'Latitude', 'Longitude',
                'Channel', 'Already a Member', 'Birthday', 'Gender', 'Created', 'Updated', 'Last Event' ,'IP Address',
                'country_source', 'city_source', 'region_source', 'zip_source',
                'MEMBER_ID', 'LEADER_ID', 'CHANNEL', 'PHONE_NUMBER',
                'SUBSCRIPTION_STATE', 'FIRST_NAME', 'LAST_NAME', 'EMAIL',
                'DATE_OF_BIRTH', 'GENDER', 'CITY', 'ZIP_CODE',
                'STATE', 'STATE_CODE', 'COUNTRY', 'COUNTRY_CODE',
                'DEVICE_TYPE', 'FIRST_ACTIVATED_AT'
            ]
            dropped_fieldnames = fieldnames + ['Drop Reason']  # Add 'Drop Reason' column to the dropped file

            # CSV writers
            valid_writer = csv.DictWriter(valid_csv_file, fieldnames=fieldnames)
            dropped_writer = csv.DictWriter(dropped_csv_file, fieldnames=dropped_fieldnames)

            # Write headers for both files
            valid_writer.writeheader()
            dropped_writer.writeheader()

            # Function to extract the 'created' attribute and convert it to a datetime object
            def extract_created(profile):
                created_str = profile.get('created', '')
                try:
                    return datetime.strptime(created_str, '%Y-%m-%dT%H:%M:%S%z')
                except (ValueError, TypeError):
                    return None

            # Function to determine the channel (SMS or WhatsApp)
            def determine_channel(phone_number):
                cleaned_phone = clean_phone_number(phone_number)
                return 'SMS' if cleaned_phone.startswith('1') else 'WhatsApp'

            # Prepare a mapping of members for quick lookup, skipping metadata keys
            app_logger.info("Prepare a mapping of members for quick lookup")
            members_dict = {}
            for member_key, member_data in members.items():

                # Handle metadata keys directly
                if member_key == b'file_name':
                    app_logger.info(f"Skipping metadata key: {member_key}, Value: {member_data.decode('utf-8')}")
                    continue
                if member_key == b'total_members_count':
                    total_members_count = int(member_data.decode('utf-8'))  # Convert to integer
                    app_logger.info(f"Total members count: {total_members_count}")
                    continue

                try:
                    if not member_data:
                        app_logger.info(f"Empty or missing data for member {member_key}. Skipping.")
                        continue

                    # Attempt to decode the JSON data
                    member_profile = json.loads(member_data.decode('utf-8'))
                    phone_number = member_profile.get('PHONE_NUMBER', '').lstrip('+')
                    members_dict[phone_number] = member_profile

                    # Count deleted subscription states
                    if member_profile.get('SUBSCRIPTION_STATE', '').lower() == 'deleted':
                        deleted_subscription_count += 1
                except json.JSONDecodeError as e:
                    app_logger.info(f"JSON decoding error for member {member_key}: {e}")
                    app_logger.info(f"Raw data: {member_data}")
                except Exception as e:
                    app_logger.info(f"Unexpected error processing member {member_key}: {e}")
                    app_logger.info(f"Raw data: {member_data}")
                    app_logger.info(f"Error: {e}")

            # Iterate over the profiles (which are JSON encoded)
            app_logger.info("Iterate over the profiles (which are JSON encoded)")
            n_profiles = 0
            for profile_id, profile_data in profiles.items():
                n_profiles += 1
                profile = json.loads(profile_data.decode('utf-8'))

                phone_number = profile.get('phone_number')
                if phone_number is not None:
                    phone_number = phone_number.strip()
                    cleaned_phone_number = clean_phone_number(phone_number)
                    created_at = extract_created(profile)

                    # Drop reasons
                    drop_reason = None
                    if not cleaned_phone_number:
                        drop_reason = 'Invalid format'
                    elif len(cleaned_phone_number.lstrip('+')) < 10:
                        drop_reason = 'Too short'
                    elif len(cleaned_phone_number.lstrip('+')) > 15:
                        drop_reason = 'Too long'
                    elif len(cleaned_phone_number.lstrip('+')) != 11 and cleaned_phone_number.lstrip('+')[0] == '1':
                        drop_reason = 'Invalid length for +1'

                    # If a drop reason exists, log it in stage1_dropped.csv
                    if drop_reason:
                        drop_counts[drop_reason] += 1
                        dropped_writer.writerow({
                            'Email': profile.get('email', '') or '',
                            'Phone Number': phone_number,
                            'First Name': profile.get('first_name', '') or '',
                            'Last Name': profile.get('last_name', '') or '',
                            'City': profile.get('city', '') or '',
                            'Country': profile.get('country', '') or '',
                            'Region': profile.get('region', '') or '',
                            'Zip': profile.get('zip', '') or '',
                            'Latitude': profile.get('latitude', '') or '',
                            'Longitude': profile.get('longitude', '') or '',
                            'Channel': '',
                            'Birthday': profile.get('birthday', '') or '',
                            'Gender': profile.get('gender', '') or '',
                            'Drop Reason': drop_reason
                        })
                        continue  # Skip this profile for the valid CSV

                    # Handle duplicates by keeping the most recent based on 'created' timestamp
                    if cleaned_phone_number in unique_phone_numbers:
                        existing_profile, existing_created_at = unique_phone_numbers[cleaned_phone_number]
                        drop_counts['Older duplicate'] += 1

                        if created_at and existing_created_at:
                            if created_at > existing_created_at:
                                dropped_writer.writerow({
                                    'Email': existing_profile.get('email', '') or '',
                                    'Phone Number': cleaned_phone_number.lstrip('+'),
                                    'First Name': existing_profile.get('first_name', '') or '',
                                    'Last Name': existing_profile.get('last_name', '') or '',
                                    'City': existing_profile.get('city', '') or '',
                                    'Country': existing_profile.get('country', '') or '',
                                    'Region': existing_profile.get('region', '') or '',
                                    'Zip': existing_profile.get('zip', '') or '',
                                    'Latitude': existing_profile.get('latitude', '') or '',
                                    'Longitude': existing_profile.get('longitude', '') or '',
                                    'Channel': '',
                                    'Birthday': existing_profile.get('birthday', '') or '',
                                    'Gender': existing_profile.get('gender', '') or '',
                                    'Drop Reason': 'Older duplicate'
                                })
                                unique_phone_numbers[cleaned_phone_number] = (profile, created_at)
                                # app_logger.info("Dropped Exiting Profile - this one is more recent")
                                # drop_counts['Older duplicate'] += 1
                                continue
                            else:
                                dropped_writer.writerow({
                                    'Email': profile.get('email', '') or '',
                                    'Phone Number': cleaned_phone_number.lstrip('+'),
                                    'First Name': profile.get('first_name', '') or '',
                                    'Last Name': profile.get('last_name', '') or '',
                                    'City': profile.get('city', '') or '',
                                    'Country': profile.get('country', '') or '',
                                    'Region': profile.get('region', '') or '',
                                    'Zip': profile.get('zip', '') or '',
                                    'Latitude': profile.get('latitude', '') or '',
                                    'Longitude': profile.get('longitude', '') or '',
                                    'Channel': '',
                                    'Birthday': profile.get('birthday', '') or '',
                                    'Gender': profile.get('gender', '') or '',
                                    'Drop Reason': 'Older duplicate'
                                })
                                # app_logger.info("Dropped Profile - have a more recent")
                                # drop_counts['Older duplicate'] += 1
                                continue
                        else:
                            dropped_writer.writerow({
                                'Email': existing_profile.get('email', '') or '',
                                'Phone Number': cleaned_phone_number.lstrip('+'),
                                'First Name': existing_profile.get('first_name', '') or '',
                                'Last Name': existing_profile.get('last_name', '') or '',
                                'City': existing_profile.get('city', '') or '',
                                'Country': existing_profile.get('country', '') or '',
                                'Region': existing_profile.get('region', '') or '',
                                'Zip': existing_profile.get('zip', '') or '',
                                'Latitude': existing_profile.get('latitude', '') or '',
                                'Longitude': existing_profile.get('longitude', '') or '',
                                'Channel': '',
                                'Birthday': existing_profile.get('birthday', '') or '',
                                'Gender': existing_profile.get('gender', '') or '',
                                'Drop Reason': 'Older duplicate'
                            })
                            unique_phone_numbers[cleaned_phone_number] = (profile, created_at)
                            # app_logger.info("Dropped Existing Profile - not sure if older")
                            # drop_counts['Older duplicate'] += 1
                            continue

                    else:
                        unique_phone_numbers[cleaned_phone_number] = (profile, created_at)

            app_logger.info(f"Number of profiles: {n_profiles}")
            # Write all unique phone numbers to the valid CSV
            app_logger.info("Write all unique phone numbers to the valid CSV")
            for cleaned_phone_number, (profile, created_at) in unique_phone_numbers.items():
                if cleaned_phone_number:
                    email = profile.get('email', '') or ''
                    first_name = profile.get('first_name', '') or ''
                    last_name = profile.get('last_name', '') or ''
                    city = profile.get('city', '') or ''
                    country = profile.get('country', '') or ''
                    region = profile.get('region', '') or ''
                    zip_code = profile.get('zip', '') or ''
                    latitude = profile.get('latitude', '') or ''
                    longitude = profile.get('longitude', '') or ''
                    birthday = profile.get('birthday', '') or ''
                    gender = profile.get('gender', '') or ''
                    created = profile.get('created', '') or ''
                    updated = profile.get('updated', '') or ''
                    last_event_date = profile.get('last_event_date', '') or ''
                    ip = profile.get('ip', '') or ''

                    country_source = profile.get('country_source', '') or ''
                    city_source = profile.get('city_source', '') or ''
                    region_source = profile.get('region_source', '') or ''
                    zip_source = profile.get('zip_source', '') or ''

                    # Determine the channel
                    channel = determine_channel(cleaned_phone_number)
                    channel_counts[channel] += 1

                    # Look up member data based on the cleaned phone number
                    member_data = members_dict.get(cleaned_phone_number.lstrip('+'), {})

                    already_member = cleaned_phone_number.lstrip('+') in members_dict

                    valid_writer.writerow({
                        'Email': email,
                        'Phone Number': cleaned_phone_number.lstrip('+'),
                        'First Name': first_name,
                        'Last Name': last_name,
                        'City': city,
                        'Country': country,
                        'Region': region,
                        'Zip': zip_code,
                        'Latitude': latitude,
                        'Longitude': longitude,
                        'Channel': channel,
                        'Already a Member': already_member,
                        'Birthday': birthday,
                        'Gender': gender,
                        'Created': created,
                        'Updated': updated,
                        'Last Event': last_event_date,
                        'IP Address': ip,
                        'country_source': country_source,
                        'city_source': city_source,
                        'region_source': region_source,
                        'zip_source': zip_source,
                        'MEMBER_ID': member_data.get("MEMBER_ID", ''),
                        'LEADER_ID': member_data.get("LEADER_ID", ''),
                        'CHANNEL': member_data.get("CHANNEL", ''),
                        'PHONE_NUMBER': member_data.get("PHONE_NUMBER", ''),
                        'SUBSCRIPTION_STATE': member_data.get("SUBSCRIPTION_STATE", ''),
                        'FIRST_NAME': member_data.get("FIRST_NAME", ''),
                        'LAST_NAME': member_data.get("LAST_NAME", ''),
                        'EMAIL': member_data.get("EMAIL", ''),
                        'DATE_OF_BIRTH': member_data.get("DATE_OF_BIRTH", ''),
                        'GENDER': member_data.get("GENDER", ''),
                        'CITY': member_data.get("CITY", ''),
                        'ZIP_CODE': member_data.get("ZIP_CODE", ''),
                        'STATE': member_data.get("STATE", ''),
                        'STATE_CODE': member_data.get("STATE_CODE", ''),
                        'COUNTRY': member_data.get("COUNTRY", ''),
                        'COUNTRY_CODE': member_data.get("COUNTRY_CODE", ''),
                        'DEVICE_TYPE': member_data.get("DEVICE_TYPE", ''),
                        'FIRST_ACTIVATED_AT': member_data.get("FIRST_ACTIVATED_AT", ''),
                    })

                    # Count members for breakdown
                    if already_member:
                        already_member_counts['TRUE']['total'] += 1
                        already_member_counts['TRUE']['channel'][channel] = already_member_counts['TRUE']['channel'].get(channel, 0) + 1

                        # Initialize the subscription state dictionary if it doesn't exist
                        subscription_state = member_data.get("SUBSCRIPTION_STATE", '')
                        if subscription_state not in already_member_counts['TRUE']['subscription_state']:
                            already_member_counts['TRUE']['subscription_state'][subscription_state] = {}

                        # Increment count for the subscription state by channel
                        already_member_counts['TRUE']['subscription_state'][subscription_state][channel] = already_member_counts['TRUE']['subscription_state'][subscription_state].get(channel, 0) + 1
                    else:
                        already_member_counts['FALSE']['total'] += 1
                        already_member_counts['FALSE']['channel'][channel] = already_member_counts['FALSE']['channel'].get(channel, 0) + 1
                        subscription_state = member_data.get("SUBSCRIPTION_STATE", '')
                        already_member_counts['FALSE']['subscription_state'][subscription_state] = already_member_counts['FALSE']['subscription_state'].get(subscription_state, 0) + 1

                    # If this profile is not already a member and the channel is SMS, store it in not_members_sms_records
                    if not already_member and channel == 'SMS':
                        not_members_sms_records.append(profile)

        # Print drop counts
        total_dropped = sum(drop_counts.values())
        app_logger.info(f"CSV file stage1.csv created successfully at {valid_csv_file_path}.")
        app_logger.info(f"CSV file stage1_dropped.csv created successfully at {dropped_csv_file_path}.")

        # Now create stage2.csv
        app_logger.info("Now create stage2.csv")
        stage2_csv_path = os.path.join(user_directory, 'stage2.csv')
        with open(stage2_csv_path, mode='w', newline='') as stage2_file:
            stage2_writer = csv.DictWriter(stage2_file, fieldnames=members_fieldnames)
            stage2_writer.writeheader()  # Write header for stage2.csv

            # Load phone numbers from stage1.csv
            app_logger.info("Load phone numbers from stage1.cs")
            stage1_phone_numbers = set()
            with open(valid_csv_file_path, mode='r', newline='') as stage1_file:
                valid_reader = csv.DictReader(stage1_file)
                for row in valid_reader:
                    stage1_phone_numbers.add(row['Phone Number'])

            # Write members not in stage1.csv to stage2.csv, skipping metadata keys
            app_logger.info("Write members not in stage1.csv to stage2.csv")
            for member_key, member_data in members.items():
                if member_key.decode('utf-8') in {"file_name", "total_members_count"}:
                    continue
                try:
                    member_profile = json.loads(member_data.decode('utf-8'))
                    member_phone_number = member_profile.get('PHONE_NUMBER', '').lstrip('+')  # Normalize phone number
                    if member_phone_number and member_phone_number not in stage1_phone_numbers:
                        stage2_writer.writerow({
                            'Phone Number': member_phone_number,
                            'MEMBER_ID': member_profile.get('MEMBER_ID', ''),
                            'LEADER_ID': member_profile.get('LEADER_ID', ''),
                            'CHANNEL': member_profile.get('CHANNEL', ''),
                            'SUBSCRIPTION_STATE': member_profile.get('SUBSCRIPTION_STATE', ''),
                            'FIRST_NAME': member_profile.get('FIRST_NAME', ''),
                            'LAST_NAME': member_profile.get('LAST_NAME', ''),
                            'EMAIL': member_profile.get('EMAIL', ''),
                            'DATE_OF_BIRTH': member_profile.get('DATE_OF_BIRTH', ''),
                            'GENDER': member_profile.get('GENDER', ''),
                            'CITY': member_profile.get('CITY', ''),
                            'ZIP_CODE': member_profile.get('ZIP_CODE', ''),
                            'STATE': member_profile.get('STATE', ''),
                            'STATE_CODE': member_profile.get('STATE_CODE', ''),
                            'COUNTRY': member_profile.get('COUNTRY', ''),
                            'COUNTRY_CODE': member_profile.get('COUNTRY_CODE', ''),
                            'DEVICE_TYPE': member_profile.get('DEVICE_TYPE', ''),
                            'FIRST_ACTIVATED_AT': member_profile.get('FIRST_ACTIVATED_AT', ''),
                        })
                except json.JSONDecodeError as e:
                    app_logger.info(f"JSON decoding error for member {member_key}: {e}")

        app_logger.info(f"Stage2 CSV file created successfully at {stage2_csv_path}.")

        # Prepare return values for silent mode
        app_logger.info("Prepare return values for silent mode")
        total_stage1_rows = sum(1 for _ in open(valid_csv_file_path)) - 1  # Exclude header
        total_dropped_rows = sum(1 for _ in open(dropped_csv_file_path)) - 1  # Exclude header
        total_stage2_rows = sum(1 for _ in open(stage2_csv_path)) - 1  # Exclude header

        result = {
            'timestamp': datetime.now().isoformat(),  # Add timestamp
            'metadata': {
                 'file_name': file_name,
                 'total_members_count': total_members_count
             },
            'stage1.csv': {
                'path': valid_csv_file_path,
                'row_count': total_stage1_rows,
                'channel_counts': channel_counts,
                'already_member': already_member_counts,
                'deleted_members': deleted_subscription_count  # Count of deleted subscription states
            },
            'stage1_dropped.csv': {
                'path': dropped_csv_file_path,
                'row_count': total_dropped_rows,
                'drop_counts': drop_counts  # Add drop counts
            },
            'stage2.csv': {
                'path': stage2_csv_path,
                'row_count': total_stage2_rows,
                'channel_counts': {}
            }
        }

        # Count channels in stage2
        app_logger.info("Count channels in stage2")
        with open(stage2_csv_path, mode='r', newline='') as stage2_file:
            stage2_reader = csv.DictReader(stage2_file)
            for row in stage2_reader:
                channel = row.get('CHANNEL', '')
                subscription_state = row.get('SUBSCRIPTION_STATE', '')
                if channel:
                    result['stage2.csv']['channel_counts'][channel] = result['stage2.csv']['channel_counts'].get(channel, {})
                    result['stage2.csv']['channel_counts'][channel]['total'] = result['stage2.csv']['channel_counts'][channel].get('total', 0) + 1
                    result['stage2.csv']['channel_counts'][channel]['subscription_state'] = result['stage2.csv']['channel_counts'][channel].get('subscription_state', {})
                    result['stage2.csv']['channel_counts'][channel]['subscription_state'][subscription_state] = result['stage2.csv']['channel_counts'][channel]['subscription_state'].get(subscription_state, 0) + 1

        # Store eligible SMS profiles in Redis with chunked keys
        app_logger.info("Store eligible SMS profiles in Redis with chunked keys")
        sms_profiles_base_key = f"sms_profiles_eligible_to_import_to_community_{username}"
        app_logger.info(f"sms_profiles_base_key : {sms_profiles_base_key}")
        load_profiles_into_redis(not_members_sms_records, sms_profiles_base_key, username)
        app_logger.info("load_profiles_into_redis completed")

        if silent:
            return result
        else:
            print(f"Total dropped: {total_dropped}")
            print(f"Number of phone numbers by channel:")
            for channel, count in channel_counts.items():
                print(f"  {channel}: {count}")
            print("JSON Output:")
            print(json.dumps(result, indent=4))  # Pretty print the JSON

    except redis_exceptions.ConnectionError as e:
        print(f"Redis connection error: {str(e)}")
    except Exception as e:
        print(f"Error processing profiles: {str(e)}")

def get_user_data(user_id):
    global cache_status
    try:
        redis_client = get_redis_client()
        user_data = redis_client.hgetall(user_id)

        # If no data is found, return default values for all attributes
        if not user_data:
            user_data = {
                'api_calls': 0, 
                'credits': 0, 
                'user_status': 'active', 
                'password': None,
                'login_attempts': 0, 
                'last_login_attempt': 'None', 
                'is_logged_in_now': 0,
                'created': 'None', 
                'role': 'client'
            }

        # Ensure 'api_calls' is in the data
        if 'api_calls' not in user_data:
            user_data['api_calls'] = 0

        # Decode all byte-encoded values and handle them appropriately
        decoded_data = {}
        for k, v in user_data.items():
            # If the key is a byte string, decode it
            decoded_key = k.decode('utf-8') if isinstance(k, bytes) else k
            
            # If the value is a byte string, decode it
            if isinstance(v, bytes):
                decoded_value = v.decode('utf-8')  # Decode value to string
                # If it's a value we expect to be numeric, convert it to integer
                if decoded_key in ['login_attempts', 'credits', 'is_logged_in_now', 'api_calls']:
                    try:
                        decoded_value = int(decoded_value)
                    except ValueError:
                        decoded_value = 0  # Fallback to 0 if not convertible to integer
            else:
                decoded_value = v

            decoded_data[decoded_key] = decoded_value

        # Now user_data is fully decoded and ready to be used
        app_logger.info(f"get_user_data: User: {user_id}, Decoded Data: {decoded_data}")

        cache_status = "Cache Available"
        return decoded_data, cache_status  # Return decoded data

    except redis_exceptions.ConnectionError as e:
        app_logger.info(f"Redis connection error in get_user_data: {str(e)}")
        cache_status = "Cache Unavailable"
        return {
            'api_calls': 0, 
            'credits': 0, 
            'user_status': 'active', 
            'password': None,
            'login_attempts': 0, 
            'last_login_attempt': 'None', 
            'is_logged_in_now': 0,
            'created': 'None', 
            'role': 'client'
        }, cache_status  # Fallback to default values

