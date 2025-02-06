import os
import requests
import json
from logs import app_logger
from logging import getLogger

from datetime import datetime
import time
from redis import Redis
from redis import exceptions as redis_exceptions
import urllib.parse
import logging
from logging.handlers import RotatingFileHandler


# Enable detailed debug logging for urllib3 (used by requests)
logging.getLogger('urllib3').setLevel(logging.DEBUG)


# Function to get Redis client
def get_redis_client():
    return Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        password=os.getenv('REDIS_PASSWORD', None),
        db=int(os.getenv('REDIS_DB', 0))
    )

# Helper to create a unique logger for async operations
def create_user_logger(username):
    log_dir = os.path.expanduser('~/logs')
    os.makedirs(log_dir, exist_ok=True)  # Ensure the log directory exists
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f'klaviyo_async_{username}_{timestamp}.log')

    logger = logging.getLogger(f'klaviyo_async_{username}')
    handler = RotatingFileHandler(log_file, maxBytes=5000000, backupCount=5)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    return logger


# Get Klaviyo Profile Count
def get_klaviyo_profile_count(phone_number, logger=None):
    logger = logger or app_logger
    klaviyo_private_api_key = os.getenv('KLAVIYO_READ_PROFILE_API_KEY')

    if not klaviyo_private_api_key:
        logger.error("Klaviyo Private API key not set in environment variables.")
        return 1  # Default deduction if API key is missing

    klaviyo_url = f"https://a.klaviyo.com/api/profiles/?filter=equals(phone_number,\"{phone_number}\")&page[size]=20"
    headers = {
        "Authorization": f"Klaviyo-API-Key {klaviyo_private_api_key}",
        "Accept": "application/json",
        "Revision": "2024-07-15"
    }

    try:
        response = requests.get(klaviyo_url, headers=headers)
        response.raise_for_status()

        data = response.json()
        profile_count = len(data.get('data', []))
        logger.debug(f"Klaviyo returned {profile_count} profiles for phone number {phone_number}")

        timestamp = datetime.utcnow().strftime('%Y-%m-%d-%H:%M:%S')
        filename = f"klaviyo_profiles_{timestamp}_{profile_count}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

        logger.debug(f"Klaviyo response logged to {filename}")
        return profile_count

    except requests.RequestException as e:
        logger.error(f"Error calling Klaviyo API: {str(e)}")
        logger.debug(f"Klaviyo API response: {response.text if 'response' in locals() else 'No response'}")
        return 1  # Fallback to the default deduction amount


def get_klaviyo_profiles(username, start_time, new_discovery=True, mode='sync', logger=None):
    logger = logger or getLogger(__name__)

    # Get Redis client
    redis_client = get_redis_client()
    redis_key = f"configuration_{username}"

    # Try to get Klaviyo API key from Redis first
    klaviyo_private_api_key = redis_client.hget(redis_key, 'KLAVIYO_READ_PROFILE_API_KEY')

    if klaviyo_private_api_key:
        # Decode the Redis value (as it is bytes) into a string
        klaviyo_private_api_key = klaviyo_private_api_key.decode('utf-8')
        logger.info(f"Klaviyo Private API key retrieved from Redis for user: {username}")
    else:
        # If not found in Redis, fallback to the environment variable
        klaviyo_private_api_key = os.getenv('KLAVIYO_READ_PROFILE_API_KEY')
        if not klaviyo_private_api_key:
            logger.error("Klaviyo Private API key not set in environment variables or Redis.")
            return

    base_url = "https://a.klaviyo.com/api/profiles/"
    headers = {
        "Authorization": f"Klaviyo-API-Key {klaviyo_private_api_key}",
        "Accept": "application/json",
        "Revision": "2024-07-15"
    }
    params = {"page[size]": 100}

    retry_attempts = 0
    max_retries = 5
    backoff_factor = 2
    file_sequence = 1
    total_profile_count = 0  # Track total profiles in sync mode

    try:
        # Define the user-specific directory to save Klaviyo data
        timestamp = start_time.strftime('%Y%m%d_%H%M%S')
        user_data_dir = f"/home/bryananthonyobrien/mysite/data/klayvio/{username}/{timestamp}"

        discovery_key = f"klaviyo_discovery_{username}_{start_time.strftime('%Y-%m-%d-%H:%M:%S')}"
        discovery_data = {
            "start_time": start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "end_time": "N/A",
            "profile_count": total_profile_count,  # Use the total profile count from both modes
            "file_location": user_data_dir,  # Save the directory location in Redis
            "status": "running"
        }

        redis_client.hset(f"klaviyo_discoveries_{username}", discovery_key, json.dumps(discovery_data))

        # Ensure the directory exists
        os.makedirs(user_data_dir, exist_ok=True)

        while retry_attempts < max_retries:
            try:
                # Request profiles data
                request_start_time = time.time()
                response = requests.get(base_url, headers=headers, params=params, timeout=(5, 5))

                request_duration = time.time() - request_start_time
                if response.status_code == 429:
                    retry_attempts += 1
                    retry_after = int(response.headers.get('Retry-After', 1))
                    logger.info(f"Rate limit exceeded. Retrying after {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                data = response.json()
                profiles = data.get('data', [])

                if not profiles:
                    break  # Exit loop when no more profiles are found

                total_profile_count += len(profiles)  # Increment profile count in sync mode
                discovery_data["profile_count"] = total_profile_count
                redis_client.hset(f"klaviyo_discoveries_{username}", discovery_key, json.dumps(discovery_data))


                # Save the JSON data in the user-specific directory
                filename = os.path.join(user_data_dir, f"klaviyo_profiles_{file_sequence}.json")
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=4)

                file_sequence += 1

                # For sync mode, check for the next page without Redis
                next_page = data.get('links', {}).get('next')
                if next_page:
                    next_cursor = urllib.parse.urlparse(next_page).query.split('=')[-1]
                    params["page[cursor]"] = next_cursor  # Add the next cursor to the request params
                else:
                    break  # Exit loop if there's no next page

            except requests.exceptions.ConnectTimeout:
                retry_attempts += 1
                logger.info("Connection timed out. Retrying...")
                time.sleep(backoff_factor ** retry_attempts)

            except requests.exceptions.ReadTimeout:
                retry_attempts += 1
                logger.info("Read timeout occurred. Retrying...")
                time.sleep(backoff_factor ** retry_attempts)

            except requests.RequestException as e:
                retry_attempts += 1
                logger.info(f"Error calling Klaviyo API: {str(e)}")
                time.sleep(backoff_factor ** retry_attempts)

                if retry_attempts >= max_retries:
                    logger.info(f"Max retries exceeded for user {username}.")
                    discovery_data["status"] = "failed"
                    redis_client.hset(f"klaviyo_discoveries_{username}", discovery_key, json.dumps(discovery_data))
                    return

        # Final step after the loop
        end_time = datetime.utcnow().strftime('%Y-%m-%d-%H:%M:%S')
        discovery_data["end_time"] = end_time
        discovery_data["profile_count"] = total_profile_count
        discovery_data["status"] = "complete"
        redis_client.hset(f"klaviyo_discoveries_{username}", discovery_key, json.dumps(discovery_data))

        logger.info(f"Sync discovery complete for {username}. Total profiles retrieved: {total_profile_count}")
        return total_profile_count  # Return the total profile count in sync mode

    except Exception as e:
        logger.info(f"Unexpected error during Klaviyo discovery for user {username}: {str(e)}")
        discovery_data["status"] = "failed"
        redis_client.hset(f"klaviyo_discoveries_{username}", discovery_key, json.dumps(discovery_data))



# Main Discovery Function
def do_klaviyo_discovery(mode='sync', username=None):
    start_time = datetime.utcnow()

    if mode == 'sync':
        app_logger.info("Performing synchronous Klaviyo discovery")
        try:
            # Capture the returned profile count from sync mode
            total_profiles = get_klaviyo_profiles(username, start_time, mode='sync', logger=app_logger)

            # Return the result, including the total profiles retrieved
            return {
                "result": "Klaviyo discovery complete",
                "mode": "synchronous",
                "total_profiles": total_profiles  # Include the number of profiles retrieved
            }
        except Exception as e:
            app_logger.error(f"Error in synchronous discovery for user {username}: {str(e)}")
            return {"result": "Error during Klaviyo discovery", "mode": "synchronous", "error": str(e)}

    else:
        app_logger.error(f"Invalid mode '{mode}' provided to do_klaviyo_discovery")
        return {"error": "Invalid mode"}
