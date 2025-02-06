import requests
import os
from logs import app_logger
from cache import get_redis_client
from countries import normalize_state
import re
import json

from unidecode import unidecode

def normalize_name(given_name, surname):
    # Normalize given name if it contains non-ASCII characters
    if not given_name.isascii():
        given_name = unidecode(given_name)  # Transliterate given name
    # Normalize surname if it contains non-ASCII characters
    if not surname.isascii():
        surname = unidecode(surname)  # Transliterate surname

    return given_name.strip(), surname.strip()

def normalize_city(city):
    # Check if city contains non-ASCII characters
    if city and not city.isascii():
        city = unidecode(city)  # Transliterate city
    return city


def to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None  # Use None for invalid or missing values

def Community_subscription_create(tag, community_client_id, community_api_token, data, username, mode='single', local_payload_structure=None, test_mode=False):
    """
    Create a subscription for the given user and data, with support for checking duplicates
    in-memory and optionally in Redis.
    """

    if mode == 'single':
        app_logger.info(f"data : {data}")

    # Prepare the API URL and headers for subscription create
    api_url = f"https://api.community.com/webhooks/v1/community/{community_client_id}/subscription_create"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {community_api_token}"
    }

    # Prepare the request payload with phone_number being mandatory
    if not data.get("phone_number"):
        app_logger.error("phone_number is required.")
        return None  # Return None or raise an exception based on your error handling strategy

    region = data.get("state_name", "")
    country = data.get("country_name", "")

    # Normalize the region to get state code, name, and country details
    state_code, state_name, country_name, country_code = normalize_state(region, country)

    if mode == 'single':
        app_logger.info(f" {state_code}, {state_name}, {country_name}, {country_code} <-- normalize_state({region} {country})")

    # Determine the communication channel (default is 'sms')
    channel = data.get("channel", "sms").lower()
    communication_channel = "whatsapp" if channel == "whatsapp" else "sms"
    email = data.get("email") or ''
    # Check if the email matches the dummy pattern
    if re.match(r'^dummy\d+@bryanworx\.com$', email):
        email = ''  # Set email to an empty string if it matches the pattern


    given_name = data.get("first_name", "")
    surname = data.get("last_name", "")

    normalized_given_name, normalized_surname = normalize_name(given_name, surname)
    if mode == 'single':
        app_logger.info(f" {normalized_given_name}, {normalized_surname} <-- normalize_name({given_name} {surname})")

    city = data.get("city", "")
    normalized_city = normalize_city(city)
    if mode == 'single':
        app_logger.info(f" {normalized_city} <-- normalized_city({city})")

    postal_code = data.get("zip","")
    potential_payload = {
        "phone_number": data.get("phone_number"),  # Mandatory field
        "given_name": normalized_given_name,
        "surname": normalized_surname,
        "email": email,
        "city": normalized_city,
        "state_or_province": state_name or '',  # Use normalized state name
        "state_or_province_abbreviation": state_code or '',  # Use normalized state code
        "country": country_name or '',  # Use normalized country name
        "country_code": country_code or '',  # Use normalized country code
        "postal_code": postal_code,
        "date_of_birth": data.get("birthday") or '',  # Optional
        "gender_identity": data.get("gender") or '',  # Optional
        "geolocation": {
            "latitude": to_float(data.get("latitude")) or '',
            "longitude": to_float(data.get("longitude")) or ''
        },
        "communication_channel": communication_channel  # Dynamic based on channel
    }

    ip = data.get("ip", "")

    # Filter out keys with empty string values and remove empty geolocation fields
    payload = {k: v for k, v in potential_payload.items() if v != ''}

    # Remove 'geolocation' if both latitude and longitude are empty or missing
    if "geolocation" in payload and (
        payload["geolocation"].get("latitude") in [None, ''] and
        payload["geolocation"].get("longitude") in [None, '']
    ):
        del payload["geolocation"]

    if mode == 'single':
        app_logger.debug(f"Payload: [test_mode : {test_mode}] {payload}")

    # Initialize a fake response object for test mode
    if test_mode:
        if mode == 'single':
            app_logger.info(f"Test mode enabled. Skipping subscription_create API call for {username}.")
        response = type('obj', (object,), {'status_code': 202, 'text': 'Test mode: success'})()  # Fake response
    else:
        # Make the POST request to the API
        try:
            response = requests.post(api_url, headers=headers, json=payload)
        except requests.exceptions.RequestException as e:
            app_logger.error(f"Error during subscription create: {str(e)}")
            return None

    # Check for the HTTP status code
    if response.status_code == 202:
        # Proceed with adding the tag after a successful 202 response
        add_tag_response = add_member_to_sub_community(tag, community_client_id, community_api_token, username, data.get("phone_number"), communication_channel, mode, test_mode)

        if add_tag_response:
            return {
                "status": "success",
                "message": "Subscription created and member added to sub-community."
            }
        else:
            return {
                "status": "partial_success",
                "message": "Subscription created, but failed to add member to sub-community."
            }
    else:
        app_logger.error(f"Failed to create subscription: HTTP {response.status_code}, Response: {response.text}")
        return None

def add_member_to_sub_community(tag, community_client_id, community_api_token, username, phone_number, communication_channel, mode, test_mode=False):
    """
    Adds a member to a sub-community by tagging them.
    """

    # Prepare the API URL and headers for subscription tag modification
    tag_api_url = f"https://api.community.com/webhooks/v1/community/{community_client_id}/subscription_tag_modify"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {community_api_token}"
    }

    # Prepare the payload for tagging the member
    tag_payload = {
        "communication_channel": communication_channel,  # Dynamic channel
        "operation": "add",
        "tag": tag,
        "phone_number": phone_number
    }

    if mode == 'single':
        app_logger.info(f"Tagging payload: [test mode: {test_mode}] {tag_payload}")

    if test_mode:
        if mode == 'single':
            app_logger.info("Simulate success in test mode")
        return True  # Simulate success in test mode

    try:
        response = requests.post(tag_api_url, headers=headers, json=tag_payload)
        if response.status_code == 202:
            if mode == 'single':
                app_logger.info(f"Successfully tagged member {phone_number} with tag '{tag}' for user {username}.")
            return True
        else:
            app_logger.info(f"Failed to tag member: HTTP {response.status_code}, Response: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        app_logger.info(f"Error during tagging: {str(e)}")
        return False


def add_member_to_sub_community_old(tag, community_client_id, community_api_token, username, phone_number, mode, test_mode=False):
    """
    Adds a member to a sub-community by tagging them.

    If test mode is enabled, the API call is skipped but the logic is executed as normal.

    Args:
        username (str): The username associated with the request.
        phone_number (str): The phone number of the member to be tagged.
        test_mode (bool): If True, skips API calls but performs all other operations as normal.

    Returns:
        bool: True if the operation succeeded, False otherwise.
    """

    # Prepare the API URL and headers for subscription tag modification
    tag_api_url = f"https://api.community.com/webhooks/v1/community/{community_client_id}/subscription_tag_modify"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {community_api_token}"
    }

    # Prepare the payload for tagging the member
    tag_payload = {
        "communication_channel": "sms",
        "operation": "add",
        "tag": tag,
        "phone_number": phone_number
    }

    if mode == 'single':
        app_logger.info(f"Tagging payload: [test mode: {test_mode}] {tag_payload}")

    if test_mode:
        if mode == 'single':
            app_logger.info("Simulate success in test mode")
        return True  # Simulate success in test mode

    try:
        response = requests.post(tag_api_url, headers=headers, json=tag_payload)
        if response.status_code == 202:
            if mode == 'single':
                app_logger.info(f"Successfully tagged member {phone_number} with tag '{tag}' for user {username}.")
            return True
        else:
            app_logger.info(f"Failed to tag member: HTTP {response.status_code}, Response: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        app_logger.info(f"Error during tagging: {str(e)}")
        return False

def create_sub_community_tag(username, test_mode=False):
    """
    Creates a new tag for a sub-community.

    If test mode is enabled, the API call is skipped but the logic is executed as normal.

    Args:
        username (str): The username associated with the request.
        test_mode (bool): If True, skips API calls but performs all other operations as normal.

    Returns:
        bool: True if the operation succeeded, False otherwise.
    """

    redis_client = get_redis_client()
    redis_key = f"configuration_{username}"

    # Retrieve Community keys and sub_community from Redis
    community_client_id = redis_client.hget(redis_key, 'COMMUNITY_CLIENT_ID')
    community_api_token = redis_client.hget(redis_key, 'COMMUNITY_API_TOKEN')
    sub_community = redis_client.hget(redis_key, 'SUB_COMMUNITY')

    # Decode the values from Redis or fall back to environment variables where needed
    if community_client_id:
        community_client_id = community_client_id.decode('utf-8')
        app_logger.info(f"COMMUNITY_CLIENT_ID retrieved from Redis for user {username}")
    else:
        community_client_id = os.getenv('COMMUNITY_CLIENT_ID')
        if not community_client_id:
            app_logger.error("COMMUNITY_CLIENT_ID not set in Redis or environment variables.")
            return False

    if community_api_token:
        community_api_token = community_api_token.decode('utf-8')
        app_logger.info(f"COMMUNITY_API_TOKEN retrieved from Redis for user {username}")
    else:
        community_api_token = os.getenv('COMMUNITY_API_TOKEN')
        if not community_api_token:
            app_logger.error("COMMUNITY_API_TOKEN not set in Redis or environment variables.")
            return False

    # Default sub_community to "Imported from Klaviyo" if not found in Redis
    if sub_community:
        sub_community = sub_community.decode('utf-8')
        app_logger.info(f"SUB_COMMUNITY retrieved from Redis for user {username}")
    else:
        sub_community = "Imported from Klaviyo"
        app_logger.info(f"SUB_COMMUNITY not found in Redis, defaulting to '{sub_community}'")

    # Prepare the API URL and headers for tag creation
    tag_create_api_url = f"https://api.community.com/webhooks/v1/community/{community_client_id}/tag_create"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {community_api_token}"
    }

    # Prepare the payload for creating the sub-community tag
    tag_payload = {
        "title": sub_community,
        "description": "These members have been imported from Klaviyo",
        "color": "#2D7F17"
    }

    app_logger.debug(f"Tag creation payload: {tag_payload}")

    if test_mode:
        return True  # Simulate success in test mode

    try:
        response = requests.post(tag_create_api_url, headers=headers, json=tag_payload)
        if response.status_code == 202:
            app_logger.info(f"Tag '{sub_community}' created successfully for user {username}.")
            return True
        else:
            app_logger.error(f"Failed to create tag: HTTP {response.status_code}, Response: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        app_logger.error(f"Error during tag creation: {str(e)}")
        return False
