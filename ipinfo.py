import csv
import os
import json
import requests
from collections import defaultdict
import ipaddress
import brotli
from logs import app_logger

def is_valid_ip(ip):
    try:
        # This will raise ValueError if the IP is invalid
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def create_ipinfo_cache_file(file_path):
    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(file_path), exist_ok=True)  # Ensure the parent directories exist

    # Define the headers based on the expected API response fields
    headers = ["ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone"]

    # Create and write the header to the CSV file
    with open(file_path, mode='w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()

# Function to load the IP cache from the CSV file
def load_ipinfo_cache(file_path):
    ipinfo_cache = {}

    if os.path.exists(file_path):
        with open(file_path, mode='r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ipinfo_cache[row["ip"]] = row  # Store the row using the IP address as the key

    return ipinfo_cache

# Function to do IP address lookup
def do_ip_address_look_up(ip, username, file_path, ipinfo_cache):
    # Check if the IP exists in the passed cache
    if ipinfo_cache.get(ip):
        app_logger.info(f"Returning cached IP info for IP {ip}")
        return ipinfo_cache[ip]

    # If IP is not cached, fetch the data from the API
    ip_data = fetch_ipinfo_from_api(ip)

    if ip_data:
        # Update in-memory cache
        ipinfo_cache[ip] = ip_data
        return ip_data
    else:
        app_logger.info(f"Failed to fetch data for IP {ip}")
        return None

# Function to fetch IP info from ipinfo.io
# Function to fetch IP info from ipinfo.io
def fetch_ipinfo_from_api(ip):
    try:
        ipinfo_url = f"http://ipinfo.io/{ip}?token=c3a12271a0687f"
        response = requests.get(ipinfo_url, timeout=10)

        if response.status_code == 200:
            content = response.content  # Default to raw content

            # Check for Brotli encoding
            if 'br' in response.headers.get('Content-Encoding', ''):
                try:
                    content = brotli.decompress(response.content)
                except brotli.error as e:
                    # Attempt fallback to raw content
                    content = response.content  # Fallback to raw content

            # Parse JSON response
            try:
                ip_data_raw = json.loads(content)

                # Standardize IP data
                ip_data = {
                    "ip": ip,
                    "hostname": ip_data_raw.get("hostname"),
                    "city": ip_data_raw.get("city"),
                    "region": ip_data_raw.get("region"),
                    "country": ip_data_raw.get("country"),
                    "loc": ip_data_raw.get("loc"),
                    "org": ip_data_raw.get("org"),
                    "postal": ip_data_raw.get("postal"),
                    "timezone": ip_data_raw.get("timezone")
                }

                return ip_data
            except json.JSONDecodeError as e:
                # Log and save raw response only if fallback also fails
                app_logger.error(f"JSON decoding failed for IP {ip}: {e}")

                # Save raw response for debugging
                debug_dir = "/home/bryananthonyobrien/logs/debug/"
                os.makedirs(debug_dir, exist_ok=True)
                debug_file_path = os.path.join(debug_dir, f"debug_ipinfo_{ip}.txt")
                with open(debug_file_path, "w") as debug_file:
                    debug_file.write(content.decode(errors="replace"))

                app_logger.error(f"Saved raw response to {debug_file_path}")
                raise RuntimeError(f"JSON decoding failed for IP {ip}. Debug file saved at {debug_file_path}")
        else:
            # Log HTTP error and stop execution
            app_logger.error(f"HTTP error {response.status_code} for IP {ip}. Response body: {response.text}")
            raise RuntimeError(f"HTTP error {response.status_code} for IP {ip}")

    except requests.exceptions.RequestException as e:
        # Log request exception and stop execution
        app_logger.error(f"Request failed for IP {ip}: {e}")
        raise RuntimeError(f"Request exception occurred for IP {ip}: {e}")

    except Exception as e:
        # Log unexpected error and stop execution
        app_logger.error(f"Unexpected error occurred while fetching IP info for {ip}: {e}")
        raise RuntimeError(f"Unexpected error for IP {ip}: {e}")

# Function to fetch IP info from ipinfo.io
def fetch_ipinfo_from_api_works(ip):
    try:
        ipinfo_url = f"http://ipinfo.io/{ip}?token=c3a12271a0687f"
        response = requests.get(ipinfo_url, timeout=10)  # Adding a timeout for the request

        if response.status_code == 200:
            try:
                # Check for content encoding and decompress accordingly
                if 'br' in response.headers.get('Content-Encoding', ''):
                    # Manually decode Brotli content
                    content = brotli.decompress(response.content)
                else:
                    content = response.content

                ip_data_raw = json.loads(content)  # Convert the decompressed content to JSON
                app_logger.info(f"Fetched raw IP info for IP {ip}: {json.dumps(ip_data_raw, indent=4)}")

                # Standardize IP data
                ip_data = {
                    "ip": ip,
                    "hostname": ip_data_raw.get("hostname"),
                    "city": ip_data_raw.get("city"),
                    "region": ip_data_raw.get("region"),
                    "country": ip_data_raw.get("country"),
                    "loc": ip_data_raw.get("loc"),
                    "org": ip_data_raw.get("org"),
                    "postal": ip_data_raw.get("postal"),
                    "timezone": ip_data_raw.get("timezone")
                }

                return ip_data
            except brotli.error as e:
                app_logger.info(f"Brotli decompression failed for IP {ip}: {e}")
                return None
            except json.JSONDecodeError as e:
                app_logger.info(f"Failed to decode JSON for IP {ip}: {e}")
                return None
        else:
            app_logger.info(f"Error fetching IP info for {ip}: HTTP {response.status_code}")
            return None

    except requests.exceptions.RequestException as e:
        app_logger.info(f"Request failed for IP {ip}: {e}")
        return None
    except Exception as e:
        app_logger.info(f"Unexpected error occurred while fetching IP info for {ip}: {e}")
        return None

# Function to update the IP info cache file
def update_ipinfo_cache_file(file_path, ip_cache):
    # Write the updated cache to the CSV file
    headers = ["ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone"]
    with open(file_path, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)

        for ip, data in ip_cache.items():
            writer.writerow(data)  # Write the data for each IP