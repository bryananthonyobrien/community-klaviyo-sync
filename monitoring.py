import time
import traceback
from flask import jsonify, request
from flask_jwt_extended import get_jwt
from logs import app_logger
import requests
import subprocess

def cpu_usage_function(USERNAME,API_TOKEN):
    try:
        usage_data = get_cpu_usage_function(USERNAME,API_TOKEN)
        return jsonify(usage_data), 200
    except Exception as e:
        app_logger.error(f"Error fetching CPU usage: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

def get_cpu_usage_function(USERNAME, API_TOKEN):
    API_URL = f'https://www.pythonanywhere.com/api/v0/user/{USERNAME}/cpu/'
    HEADERS = {
        'Authorization': f'Token {API_TOKEN}'
    }

    response = requests.get(API_URL, headers=HEADERS)
    if response.status_code == 200:
        usage_data = response.json()
        return usage_data
    else:
        raise Exception(f"Error fetching usage data: {response.status_code} {response.text}")

def get_file_storage_usage_function():
    try:
        # Run the command to get the file storage usage
        command = "du -s -B 1 /tmp ~/.[!.]* ~/* | awk '{s+=$1}END{print s}'"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, executable='/bin/bash')

        if result.returncode != 0:
            raise Exception(f"Command failed with return code {result.returncode}")

        # Get the storage used in bytes
        file_storage_used_bytes = int(result.stdout.strip())

        # Assume a limit for the example
        file_storage_limit_bytes = 5000000000  # 5 GB limit

        data = {
            "file_storage_limit_bytes": file_storage_limit_bytes,
            "file_storage_used_bytes": file_storage_used_bytes
        }
        return jsonify(data), 200
    except Exception as e:
        app_logger.error(f"Error fetching file storage usage: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500
