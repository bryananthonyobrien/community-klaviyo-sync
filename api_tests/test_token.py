import requests
import json
import time

def pretty_print_json(data):
    """Formats and prints JSON data in a readable way."""
    print(json.dumps(data, indent=4, sort_keys=True))

# Step 1: Login and Get the Token
login_url = "http://localhost:5001/login"
login_data = {
    "username": "bryan123",
    "password": "bryan123"
}

print("\n🔐 Attempting to log in...")

login_response = requests.post(login_url, json=login_data)
login_json = login_response.json()

if login_response.status_code == 200:
    access_token = login_json.get("access_token")
    print("\n✅ **Login Successful!**")
    print("🔑 Extracted Access Token:")
    pretty_print_json({"access_token": access_token})
else:
    print("\n❌ **Login Failed!**")
    pretty_print_json(login_json)
    exit()

# Step 2: Use Token to Test Validity
test_url = "http://localhost:5001/test-token"
headers = {"Authorization": f"Bearer {access_token}"}

print("\n🔍 Testing Token Validity...")

test_response = requests.get(test_url, headers=headers)
test_json = test_response.json()

print("\n🔍 **Token Test API Response (Initial Test):**")
pretty_print_json(test_json)

# Extract expiration time
time_remaining_seconds = test_json.get("time_remaining_seconds", None)

if time_remaining_seconds is not None:
    print(f"\n⏳ Waiting for {time_remaining_seconds + 1} seconds to let the token expire...")
    time.sleep(time_remaining_seconds + 1)

    # Step 3: Retest Token Validity After Expiry
    print("\n🔍 Re-testing Token Validity After Expiry...")

    test_response_after_expiry = requests.get(test_url, headers=headers)
    test_json_after_expiry = test_response_after_expiry.json()

    print("\n🔍 **Token Test API Response (After Expiry):**")
    pretty_print_json(test_json_after_expiry)

else:
    print("\n⚠️ `time_remaining_seconds` not found in the API response. Expiry check skipped.")
