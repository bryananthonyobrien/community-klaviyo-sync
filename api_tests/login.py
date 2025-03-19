import requests

url = "http://localhost:5001/login"
data = {
    "username": "bryan123",
    "password": "bryan123"
}
headers = {"Content-Type": "application/json"}

response = requests.post(url, json=data, headers=headers)

print("Status Code:", response.status_code)
print("Response JSON:", response.json())
