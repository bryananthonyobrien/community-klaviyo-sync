import jwt
import json
from datetime import datetime

# Your JWT secret key (must match the one used to sign the token)
JWT_SECRET_KEY = "3209feb1ac2e65e60f70fad18cff1e9c7fa077c5b7d1578a586e792c5b753391"

# Example token stored in Redis
revoked_token_entry = {
    "jti": "39dcb849-e95b-46a2-b72c-9dd462324e20",
    "username": "test_user",
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MTY5NzE0NiwianRpIjoiMzlkY2I4NDktZTk1Yi00NmEyLWI3MmMtOWRkNDYyMzI0ZTIwIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InRlc3RfdXNlciIsIm5iZiI6MTc0MTY5NzE0NiwiY3NyZiI6ImEyNmQ1YWFhLWM1ZTItNDAxZS05MGZmLWVhNDE2YWE4ZjVlOCIsImV4cCI6MTc0MTY5ODA0Niwicm9sZSI6ImNsaWVudCIsImRhaWx5X2xpbWl0IjoxMDAwLCJob3VybHlfbGltaXQiOjUwMCwibWludXRlX2xpbWl0IjoxMDB9.IGuD3KiLilkiKWqTO-3YXaXlwWMp_X-MYYhdxQP1Cm0",
    "expires_at": "2025-03-11T13:00:46.599662",
    "type": "access"
}

# Extract JWT
jwt_token = revoked_token_entry["jwt"]

try:
    # Decode JWT
    decoded_token = jwt.decode(jwt_token, JWT_SECRET_KEY, algorithms=["HS256"])

    # Pretty print decoded token
    print("🔍 Decoded JWT:")
    print(json.dumps(decoded_token, indent=4))

    # Extract JTI
    jti = decoded_token.get("jti", "JTI NOT FOUND")
    print(f"\n🔍 Extracted JTI: {jti}")

    # Extract Expiry
    exp = decoded_token.get("exp")
    if exp:
        exp_datetime = datetime.utcfromtimestamp(exp)
        print(f"⏳ Token Expiry (UTC): {exp_datetime}")
    else:
        print("❌ Expiry Not Found in JWT")

except jwt.ExpiredSignatureError:
    print("❌ JWT has expired")
except jwt.InvalidTokenError:
    print("❌ Invalid JWT")
except Exception as e:
    print(f"❌ Error decoding JWT: {str(e)}")

