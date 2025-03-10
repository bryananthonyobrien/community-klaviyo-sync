import os
import json
from datetime import datetime
import stripe
import traceback
from flask import jsonify, request, render_template
from flask_jwt_extended import get_jwt_identity, create_access_token, create_refresh_token
from logs import app_logger
from cache import get_user_data
import time
    
app_logger.debug("Importing common module in credits.py")
from common import add_issued_token_function, revoke_all_access_tokens_for_user, decode_jwt, add_revoked_token_function
from cache import get_redis_client

app_logger.debug("Imported common module successfully in credits.py")

# Set the Stripe API key
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

# Global variable to keep track of credits used
credits_used_by_this_worker = 0

def log_credit_change(redis_client, username, amount, source, transaction_id):
    try:
        credit_change = {
            "username": username,
            "amount": amount,
            "source": source,
            "transaction_id": transaction_id,
            "change_date": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')  # ✅ Fixed
        }

        redis_key = f"{username}:credit_changes"

        # Ensure the key exists
        if not redis_client.exists(redis_key):
            app_logger.info(f"Redis list {redis_key} does not exist. Initializing...")

        # Push credit change
        redis_client.rpush(redis_key, json.dumps(credit_change))

        app_logger.info(f"✅ Successfully logged credit change for user {username}")

    except Exception as e:
        app_logger.error(f"❌ Error logging credit change for user {username}: {e}")
        raise
    return

def add_user_credits(username, credits):
    redis_client = get_redis_client()

    # Check if user exists by verifying if their hash exists in Redis
    user_data_key = username
    if not redis_client.exists(user_data_key):
        app_logger.info(f"User {username} does not exist.")
        return f"User {username} does not exist."

    # Fetch the current credits from Redis
    current_credits = int(redis_client.hget(user_data_key, "credits") or 0)
    new_credits = current_credits + credits
    redis_client.hset(user_data_key, "credits", new_credits)
    log_credit_change(redis_client, username, credits, 'stripe', '0')
    app_logger.info(f"{username} had {current_credits} but now has {new_credits} credits")

    return "Success"
    
def create_checkout_session_function():
    try:
        username = get_jwt_identity()
        redis_client = get_redis_client()

        # Log credits at the start
        initial_credits = redis_client.hget(username, "credits")
        initial_credits = int(initial_credits) if initial_credits else 0
        app_logger.info(f"🔹 Prior credits for user {username}: {initial_credits}")

        data = request.get_json()
        credits = data.get('credits', 0)

        if credits < 1000:
            return jsonify({'error': 'Minimum number of credits is 1,000'}), 400

        amount = credits * 0.01  # Calculate the payment amount in USD
        amount_cents = int(amount * 100)  # Stripe requires the amount in cents

        app_logger.debug(f'Creating checkout session for user: {username} for {credits} credits')

        # Determine success and cancel URLs based on the environment
        if os.getenv('FLASK_ENV') == 'production':
            success_url = f'https://www.bryanworx.com/success?session_id={{CHECKOUT_SESSION_ID}}&username={username}'
            cancel_url = 'https://www.bryanworx.com/cancel'
        else:
            success_url = f'http://localhost:5001/success?session_id={{CHECKOUT_SESSION_ID}}&username={username}'  # Dev URL
            cancel_url = 'http://localhost:5001/cancel'  # Dev URL

        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f'{credits} API Credits',
                    },
                    'unit_amount': amount_cents,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={'username': username, 'credits': credits}
        )

        app_logger.info(f'Checkout session created for user: {username} with session ID: {session.id}')

        return jsonify({'id': session.id})
    
    except Exception as e:
        app_logger.error(f"Error creating checkout session: {str(e)}")
        app_logger.error(traceback.format_exc())  # Add traceback for detailed error logging
        return jsonify(error=str(e)), 403

def handle_payment_intent_succeeded(payment_intent):
    app_logger.info(f"✅ PaymentIntent was successful")
    return

def handle_checkout_session_completed(session):
    metadata = session.get('metadata', {})
    username = metadata.get('username')
    credits = metadata.get('credits')
    session_id = session.get('id')  # Ensure we use the correct Stripe session ID

    if username and credits and session_id:
        redis_client = get_redis_client()
        session_key = f"session:{session_id}"

        # 🚨 Use SETNX (SET if Not Exists) to ensure only ONE worker processes this session
        if not redis_client.setnx(session_key, "processed"):
            existing_value = redis_client.get(session_key)
            app_logger.warning(f"⚠️ Duplicate processing attempt for session_id: {session_id}, skipping. Session was processed at: {existing_value}")
            return

        # ✅ Set an expiration for cleanup after 24 hours
        redis_client.expire(session_key, 86400)

        credits = int(credits)
        app_logger.info(f"✅ Checkout session completed for user: {username} ({credits} credits)")

        try:
            if redis_client.exists(username):
                user_data = redis_client.hgetall(username)
                user_data = {k.decode(): v.decode() for k, v in user_data.items()}
                app_logger.info(f"🛠️ Redis BEFORE updating credits for {username}: {user_data}")
            else:
                app_logger.info(f"⚠️ Redis key {username} does not exist")

            # 🔄 Retry logic for Redis transaction
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    with redis_client.pipeline() as pipe:
                        pipe.watch(username)  # Watch key to detect external modifications
                        current_credits = int(redis_client.hget(username, "credits") or 0)
                        new_credits = current_credits + credits

                        pipe.multi()  # Start transaction
                        pipe.hset(username, "credits", new_credits)  # Update credits
                        pipe.execute()  # Commit transaction

                        app_logger.info(f"✅ Credits updated for {username}: {current_credits} ➝ {new_credits}")
                        break  # ✅ Success, break out of retry loop

                except redis.WatchError:
                    app_logger.warning(f"⚠️ Race condition detected while updating credits for {username}, retrying ({attempt+1}/{max_retries})...")
                    time.sleep(0.2)  # Wait a bit before retrying
                    continue

            else:
                app_logger.error(f"❌ Failed to update credits for {username} after {max_retries} attempts due to race conditions.")

        except Exception as e:
            app_logger.error(f"❌ Exception updating credits for {username}: {str(e)}")

    else:
        app_logger.info(f"❌ Metadata missing in Checkout Session. Data: {json.dumps(session, indent=4)}")
    return

def handle_charge_succeeded(charge):
    app_logger.info(f"✅ Charge Succeeded")
    return
 
def handle_charge_updated(charge):
    app_logger.info(f"🔄 Charge Updated")
    return

def handle_payment_intent_created(charge):
    app_logger.info(f"✅ PaymentIntent Created")
    return

def handle_payment_failed(payment_intent):
    app_logger.info(f"❌ PaymentIntent failed")
    return

from flask_jwt_extended import get_jwt_identity

from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request

def stripe_webhook_function(event):  
    try:
        event_type = event['type']
        event_data = event['data']['object']
        redis_client = get_redis_client()

        username = None

        # **Try extracting username from JWT (if available)**
        try:
            verify_jwt_in_request()
            username = get_jwt_identity()
        except Exception:
            pass  # No need to log here; we handle fallback below

        # **If JWT fails, extract from Stripe metadata**
        if not username:
            metadata = event_data.get('metadata', {})
            username = metadata.get('username')

        # **Handle missing username gracefully**
        if not username:
            app_logger.warning(f"⚠️ No username found in JWT or Stripe metadata for event: {event_type}")
            return jsonify({"error": "Username not found"}), 400

        # **Fetch initial credits before processing**
        initial_credits = int(redis_client.hget(username, "credits") or 0)
        app_logger.info(f"🚀 Start of Webhook Processing | Event: {event_type} | User: {username} | Initial Credits: {initial_credits}")

        # **Process the event**
        if event_type == 'payment_intent.succeeded':
            handle_payment_intent_succeeded(event_data)
        elif event_type == 'checkout.session.completed':
            handle_checkout_session_completed(event_data)
        elif event_type == 'payment_intent.payment_failed':
            handle_payment_failed(event_data)
        elif event_type == 'charge.succeeded':
            handle_charge_succeeded(event_data)
        elif event_type == 'charge.updated':
            handle_charge_updated(event_data)
        elif event_type == 'payment_intent.created':
            handle_payment_intent_created(event_data)
        else:
            app_logger.warning(f"⚠️ Unhandled event type: {event_type}")
            app_logger.info(f"{json.dumps(event, indent=4)}")

        # **Fetch final credits after processing**
        final_credits = int(redis_client.hget(username, "credits") or 0)
        app_logger.info(f"🏁 End of Webhook Processing | Event: {event_type} | User: {username} | Final Credits: {final_credits}")

    except Exception as e:
        app_logger.error(f"❌ Error handling webhook event: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

    return jsonify({'status': 'success'}), 200


def create_tokens(username, role, daily_limit, hourly_limit, minute_limit, secret, access_expires, refresh_expires, check_existing_refresh=False):
    secret = str(secret)
    app_logger.debug(f"Secret key type in create_tokens: {secret}")

    additional_claims = {
        "role": role,
        "daily_limit": daily_limit,
        "hourly_limit": hourly_limit,
        "minute_limit": minute_limit
    }

    try:
        redis_client = get_redis_client()

        # Revoke all existing access tokens from the global Redis set (not per user)
        revoke_all_access_tokens_for_user(username, secret)

        # Create a new access token
        access_token = create_access_token(identity=username, additional_claims=additional_claims)
        app_logger.debug(f"Created access token for user {username}")

        # Check if there is an existing refresh token in Redis
        refresh_token = None
        if check_existing_refresh:
            # Look for an existing refresh token in the global issued tokens set
            existing_refresh_token = redis_client.sismember("issued_tokens", username)
            if existing_refresh_token:
                refresh_token = existing_refresh_token
                app_logger.debug(f"Found existing refresh token for user {username}")

        # If no existing refresh token, create a new one
        if not refresh_token:
            refresh_token = create_refresh_token(identity=username, additional_claims=additional_claims)
            app_logger.debug(f"Created new refresh token for user {username}")

        # Decode the access and refresh tokens to get their JTI (JWT ID)
        decoded_access_token = decode_jwt(access_token, secret)
        decoded_refresh_token = decode_jwt(refresh_token, secret)

        access_jti = decoded_access_token["jti"]
        refresh_jti = decoded_refresh_token["jti"]

        # Convert the expiry times to string format before adding to Redis
        access_expiry_str = (datetime.utcnow() + access_expires).isoformat()
        refresh_expiry_str = (datetime.utcnow() + refresh_expires).isoformat()

        # Add the issued access and refresh tokens to the global Redis set for issued tokens
        # Use the global issued tokens key (set of all issued tokens)
        add_issued_token_function(access_jti, username, access_token, access_expiry_str, 'access', redis_client)
        
        if not existing_refresh_token:
            add_issued_token_function(refresh_jti, username, refresh_token, refresh_expiry_str, 'refresh', redis_client)

    except Exception as e:
        app_logger.error(f"Error during token creation for user {username}: {str(e)}")
        raise  # Re-raise the exception after logging

    return access_token, refresh_token

def cancel_payment_function():
    return render_template('cancel.html', message="Payment was cancelled. Please try again.")

def payment_success_function():
    """
    Handles successful payments by retrieving the Stripe session
    and then just rendering a success page (credits are handled by the webhook).
    """
    try:
        app_logger.info("Accessed the success route")

        # Extract query params
        username = request.args.get('username')
        session_id = request.args.get('session_id')
        app_logger.info(f"Username from query parameters: {username}")
        app_logger.info(f"Session ID from query parameters: {session_id}")

        # Get Redis client
        redis_client = get_redis_client()

        # 🚨 Only log credits, do not modify them!
        initial_credits = redis_client.hget(username, "credits")
        initial_credits = int(initial_credits) if initial_credits else 0
        app_logger.info(f"🔹 Upon entering payment success credits for user {username}: {initial_credits}")

        # Fetch the Stripe checkout session (only for logging)
        session = stripe.checkout.Session.retrieve(session_id)
        app_logger.debug(f"Session object: {session}")

        # ✅ Ensure we are NOT updating credits in this function
        final_credits = redis_client.hget(username, "credits")
        final_credits = int(final_credits) if final_credits else 0
        app_logger.info(f"✅ Upon exiting payment success credits for user {username}: {final_credits}")

        return render_template('success.html', username=username, session_id=session_id)

    except Exception as e:
        app_logger.error(f"Error in payment success: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

