import os
import json
import datetime
import stripe
import traceback
from flask import jsonify, request, render_template
from flask_jwt_extended import get_jwt_identity, create_access_token, create_refresh_token
from logs import app_logger
from cache import get_user_data

app_logger.debug("Importing common module in credits.py")
from common import add_issued_token_function, revoke_all_access_tokens_for_user, decode_jwt, add_revoked_token_function, get_db_connection
from cache import get_redis_client

app_logger.debug("Imported common module successfully in credits.py")

# Set the Stripe API key
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

# Global variable to keep track of credits used
credits_used_by_this_worker = 0

def deduct_credits_for_usage(username):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Fetch the number of API calls made and cache status
            user_data, cache_status = get_user_data(username)
            api_calls_made = user_data['api_calls']

            # If no API calls have been made, there's nothing to deduct
            if api_calls_made == 0:
                return True

            # Fetch the user's current credits
            cursor.execute("SELECT credits FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            if result is None:
                app_logger.error(f"User {username} does not exist")
                return False

            current_credits = result[0]

            # Calculate the new credits
            new_credits = current_credits - api_calls_made
            if new_credits < 0:
                new_credits = 0

            # Update the user's credits
            cursor.execute("UPDATE users SET credits = ? WHERE username = ?", (new_credits, username))

            # Determine the source
            source = "usage" if cache_status == "Cache Available" else str(os.getpid())

            # Log the credit change
            cursor.execute("""
                INSERT INTO credit_changes (user_id, amount, source, transaction_id, change_date)
                VALUES (?, ?, ?, '0', ?)
            """, (username, -api_calls_made, source, datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))

            conn.commit()
            app_logger.debug(f"Deducted {api_calls_made} credits from user: {username}, new credits: {new_credits}, source: {source}")

            return True
    except Exception as e:
        app_logger.error(f"Error deducting credits for user {username}: {str(e)}")
        return False

def create_checkout_session_function_old():
    try:
        username = get_jwt_identity()
        data = request.get_json()
        credits = data.get('credits', 0)

        if credits < 10000:
            return jsonify({'error': 'Minimum number of credits is 10,000'}), 400

        amount = credits * 0.0005  # Calculate the payment amount in USD
        amount_cents = int(amount * 100)  # Stripe requires the amount in cents

        app_logger.debug(f'Creating checkout session for user: {username} for {credits} credits')

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
            success_url=f'https://www.bryanworx.com/success?session_id={{CHECKOUT_SESSION_ID}}&username={username}',
            cancel_url='https://www.bryanworx.com/cancel',
            metadata={'username': username, 'credits': credits}
        )
        app_logger.info(f'Checkout session created for user: {username} with session ID: {session.id}')
        return jsonify({'id': session.id})
    except Exception as e:
        app_logger.error(f"Error creating checkout session: {str(e)}")
        app_logger.error(traceback.format_exc())  # Add traceback for detailed error logging
        return jsonify(error=str(e)), 403

def create_checkout_session_function():
    try:
        username = get_jwt_identity()
        data = request.get_json()
        credits = data.get('credits', 0)

        if credits < 10000:
            return jsonify({'error': 'Minimum number of credits is 10,000'}), 400

        amount = credits * 0.0005  # Calculate the payment amount in USD
        amount_cents = int(amount * 100)  # Stripe requires the amount in cents

        app_logger.debug(f'Creating checkout session for user: {username} for {credits} credits')

        # Determine success and cancel URLs based on the environment
        if os.getenv('FLASK_ENV') == 'production':
            success_url = f'https://www.bryanworx.com/success?session_id={{CHECKOUT_SESSION_ID}}&username={username}'
            cancel_url = 'https://www.bryanworx.com/cancel'
        else:
            success_url = f'http://localhost:5050/success?session_id={{CHECKOUT_SESSION_ID}}&username={username}'  # Dev URL
            cancel_url = 'http://localhost:5050/cancel'  # Dev URL

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

def stripe_webhook_function():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = os.getenv('STRIPE_WEBHOOK_SECRET')  # Use the signing secret from Stripe dashboard

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
        app_logger.info(f"Webhook event received: {json.dumps(event, indent=4)}")
    except ValueError as e:
        # Invalid payload
        app_logger.error(f"Invalid payload: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        app_logger.error(f"Invalid signature: {str(e)}")
        return jsonify({'error': str(e)}), 400

    # Handle the event
    try:
        if event['type'] == 'payment_intent.succeeded':
            payment_intent = event['data']['object']  # contains a stripe.PaymentIntent
            app_logger.info('PaymentIntent was successful! Event: {}'.format(json.dumps(event, indent=4)))
            # Extract user information from metadata or another identifier
            app_logger.info(f'Metadata: {payment_intent.get("metadata")}')
            if 'metadata' in payment_intent and 'username' in payment_intent['metadata']:
                username = payment_intent['metadata']['username']
                credits = int(payment_intent['metadata']['credits'])
                app_logger.info(f'PaymentIntent succeeded for user: {username} for {credits} credits')

                # Update credits for the user
                try:
                    redis_client = get_redis_client()
                    user_data = redis_client.hgetall(username)

                    # Decode Redis values and handle specific fields as integers
                    user_data = {k.decode(): v.decode() for k, v in user_data.items()}
                    user_data['api_calls'] = int(user_data.get('api_calls', 0))
                    user_data['credits'] = int(user_data.get('credits', 0))

                    # Update credits
                    current_credits = user_data['credits']
                    new_credits = current_credits + credits

                    # Save updated credits to Redis
                    redis_client.hmset(username, {'credits': new_credits})
                    app_logger.info(f'Credits updated for user: {username} - New Credits: {new_credits}')
                except Exception as e:
                    app_logger.error(f"Error updating credits for user {username}: {str(e)}")
            else:
                app_logger.error('Metadata or username not found in payment_intent')

        elif event['type'] == 'checkout.session.completed':
            session = event['data']['object']  # contains a stripe.Session
            app_logger.info('Checkout session was completed! Event: {}'.format(json.dumps(event, indent=4)))
            # Extract user information from metadata
            app_logger.info(f'Metadata: {session.get("metadata")}')
            if 'metadata' in session and 'username' in session['metadata']:
                username = session['metadata']['username']
                credits = int(session['metadata']['credits'])
                app_logger.info(f'Checkout session completed for user: {username} for {credits} credits')

                # Update credits for the user
                try:
                    redis_client = get_redis_client()
                    user_data = redis_client.hgetall(username)

                    # Decode Redis values and handle specific fields as integers
                    user_data = {k.decode(): v.decode() for k, v in user_data.items()}
                    user_data['api_calls'] = int(user_data.get('api_calls', 0))
                    user_data['credits'] = int(user_data.get('credits', 0))

                    # Update credits
                    current_credits = user_data['credits']
                    new_credits = current_credits + credits

                    # Save updated credits to Redis
                    redis_client.hmset(username, {'credits': new_credits})
                    app_logger.info(f'Credits updated for user: {username} - New Credits: {new_credits}')
                except Exception as e:
                    app_logger.error(f"Error updating credits for user {username}: {str(e)}")
            else:
                app_logger.error('Metadata or username not found in session')

        elif event['type'] == 'payment_intent.payment_failed':
            payment_intent = event['data']['object']  # contains a stripe.PaymentIntent
            app_logger.info('PaymentIntent failed! Event: {}'.format(json.dumps(event, indent=4)))
            # Handle failed payment intent
        else:
            # Unexpected event type
            app_logger.info(f'Unhandled event type {event["type"]}')
    except Exception as e:
        app_logger.error(f"Error handling webhook event: {str(e)}")
        app_logger.error(traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

    return jsonify({'status': 'success'}), 200

def create_tokens(username, role, daily_limit, hourly_limit, minute_limit, secret, access_expires, refresh_expires, check_existing_refresh=False):
    secret = str(secret)
    app_logger.debug(f"Secret key type in create_tokens: {type(secret)} {secret}")

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
        access_expiry_str = (datetime.datetime.utcnow() + access_expires).isoformat()
        refresh_expiry_str = (datetime.datetime.utcnow() + refresh_expires).isoformat()

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

def payment_success_function_old():
    try:
        app_logger.info("Accessed the success route")
        username = request.args.get('username')
        session_id = request.args.get('session_id')
        app_logger.info(f"Username from query parameters: {username}")
        app_logger.info(f"Session ID from query parameters: {session_id}")
        return render_template('success.html', username=username, session_id=session_id)
    except Exception as e:
        app_logger.error(f"Error in payment success: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

def payment_success_function():
    try:
        app_logger.info("Accessed the success route")
        username = request.args.get('username')
        session_id = request.args.get('session_id')
        app_logger.info(f"Username from query parameters: {username}")
        app_logger.info(f"Session ID from query parameters: {session_id}")

        # Retrieve the Checkout Session from Stripe using session_id
        session = stripe.checkout.Session.retrieve(session_id)
        app_logger.debug(f'Session object: {session}')

        # Extract credits and username directly from session metadata
        credits = int(session.metadata.get('credits', 0))  # Fetch credits from the session metadata
        app_logger.debug(f'Credits from session metadata: {credits}')
        
        # Update the credits for the user in the database
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT credits FROM users WHERE username = ?", (username,))
            current_credits = cursor.fetchone()[0]
            new_credits = current_credits + credits  # Add the purchased credits

            cursor.execute("UPDATE users SET credits = ? WHERE username = ?", (new_credits, username))
            conn.commit()

            app_logger.info(f"Updated credits for user {username}. New balance: {new_credits}")

        # Optionally, log the credit change to the `credit_changes` table
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO credit_changes (user_id, amount, source, transaction_id, change_date)
                VALUES (?, ?, ?, ?, ?)
            """, (username, credits, "payment", session_id, datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()

            app_logger.info(f"Logged credit change for user {username}: {credits} credits added.")

        return render_template('success.html', username=username, session_id=session_id)
    except Exception as e:
        app_logger.error(f"Error in payment success: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500
