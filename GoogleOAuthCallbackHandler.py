import json
import requests
import os
import boto3
from botocore.exceptions import ClientError
import urllib.parse
import time # For epoch time
import datetime # For TTL check

# --- Configuration ---
# Get the name of the secret storing your app's Google Client ID/Secret
APP_CREDS_SECRET_NAME = os.environ.get('APP_CREDS_SECRET_NAME') # Default name
# Base URL for redirecting the user back to your frontend after OAuth
FRONTEND_REDIRECT_BASE_URL = os.environ.get('FRONTEND_REDIRECT_BASE_URL', 'https://image-caption-web-morgan.s3.us-east-1.amazonaws.com/index2.html')
# Google Token Exchange Endpoint
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
# Base Secret Name for user refresh tokens
USER_SECRETS_BASE_NAME = 'google-photos/'
# DynamoDB table name for temporary OAuth states
OAUTH_STATE_TABLE = os.environ.get('OAUTH_STATE_TABLE') # Default name

# --- AWS Clients ---
secrets_client = boto3.client('secretsmanager')
dynamodb = boto3.client('dynamodb') # Add DynamoDB client

# --- Helper Functions ---

def get_secret_value(secret_name):
    """Retrieves a secret from AWS Secrets Manager."""
    try:
        response = secrets_client.get_secret_value(SecretId=secret_name)
        # print(f"Successfully retrieved secret {secret_name}.") # Avoid logging secret content
        return json.loads(response['SecretString'])
    except ClientError as e:
        print(f"Error retrieving secret {secret_name}: {e}")
        # Handle specific AWS errors if necessary
        return None # Return None on error

def put_secret_value(secret_name, secret_value):
    """Creates or updates a secret in AWS Secrets Manager."""
    secret_string = json.dumps(secret_value)
    try:
        # Try updating first
        secrets_client.update_secret(SecretId=secret_name, SecretString=secret_string)
        print(f"Updated secret {secret_name}.")
    except secrets_client.exceptions.ResourceNotFoundException:
        # If update fails because secret not found, create it
        try:
            secrets_client.create_secret(Name=secret_name, SecretString=secret_string)
            print(f"Created secret {secret_name}.")
        except ClientError as e:
            print(f"Error creating secret {secret_name}: {e}")
            raise # Re-raise the exception
    except ClientError as e:
        print(f"Error updating secret {secret_name}: {e}")
        raise # Re-raise the exception

def get_state_from_dynamodb(state_value):
    """Looks up the state in DynamoDB and returns the associated user ID and expiry."""
    try:
        response = dynamodb.get_item(
            TableName=OAUTH_STATE_TABLE,
            Key={'state': {'S': state_value}}
        )
        item = response.get('Item')

        if not item:
            print(f"State '{state_value}' not found in DynamoDB table '{OAUTH_STATE_TABLE}'.")
            return None, None # State not found

        user_id = item.get('userId', {}).get('S')
        expiry_time_str = item.get('expiryTime', {}).get('N') # Expiry time stored as Number (String 'N')

        if not user_id or not expiry_time_str:
            print(f"Item for state '{state_value}' is missing userId or expiryTime.")
            return None, None # Item incomplete

        try:
            expiry_time = int(expiry_time_str)
        except ValueError:
             print(f"Could not parse expiryTime '{expiry_time_str}' for state '{state_value}'.")
             return None, None # Invalid expiry time format


        print(f"Found state '{state_value}' for user '{user_id}' expiring at {expiry_time}.")
        return user_id, expiry_time

    except ClientError as e:
        print(f"Error getting item from DynamoDB table '{OAUTH_STATE_TABLE}': {e}")
        raise # Re-raise the exception for logging/alerting

def delete_state_from_dynamodb(state_value):
    """Deletes the state entry from DynamoDB after use."""
    try:
        dynamodb.delete_item(
            TableName=OAUTH_STATE_TABLE,
            Key={'state': {'S': state_value}}
        )
        print(f"Successfully deleted state '{state_value}' from DynamoDB.")
    except ClientError as e:
        print(f"Error deleting item from DynamoDB table '{OAUTH_STATE_TABLE}': {e}")
        # Log error, but don't necessarily fail the Lambda if storage succeeded


# --- Lambda Handler ---
def lambda_handler(event, context):
    print("Received OAuth callback event.")
    # API Gateway proxy integration puts query parameters in 'queryStringParameters' for GET
    query_params = event.get('queryStringParameters') or {}
    auth_code = query_params.get('code')
    state = query_params.get('state')

    # --- 1. Basic Validation ---
    if not auth_code:
        error_description = query_params.get('error', 'unknown_error')
        print(f"OAuth callback failed. No authorization code received. Error: {error_description}")
        # Redirect user to a failure page
        redirect_url = f"{FRONTEND_REDIRECT_BASE_URL}?success=false&error={urllib.parse.quote_plus(error_description)}"
        return {
            'statusCode': 302,
            'headers': {'Location': redirect_url}
        }

    if not state:
         print("OAuth callback failed. State parameter is missing.")
         redirect_url = f"{FRONTEND_REDIRECT_BASE_URL}?success=false&error={urllib.parse.quote_plus('state_missing')}"
         return {
            'statusCode': 302,
            'headers': {'Location': redirect_url}
        }

    # --- 2. State Verification and User Identification (Using DynamoDB) ---
    user_id = None
    try:
        user_id, expiry_time = get_state_from_dynamodb(state)

        if not user_id:
            # State not found or incomplete data
            print(f"State '{state}' not found or incomplete in DB.")
            redirect_url = f"{FRONTEND_REDIRECT_BASE_URL}?success=false&error={urllib.parse.quote_plus('invalid_state')}"
            return {'statusCode': 302, 'headers': {'Location': redirect_url}}

        # Check if the state has expired
        current_time = int(time.time())
        if expiry_time is not None and current_time > expiry_time:
             print(f"State '{state}' for user '{user_id}' has expired.")
             # Optionally delete the expired state immediately
             delete_state_from_dynamodb(state) # Fire and forget delete
             redirect_url = f"{FRONTEND_REDIRECT_BASE_URL}?success=false&error={urllib.parse.quote_plus('state_expired')}"
             return {'statusCode': 302, 'headers': {'Location': redirect_url}}

        print(f"State '{state}' successfully verified for user ID: {user_id}")

        # State is valid, attempt to delete it so it can't be reused
        delete_state_from_dynamodb(state) # Fire and forget delete

    except Exception as e:
         print(f"An unexpected error occurred during state verification for state '{state}': {e}")
         redirect_url = f"{FRONTEND_REDIRECT_BASE_URL}?success=false&error={urllib.parse.quote_plus('state_verification_error')}"
         return {'statusCode': 302, 'headers': {'Location': redirect_url}}


    # --- 3. Get Google App Credentials ---
    app_creds = get_secret_value(APP_CREDS_SECRET_NAME)
    if not app_creds or 'client_id' not in app_creds or 'client_secret' not in app_creds:
        print(f"Failed to retrieve application Google credentials from secret '{APP_CREDS_SECRET_NAME}'.")
        # This is a server configuration error, redirect user to general error page
        redirect_url = f"{FRONTEND_REDIRECT_BASE_URL}?success=false&error={urllib.parse.quote_plus('server_config_error')}"
        return {
            'statusCode': 302,
            'headers': {'Location': redirect_url}
        }

    client_id = app_creds['client_id']
    client_secret = app_creds['client_secret']

    # The redirect_uri MUST EXACTLY match the one configured in Google Cloud Console
    # and the one you sent when initiating the OAuth flow.
    # It's constructed dynamically based on the API Gateway request context.
    api_id = event['requestContext']['apiId']
    stage = event['requestContext']['stage']
    region = os.environ.get('AWS_REGION') # Get region from environment variable
    # Assuming the path is /google-oauth-callback - adjust if needed
    redirect_uri_path = '/google-oauth-callback'
    redirect_uri = f"https://{api_id}.execute-api.{region}.amazonaws.com/{stage}{redirect_uri_path}"
    print(f"Constructed redirect_uri: {redirect_uri}")


    # --- 4. Exchange Authorization Code for Tokens ---
    token_exchange_payload = {
        'code': auth_code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }

    print("Exchanging authorization code for tokens...")
    try:
        response = requests.post(GOOGLE_TOKEN_URI, data=token_exchange_payload)
        response.raise_for_status() # Raise an exception for bad status codes
        token_data = response.json()
        print("Token exchange successful.")

    except requests.exceptions.RequestException as e:
        print(f"Error during token exchange: {e}")
        error_message = f"Token exchange failed: {e}"
        redirect_url = f"{FRONTEND_REDIRECT_BASE_URL}?success=false&error={urllib.parse.quote_plus(error_message)}"
        return {
            'statusCode': 302,
            'headers': {'Location': redirect_url}
        }

    # --- 5. Extract and Store Refresh Token ---
    refresh_token = token_data.get('refresh_token')
    # access_token = token_data.get('access_token') # You get this but don't need to store long-term
    # expires_in = token_data.get('expires_in')
    # scope = token_data.get('scope')

    if not refresh_token:
        print("Error: Refresh token not received in token exchange response.")
        # This is unexpected, likely an issue with Google's response or setup
        redirect_url = f"{FRONTEND_REDIRECT_BASE_URL}?success=false&error={urllib.parse.quote_plus('no_refresh_token')}"
        return {
            'statusCode': 302,
            'headers': {'Location': redirect_url}
        }


    user_secret_value = {
        'refresh_token': refresh_token,
        'client_id': client_id, # Store client_id/secret with the refresh token
        'client_secret': client_secret # as the daily refresh needs them

    }
    user_secret_name = f"{USER_SECRETS_BASE_NAME}{user_id}" 

    print(f"Storing refresh token for user {user_id} in secret {user_secret_name}...")
    try:
        put_secret_value(user_secret_name, user_secret_value)
        print("Successfully stored user refresh token.")
        success = True
        message = "Google Photos connected successfully."


    except Exception as e:
        print(f"Failed to store user refresh token for {user_id}: {e}")
        success = False
        message = f"Failed to save credentials: {e}"



    redirect_url = f"{FRONTEND_REDIRECT_BASE_URL}?success={str(success).lower()}&message={urllib.parse.quote_plus(message)}"
    

    print(f"Redirecting user to: {redirect_url}")
    return {
        'statusCode': 302, # HTTP status code for Found (Temporary Redirect)
        'headers': {
            'Location': redirect_url # The URL to redirect to
        }
    }