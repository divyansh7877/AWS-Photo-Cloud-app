import json
import os
import boto3
import urllib.parse
import uuid # For generating state
import time # For epoch time
from botocore.exceptions import ClientError

# --- Configuration ---

APP_CREDS_SECRET_NAME = os.environ.get('APP_CREDS_SECRET_NAME', 'google-oauth-app-creds')

OAUTH_STATE_TABLE = os.environ.get('OAUTH_STATE_TABLE', 'OAuthStates')

CALLBACK_REDIRECT_URI = os.environ.get('CALLBACK_REDIRECT_URI')

# Google Authorization Endpoint Base URL
GOOGLE_AUTH_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
# Required scope for Google Photos Library API read access
GOOGLE_PHOTOS_SCOPE = "https://www.googleapis.com/auth/photoslibrary.readonly"

# --- AWS Clients ---
secrets_client = boto3.client('secretsmanager')
dynamodb = boto3.client('dynamodb')

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
        return None

def put_state_in_dynamodb(state_value, user_id):
    """Stores the state and associated user ID in DynamoDB with a TTL."""
    # Set expiry time (e.g., 15 minutes from now)
    expiry_seconds = 15 * 60
    expiry_time = int(time.time()) + expiry_seconds

    try:
        dynamodb.put_item(
            TableName=OAUTH_STATE_TABLE,
            Item={
                'state': {'S': state_value},
                'userId': {'S': user_id},
                'expiryTime': {'N': str(expiry_time)} # DynamoDB Number type requires string representation
            }
        )
        print(f"Successfully stored state '{state_value}' for user '{user_id}' expiring at {expiry_time}.")
    except ClientError as e:
        print(f"Error putting item in DynamoDB table '{OAUTH_STATE_TABLE}': {e}")
        raise # Re-raise the exception

# --- Lambda Handler ---
def lambda_handler(event, context):
    print("Received OAuth initiation request.")

    # --- 1. Authenticate and Identify User (Using Cognito ID Token) ---
    # API Gateway Lambda Proxy typically puts auth headers in event['headers']
    # If you configured a Cognito Authorizer, the user ID might be in event['requestContext']['authorizer']['claims']['sub']
    # If you are manually validating the token here, get it from the header:
    auth_header = event.get('headers', {}).get('Authorization')
    cognito_user_id = None # This will store the user's Cognito 'sub'

    if not auth_header or not auth_header.startswith('Bearer '):
        print("Authorization header missing or malformed.")
        return {
             'statusCode': 401, # Unauthorized
             'headers': {'Content-Type': 'application/json'},
             'body': json.dumps({'message': 'Authorization header required'})
        }

    id_token = auth_header.split(' ')[1] # Get the token part



    try:

         import base64
         import json
         def decode_jwt_payload_unsafe(token):
             try:
                 payload_base64 = token.split('.')[1]
                 payload_base64 = payload_base64 + '=' * (-len(payload_base64) % 4) # Add padding
                 payload_bytes = base64.b64decode(payload_base64)
                 return json.loads(payload_bytes.decode('utf-8'))
             except Exception as e:
                 print(f"Unsafe decode failed: {e}")
                 return None

         decoded_payload = decode_jwt_payload_unsafe(id_token)
         if not decoded_payload:
             print("Failed to decode token payload.")
             return {
                 'statusCode': 401,
                 'headers': {'Content-Type': 'application/json'},
                 'body': json.dumps({'message': 'Invalid token'})
             }
         cognito_user_id = decoded_payload.get('sub') # Get the 'sub' claim

         if not cognito_user_id:
             print("Cognito 'sub' not found in token payload.")
             return {
                 'statusCode': 401,
                 'headers': {'Content-Type': 'application/json'},
                 'body': json.dumps({'message': 'User ID not found in token'})
             }
         print(f"Authenticated user ID: {cognito_user_id}")
     # --- END DUMMY DECODE ---

    except Exception as e:
         print(f"Token validation/decoding error: {e}")
         return {
             'statusCode': 401,
             'headers': {'Content-Type': 'application/json'},
             'body': json.dumps({'message': 'Authentication failed'})
         }

    # --- 2. Generate and Store State ---
    state = str(uuid.uuid4()) # Generate a unique state value
    try:
        put_state_in_dynamodb(state, cognito_user_id)
    except Exception as e:
         print(f"Failed to save state to DynamoDB: {e}")
         return {
             'statusCode': 500,
             'headers': {'Content-Type': 'application/json'},
             'body': json.dumps({'message': 'Failed to initiate OAuth flow'})
         }

    # --- 3. Get Google App Credentials ---
    app_creds = get_secret_value(APP_CREDS_SECRET_NAME)
    if not app_creds or 'client_id' not in app_creds or 'client_secret' not in app_creds:
        print(f"Failed to retrieve application Google credentials from secret '{APP_CREDS_SECRET_NAME}'.")
        return {
             'statusCode': 500,
             'headers': {'Content-Type': 'application/json'},
             'body': json.dumps({'message': 'Server configuration error'})
        }
    client_id = app_creds['client_id']
    # client_secret = app_creds['client_secret'] # Not needed for the auth URL construction


    # --- 4. Construct Google Authorization URL ---
    if not CALLBACK_REDIRECT_URI:
         print("CALLBACK_REDIRECT_URI environment variable is not set.")
         return {
             'statusCode': 500,
             'headers': {'Content-Type': 'application/json'},
             'body': json.dumps({'message': 'Callback URL not configured'})
         }

    auth_params = {
        'client_id': client_id,
        'redirect_uri': CALLBACK_REDIRECT_URI,
        'response_type': 'code',
        'scope': GOOGLE_PHOTOS_SCOPE,
        'access_type': 'offline', # Important to get a refresh token
        'include_granted_scopes': 'true', # Recommended
        'state': state # Include the generated state
    }

    # Build the authorization URL
    google_auth_url = f"{GOOGLE_AUTH_BASE_URL}?{urllib.parse.urlencode(auth_params)}"

    print(f"Generated Google Auth URL: {google_auth_url}")

    # --- 5. Return Google Auth URL to Frontend ---
    return {
        'statusCode': 200,
        'headers': {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',  # <-- IMPORTANT
        'Access-Control-Allow-Headers': 'Authorization'  # <-- So browser accepts your Bearer token
    },
        'body': json.dumps({'googleAuthUrl': google_auth_url}) # Return the URL in a JSON body
    }