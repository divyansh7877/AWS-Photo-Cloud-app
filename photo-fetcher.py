import boto3
import json
import requests
import datetime
import io
import os # Import os
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from botocore.exceptions import ClientError

# --- Configuration ---
BUCKET = os.environ.get('PHOTO_STORAGE_BUCKET', 'photo-storage-recommendation') # S3 Bucket Name
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
GOOGLE_PHOTOS_SCOPE = ["https://www.googleapis.com/auth/photoslibrary.readonly"]
USER_SECRETS_BASE_NAME = 'google-photos/' # Base Secret Name for user refresh tokens
QUEUE_URL = os.environ['INDEXING_QUEUE_URL']  

# --- AWS Clients ---
s3 = boto3.client('s3')
sqs = boto3.client('sqs')
secrets_client = boto3.client('secretsmanager')

# --- Helper Functions (Reused/Adapted) ---

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
        # print(f"Updated secret {secret_name}.") # Avoid logging secret content
    except secrets_client.exceptions.ResourceNotFoundException:
        # If update fails because secret not found, create it
        try:
            secrets_client.create_secret(Name=secret_name, SecretString=secret_string)
            # print(f"Created secret {secret_name}.") # Avoid logging secret content
        except ClientError as e:
            print(f"Error creating secret {secret_name}: {e}")
            raise # Re-raise the exception
    except ClientError as e:
        print(f"Error updating secret {secret_name}: {e}")
        raise # Re-raise the exception


def get_user_credentials(user_id):
    """Retrieves user credentials (including refresh token) from Secrets Manager and refreshes token."""
    secret_name = f'{USER_SECRETS_BASE_NAME}{user_id}'
    creds_data = get_secret_value(secret_name)
    if not creds_data:
        print(f"No credentials found for user {user_id} in secret '{secret_name}'. Skipping.")
        return None

    # Ensure required keys exist (basic validation)
    if 'refresh_token' not in creds_data or 'client_id' not in creds_data or 'client_secret' not in creds_data:
        print(f"Incomplete credentials data for user {user_id} in secret '{secret_name}'. Skipping.")
        return None

    # Create Credentials object - initial token can be None for refresh flow
    creds = Credentials(
        None, # No access token initially
        refresh_token=creds_data['refresh_token'],
        token_uri=GOOGLE_TOKEN_URI,
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret'],
        scopes=GOOGLE_PHOTOS_SCOPE # Explicitly set scopes
    )

    try:
        # Attempt to refresh the token
        # print(f"Attempting to refresh token for user {user_id}...") # Avoid excessive logging
        creds.refresh(Request())
        # print(f"Token refreshed successfully for user {user_id}.")

        # If refresh token changed (rare, but possible), update the secret
        if creds.refresh_token and creds.refresh_token != creds_data.get('refresh_token'):
             print(f"Refresh token updated for user {user_id}. Saving new token.")
             updated_secret_value = {
                'refresh_token': creds.refresh_token,
                'client_id': creds_data['client_id'], # Keep original client_id/secret
                'client_secret': creds_data['client_secret']
            }
             put_secret_value(secret_name, updated_secret_value)

    except Exception as e:
        print(f"Error refreshing token for user {user_id}: {e}")
        # Depending on the error, you might want to disable the user or alert
        return None # Return None if refresh fails

    return creds

def send_to_indexing_queue(user_id, media_item_id, filename,today_iso):
    s3_key = f"{user_id}/photos/{today_iso}/{media_item_id}_{filename}"
    message = {
        "user_id": user_id,
        "media_item_id": media_item_id,
        "filename": filename,
        "s3_key": s3_key
    }
    sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps(message))
    print(f"Sent indexing message for user {user_id} to queue.")
    
def process_user_photos(user_id):
    """Fetches photos for a specific user for the current day and uploads to S3."""
    print(f"Processing photos for user: {user_id}")
    creds = get_user_credentials(user_id)
    if not creds:
        print(f"Skipping user {user_id} due to invalid or unrefrashable credentials.")

        return

    # Calculate the date for THIS execution of the function
    today = datetime.datetime.utcnow().date()# - datetime.timedelta(days=1)
    today_iso = today.isoformat()
    
    print(f"Fetching photos for user {user_id} on {today_iso}")

    try:
        # Build Google Photos service - static_discovery=False can help in Lambda environments
        service = build('photoslibrary', 'v1', credentials=creds, static_discovery=False)

        # Define the search body with date and media type filters
        body = {
            "filters": {
                "dateFilter": {
                    "dates": [{
                        "year": today.year,
                        "month": today.month,
                        "day": today.day
                    }]
                },
                "mediaTypeFilter": {
                    "mediaTypes": ["PHOTO"]
                }
            },
            "pageSize": 100 # Max page size per request
        }

        media_items_count = 0
        nextPageToken = None

        # --- Pagination Loop ---
        while True:
            if nextPageToken:
                body['pageToken'] = nextPageToken
                # print(f"Fetching next page for user {user_id} with token: {nextPageToken[:10]}...")

            try:
                response = service.mediaItems().search(body=body).execute()
            except Exception as e:
                print(f"Error searching Google Photos API for user {user_id}: {e}")
                # Depending on the error, you might break or raise. Raising allows SQS retry.
                # break # Exit pagination loop on API error
                raise # Re-raise to signal message processing failure for retry


            media_items = response.get('mediaItems', [])

            if not media_items:
                # print(f"No photos found for user {user_id} on {today_iso} (or end of results on this page).")
                break # No items on this page, or no more pages

            print(f"Found {len(media_items)} items on this page for user {user_id}.")

            # --- Process Each Media Item ---
            for item in media_items:
                # Construct download URL - '=d' gets the raw bytes
                # Ensure 'baseUrl' and 'filename' exist, handle potential missing keys
                image_url = item.get('baseUrl')
                filename = item.get('filename')
                media_item_id = item.get('id')

                if not image_url or not filename or not media_item_id:
                     print(f"Skipping media item with missing data for user {user_id}: {item}")
                     continue # Skip this item if essential data is missing

                image_url += "=d" # Append '=d' for raw bytes

                # Construct S3 key using media item ID to prevent filename collisions
                s3_key = f"{user_id}/photos/{today_iso}/{media_item_id}_{filename}"

                # print(f"Attempting to download '{filename}' ({media_item_id}) for user {user_id}...")

                try:
                    # Stream the image data directly from requests to S3
                    with requests.get(image_url, stream=True) as r:
                        r.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

                        # print(f"Uploading '{filename}' to S3 key: {s3_key}")
                        s3.upload_fileobj(
                            r.raw, # Stream the raw response content
                            BUCKET,
                            s3_key,
                            ExtraArgs={'ContentType': r.headers.get('Content-Type', 'application/octet-stream')}
                        )
                        print(f"Successfully uploaded '{filename}' to S3 as {s3_key} for user {user_id}.")
                        media_items_count += 1

                except requests.exceptions.RequestException as e:
                    print(f"Error downloading '{filename}' ({media_item_id}) for user {user_id}: {e}")

                    continue # Continue to the next item in the current page

                except ClientError as e:
                    print(f"Error uploading '{filename}' ({media_item_id}) to S3 ({s3_key}) for user {user_id}: {e}")
                    # Log the error but continue processing other items/pages
                    continue # Continue to the next item in the current page

                except Exception as e:
                    print(f"An unexpected error occurred processing '{filename}' ({media_item_id}) for user {user_id}: {e}")
                    # Catch any other unforeseen errors per item
                    continue # Continue to the next item in the current page

            send_to_indexing_queue(user_id,media_item_id,filename,today_iso)
            nextPageToken = response.get('nextPageToken')
            if not nextPageToken:
                print(f"End of pagination for user {user_id}.")
                break # No more pages

        print(f"Finished processing photos for user {user_id}. Total uploaded: {media_items_count}")

    except Exception as e:
        # This catches errors from service building, pagination loop control, etc.
        print(f"An unhandled error occurred during photo fetching for user {user_id}: {e}")
        # Raising the exception here signals SQS that the message processing failed,
        # triggering a retry based on the queue's configuration.
        raise



# --- Lambda Handler ---
def lambda_handler(event, context):
    # Lambda SQS trigger sends batch of messages in event['Records']
    print(f"Received {len(event.get('Records', []))} SQS messages.")

    for record in event['Records']:
        try:
            # Messages are typically JSON strings in the body
            message_body = json.loads(record['body'])
            user_id = message_body.get('user_id')

            if not user_id:
                print(f"SQS message record missing 'user_id': {record['body']}. Skipping.")
                continue # Skip this message, it's malformed

            # Process the photos for this single user
            # Wrap this call in try/except so one user's failure doesn't stop others in the batch
            try:
                process_user_photos(user_id)


            except Exception as e:
                # Log the failure for this specific user/message
                print(f"Processing failed for SQS message for user {user_id}. Error: {e}")

                raise # Re-raise to indicate failure for this message

        except json.JSONDecodeError:
            print(f"Failed to parse SQS message body as JSON: {record.get('body')}. Skipping malformed message.")
            continue # Skip this malformed message
        except Exception as e:
             print(f"An unexpected error occurred processing SQS record: {e}")
             continue

    print("Finished processing SQS messages in this batch.")

    return {
        "statusCode": 200,
        "body": "Batch processing initiated. Check logs for individual user status."
    }