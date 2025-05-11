import boto3
import os
import json

# --- Configuration ---
# SQS Queue URL to send user IDs to
SQS_QUEUE_URL = os.environ.get('SQS_QUEUE_URL')
# Your AWS Cognito User Pool ID
COGNITO_USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID')

# --- AWS Clients ---
sqs = boto3.client('sqs')
# Use the Cognito Identity Provider client
cognito_idp = boto3.client('cognito-idp')

# --- Helper Functions ---

def get_all_user_ids_from_cognito():
    """
    Fetches all user 'sub' (subject) IDs from the configured Cognito User Pool.
    Handles pagination automatically.
    """
    if not COGNITO_USER_POOL_ID:
        print("COGNITO_USER_POOL_ID environment variable is not set.")
        return []

    print(f"Fetching user IDs from Cognito User Pool: {COGNITO_USER_POOL_ID}")
    user_ids = []
    pagination_token = None

    try:
        while True:
            # Use the list_users API call
            list_users_params = {
                'UserPoolId': COGNITO_USER_POOL_ID,

            }
            if pagination_token:
                list_users_params['PaginationToken'] = pagination_token

            response = cognito_idp.list_users(**list_users_params)

            # Process users from the current page
            for user in response.get('Users', []):
                # Find the 'sub' attribute which is the unique user ID
                sub_attribute = next(
                    (attr for attr in user.get('Attributes', []) if attr['Name'] == 'sub'),
                    None
                )
                if sub_attribute:
                    user_ids.append(sub_attribute['Value'])

            # Check for pagination
            pagination_token = response.get('PaginationToken')
            if not pagination_token:
                break # No more pages

        print(f"Successfully fetched {len(user_ids)} user 'sub' IDs from Cognito.")
        return user_ids

    except Exception as e:
        print(f"Error fetching user IDs from Cognito: {e}")

        return []


# --- Lambda Handler ---
def lambda_handler(event, context):
    if not SQS_QUEUE_URL:
        print("SQS_QUEUE_URL environment variable is not set. Exiting.")
        return {"statusCode": 500, "body": "SQS Queue URL not configured."}

    print("Starting daily photo fetch coordination.")

    # *** This is the updated call to fetch users from Cognito ***
    user_ids = get_all_user_ids_from_cognito()

    if not user_ids:
        print("No user IDs found in Cognito or error fetching. No messages sent to SQS.")
        return {"statusCode": 200, "body": "No users processed."}

    messages_sent = 0
    failed_users = []

    for user_id in user_ids:
        try:
            # Send a message to SQS for each user ID
            sqs.send_message(
                QueueUrl=SQS_QUEUE_URL,
                MessageBody=json.dumps({'user_id': user_id}) # Message body contains the user's Cognito 'sub'
            )
            print(f"Sent SQS message for user: {user_id}") # Optional: log each send
            messages_sent += 1
        except Exception as e:
            print(f"Failed to send SQS message for user {user_id}: {e}")
            failed_users.append(user_id)
            # Continue processing other users

    status_message = f"Finished coordinating. Sent {messages_sent} messages to SQS."
    if failed_users:
        status_message += f" Failed to send messages for {len(failed_users)} users: {', '.join(failed_users)}"
        print(status_message)
        # Returning 500 indicates that the coordinator had partial failure
        return {"statusCode": 500, "body": status_message}
    else:
        print(status_message)
        return {"statusCode": 200, "body": status_message}