import boto3
import os
import json
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection
from botocore.exceptions import ClientError

# AWS Clients
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
rekognition = boto3.client('rekognition')

# Configuration
BUCKET = 'photo-storage-recommendation'
DDB_TABLE = dynamodb.Table('RekognitionTracker')  # Updated table name for minimal tracking
TODAY = datetime.utcnow().strftime('%Y-%m-%d')

# OpenSearch Config
es = OpenSearch(
    hosts=[{'host': 'search-photo-index-u6o4c3fhzvwkj657amwq3d6jjm.aos.us-east-1.on.aws', 'port': 443}],
    http_auth=(os.environ.get('ES_USERNAME'),os.environ.get('ES_PASSWORD')),  # Use credentials or IAM if configured
    use_ssl=True,
    verify_certs=True,
    connection_class=RequestsHttpConnection
)

def is_processed(s3_key):
    try:
        response = DDB_TABLE.get_item(Key={'s3_key': s3_key})
        return 'Item' in response and response['Item'].get('processed', False)
    except ClientError as e:
        print(f"DynamoDB get error: {e}")
        return False

def mark_processed(s3_key):
    try:
        DDB_TABLE.put_item(Item={
            's3_key': s3_key,
            'processed': True
        })
    except ClientError as e:
        print(f"DynamoDB put error: {e}")
        
def lambda_handler(event, context):
    for record in event['Records']:
        body = json.loads(record['body'])

        user_id = body['user_id']
        s3_key = body['s3_key']
        filename = body['filename']
        media_item_id = body['media_item_id']

        if is_processed(s3_key):
            continue

        try:
            labels_response = rekognition.detect_labels(
                Image={'S3Object': {'Bucket': BUCKET, 'Name': s3_key}},
                MaxLabels=10,
                MinConfidence=80
            )
        except rekognition.exceptions.InvalidImageFormatException as e:
            print(f"[ERROR] Invalid image format for {s3_key}: {e}")
            continue

        labels = [label['Name'].lower() for label in labels_response['Labels']]
        
        doc = {
            'user_id': user_id,
            's3_key': s3_key,
            'media_item_id': media_item_id,
            'filename': filename,
            'labels': labels,
            'upload_date': TODAY,
            'processed': True
        }

        es.index(index='photo-metadata', id=media_item_id, body=doc)
        mark_processed(s3_key)
