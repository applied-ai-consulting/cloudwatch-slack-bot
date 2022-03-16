import boto3
import os

def create_table():

    dynamodb = boto3.client('dynamodb', region_name='us-east-1')
    dynamodb.create_table(
        TableName=os.environ['DYNAMODB_TABLE'],
        KeySchema=[
            {
                'AttributeName': 'id',
                'KeyType': 'HASH'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'id',
                'AttributeType': 'S'
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 1,
            'WriteCapacityUnits': 1
        }
    )