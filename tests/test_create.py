import os
import json
import boto3
from mock import patch
from moto import mock_dynamodb2

from create_table import create_table


@mock_dynamodb2
@patch.dict(os.environ, {"DYNAMODB_TABLE": "botServerless-table"})
def test_create_ok():
    from create import create
    create_table()
    create_event = {'body': '{"text": "sample"}',
                    'httpMethod': 'POST'}
    result = create(create_event, None)

    assert result['statusCode'] == 200


@mock_dynamodb2
@patch.dict(os.environ, {"DYNAMODB_TABLE": "botServerless-table"})
def test_create_error():
    from create import create
    create_table()

    create_event = {'httpMethod': 'POST', 'body': '{}'}
    result = create(create_event, None)

    assert result['statusCode'] == 501