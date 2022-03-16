import os
import boto3
from mock import patch
from moto import mock_dynamodb2

from create_table import create_table


@mock_dynamodb2
@patch.dict(os.environ, {"DYNAMODB_TABLE": "botServerless-table"})
def test_list_ok():
    from list import list
    create_table()

    list_event = {'httpMethod': 'GET'}
    result = list(list_event, None)

    assert result['statusCode'] == 200