import json

NOT_IMPLEMENTED_ERROR_RESPONSE = {
    'statusCode': 501,
    'body': json.dumps('Input parameters missing')
}

NOT_FOUND_RESPONSE = {
    'statusCode': 404,
    'body': json.dumps('Item not Found')
}

INVALID_TOKEN_RESPONSE = {
    'statusCode': 400,
    'body': json.dumps('Invalid token')
}