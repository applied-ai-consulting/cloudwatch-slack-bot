import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime
from urllib.parse import parse_qs

import boto3
import requests
from boto3.dynamodb.conditions import Attr

from secrets_manager import get_secret

logger = logging.getLogger()
logger.setLevel(logging.INFO)

client = boto3.client('logs', region_name='us-east-1')
cw_client = boto3.client('cloudwatch', region_name='us-east-1')
sns_client = boto3.client('sns', region_name='us-east-1')
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])


def respond(err, res=None):
    print(res)
    return {
        'statusCode': '400' if err else '200',
        'body': str(err) if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }


def get_log_groups(next_token=None, prefix=None):
    log_groups = ""

    if prefix and next_token:
        response = client.describe_log_groups(
            logGroupNamePrefix=prefix, nextToken=next_token, limit=10)
    elif prefix:
        response = client.describe_log_groups(
            logGroupNamePrefix=prefix, limit=10)
    elif next_token:
        response = client.describe_log_groups(nextToken=next_token, limit=10)
    else:
        response = client.describe_log_groups(limit=10)

    print(json.dumps(response, indent=4))

    for each_line in response['logGroups']:
        print(each_line)
        log_groups += "\n- " + each_line['logGroupName']

    if not log_groups:
        log_groups = "No matching log groups found. Please try again..!!"

    if "nextToken" in response:
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "LogGroups",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                            "type": "mrkdwn",
                            "text": log_groups
                    }
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "emoji": True,
                                "text": "Show more"
                            },
                            "style": "primary",
                            "value": response["nextToken"]
                        }
                    ]
                }
            ]
        }
    else:
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "LogGroups",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": log_groups
                    }
                }
            ]
        }

    return payload


def show_input_dialog(trigger_id, initial_values=None):

    view = {
        "title": {
            "type": "plain_text",
            "text": "Configure Alarm",
            "emoji": True
        },
        "submit": {
            "type": "plain_text",
            "text": "Save",
            "emoji": True
        },
        "type": "modal",
        "blocks": [
            {
                "type": "input",
                "element": {
                        "type": "plain_text_input"
                },
                "label": {
                    "type": "plain_text",
                    "text": "Enter Log Group Name",
                    "emoji": True
                }
            },
            {
                "type": "input",
                "element": {
                        "type": "plain_text_input"
                },
                "label": {
                    "type": "plain_text",
                    "text": "Enter Alarm String",
                    "emoji": True
                }
            },
            {
                "type": "input",
                "element": {
                        "type": "plain_text_input"
                },
                "label": {
                    "type": "plain_text",
                    "text": "Enter Email for receiving Notification",
                    "emoji": True
                }
            }
        ]
    }

    if initial_values:
        view['title']['text'] = "Update Alarm Config"
        view['blocks'][0]['element']['initial_value'] = initial_values[0]
        view['blocks'][1]['element']['initial_value'] = initial_values[1]
        view['blocks'][2]['element']['initial_value'] = initial_values[2]
        view['private_metadata'] = initial_values[3]

    payload = {"trigger_id": trigger_id,
               "view": view}

    return payload


def configure_alarm(payload):
    log_group_block_id = payload['view']['blocks'][0]['block_id']
    log_group_action_id = payload['view']['blocks'][0]['element']['action_id']

    alarm_string_block_id = payload['view']['blocks'][1]['block_id']
    alarm_string_action_id = payload['view']['blocks'][1]['element']['action_id']

    email_group_block_id = payload['view']['blocks'][2]['block_id']
    email_group_action_id = payload['view']['blocks'][2]['element']['action_id']

    log_group_name = payload['view']['state']['values'][log_group_block_id][log_group_action_id]['value']
    alarm_string = payload['view']['state']['values'][alarm_string_block_id][alarm_string_action_id]['value']
    email = payload['view']['state']['values'][email_group_block_id][email_group_action_id]['value']

    response = client.put_metric_filter(
        logGroupName=log_group_name,
        filterName=f"{payload['user']['username']}_{alarm_string}",
        filterPattern=alarm_string,
        metricTransformations=[
            {
                'metricName': alarm_string,
                'metricNamespace': payload['user']['username'],
                'metricValue': '1',
            },
        ]
    )

    print(response)

    response = sns_client.create_topic(
        Name=f"{payload['user']['username']}-Topic"
    )

    print(response)

    sns_client.subscribe(
        TopicArn=response['TopicArn'],
        Protocol='email',
        Endpoint=email
    )

    response = cw_client.put_metric_alarm(
        AlarmName=f'{alarm_string}_Alarm',
        ComparisonOperator='GreaterThanOrEqualToThreshold',
        EvaluationPeriods=1,
        MetricName=alarm_string,
        Namespace=payload['user']['username'],
        AlarmActions=[
            response['TopicArn'],
        ],
        Period=300,
        Statistic='Sum',
        Threshold=2,
        TreatMissingData='notBreaching',
        AlarmDescription=f'Alarm when {alarm_string} is found'
    )

    print(response)

    timestamp = str(datetime.utcnow().timestamp())

    update_id = payload['view'].get('private_metadata', None)

    if update_id:
        item = table.get_item(Key={'id': update_id})["Item"]
        data = {
            'log_group_name': log_group_name,
            'alarm_string': alarm_string,
            'email': email,
            'updatedAt': timestamp,
        }
        item.update(data)
    else:
        item = {
            'id': str(uuid.uuid1()),
            'username': payload['user']['username'],
            'log_group_name': log_group_name,
            'alarm_string': alarm_string,
            'email': email,
            'createdAt': timestamp,
            'updatedAt': timestamp,
        }

    table.put_item(Item=item)

    payload = {
        "response_action": "update",
        "view": {
            "type": "modal",
            "title": {
                "type": "plain_text",
                "text": "Configuration Status"
            },
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "plain_text",
                        "text": "Alarm Configured Successfully"
                    }
                }
            ]
        }
    }

    return payload


def show_list(result):

    payload = {
        "blocks": [
        ]
    }

    divider = {
        "type": "divider"
    }

    buttons = {
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "emoji": True,
                    "text": "Edit"
                },
                "style": "primary",
                "value": ""
            },
            {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "emoji": True,
                    "text": "Delete"
                },
                "style": "danger",
                "value": ""
            }
        ]
    }

    for item in result:
        block = {
            "type": "section",
            "fields": []
        }
        block['fields'].append({
            "type": "mrkdwn",
            "text": f"*Log Group Name:*\n{item['log_group_name']}"
        })

        block['fields'].append({
            "type": "mrkdwn",
            "text": f"*Alarm String:*\n{item['alarm_string']}"
        })

        block['fields'].append({
            "type": "mrkdwn",
            "text": f"*Email:*\n{item['email']}"
        })

        buttons['elements'][0]['value'] = item['id']
        buttons['elements'][1]['value'] = item['id']

        payload['blocks'].append(block)
        payload['blocks'].append(buttons)
        payload['blocks'].append(divider)

    print(payload)

    return payload


def delete_alarm(payload):
    id = payload['actions'][0]['value']
    result = table.get_item(
        Key={
            'id': id
        }
    )
    log_group_name = result['Item']['log_group_name']
    alarm_string = result['Item']['alarm_string']

    response = client.delete_metric_filter(
        logGroupName=log_group_name,
        filterName=f"{payload['user']['username']}_{alarm_string}"
    )
    print(response)

    response = cw_client.delete_alarms(
        AlarmNames=[
            f'{alarm_string}_Alarm',
        ]
    )
    print(response)

    table.delete_item(
        Key={
            'id': id
        }
    )


def edit_alarm(payload):

    trigger_id = payload['trigger_id']
    id = payload['actions'][0]['value']
    result = table.get_item(
        Key={
            'id': id
        }
    )
    log_group_name = result['Item']['log_group_name']
    alarm_string = result['Item']['alarm_string']
    email = result['Item']['email']

    payload = show_input_dialog(
        trigger_id, [log_group_name, alarm_string, email, id])

    return payload


def is_valid_request(request):

    slack_signing_secret = get_secret("slack_oauth_token")[
        'slack_signing_secret']
    timestamp = request['headers']['X-Slack-Request-Timestamp']
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False

    payload = request['body']

    sig_basestring = 'v0:' + timestamp + ':' + payload

    sig_basestring = sig_basestring.encode('utf-8')

    signing_secret = slack_signing_secret.encode('utf-8')

    my_signature = 'v0=' + \
        hmac.new(signing_secret, sig_basestring, hashlib.sha256).hexdigest()
    slack_signature = request['headers']['X-Slack-Signature']
    if hmac.compare_digest(my_signature, slack_signature):
        return True

    return False


def create(event, context):
    logger.info(event)
    params = parse_qs(event['body'])

    token = get_secret("slack_oauth_token")['Slack Bot User OAuth Token']

    if not is_valid_request(event):
        logger.error("Request does not match expected token")
        return respond(Exception('Invalid request token'))

    if params.get('payload'):
        payload = json.loads(params['payload'][0])
        if payload.get('type', None) == "view_submission":
            response = configure_alarm(payload)
            return respond(None, response)

        elif payload.get('type', None) == "block_actions" and payload['actions'][0]['text']['text'] == "Delete":

            response_url = payload['response_url']
            delete_alarm(payload)
            result = table.scan(
                FilterExpression=boto3.dynamodb.conditions.Attr('username').eq(payload['user']['username']))

            payload = show_list(result['Items'])
            print(payload)
            response = requests.post(response_url, data=json.dumps(payload))
            print(response.text)
            return

        elif payload.get('type', None) == "block_actions" and payload['actions'][0]['text']['text'] == "Edit":
            response_url = payload['response_url']

            payload = edit_alarm(payload)

            response = requests.post("https://slack.com/api/views.open", headers={
                                     'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}, data=json.dumps(payload))
            print(response.text)
            return

        next_token = payload['actions'][0]['value']
        response_url = payload['response_url']

        payload = get_log_groups(next_token)
        print(payload)
        response = requests.post(response_url, data=json.dumps(payload))
        print(response.text)
        return

    else:
        user = params['user_name'][0]
        command = params['command'][0]
        channel = params['channel_name'][0]
        command_text = params.get('text', [None])[0]

        logger.info("OK")

        if command == "/list-all-log-groups":
            payload = get_log_groups()
            return respond(None, payload)

        elif command == "/list-log-groups-with-prefix":
            payload = get_log_groups(prefix=command_text)
            return respond(None, payload)

        elif command == "/configure-alarm":
            trigger_id = params['trigger_id'][0]
            payload = show_input_dialog(trigger_id)
            response = requests.post("https://slack.com/api/views.open", headers={
                                     'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}, data=json.dumps(payload))
            print(response.text)
            return respond(None, "OK")

        elif command == "/list-configured-alarms":
            result = table.scan(
                FilterExpression=boto3.dynamodb.conditions.Attr('username').eq(user))

            payload = show_list(result['Items'])
            print(payload)
            return respond(None, payload)

    return respond(None, "%s invoked %s in %s with the following text: %s" % (user, command, channel, command_text))
