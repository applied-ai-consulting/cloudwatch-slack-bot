# cloudwatch-slack-bot
Cloudwatch Slack Bot

# Problem Statement:
It is not easy to monitor and manage the serverless solution. Observing and configuring for notification on specific types of strings/errors in the logs is not as easy.
Developers know what they have put in the logs, so they know what to look for in the logs which needs notification. Thus providing a simpler Slack based approach will help the developers a lot. e.g. I want to know if the logs has string like SQLException. But I do not want to get notified when the logs has AccessDeniedException or BadRequestException strings. So I will configure the notification only for SQLException.

# Goal:
Monitor and managing a serverless solution through communication mechanism like Slack

# Usecases:
Slack user should be able to list the log groups and configure to receive a notification if a particular String is found in the specified log groups(configure the alarm in Cloudwatch itself). User should be able to see a list of strings that are configured for alarm/notification and change it too. All of it only for logs in Cloudwatch.
Later: More use cases can come later. More Clouds and Serverless platforms can come later. More communication platforms like Teams can come later too.
Later: Knowing what the average load and getting notifications if the load goes beyond average can come later too
Later: User should be able to put a email too for notification.

# Expectations:
The solution itself should be serverless using AWS Lambda and dynamodb as required.
The solution should take care of basic security when connecting with Slack
Working code. Usecases marked Later: need not be done now. Just mentioned so that you worry about the architecture with that in context.

# Presentation:
Demo for below
add your app to slack channel
show the list of log groups
configure to receive notification on specific string in the log. You can do self monitoring of the botServerless if you do not have other serverless app
show the list of strings configured. Add/edit/delete these.

# Some Reference:
https://github.com/MrTomerLevi/aws-sns-to-slack
https://serverlessrepo.aws.amazon.com/applications/arn:aws:serverlessrepo:us-east-1:641494176294:applications~aws-sns-to-slack-publisher
https://hevodata.com/learn/aws-sns-webhooks-integration/
