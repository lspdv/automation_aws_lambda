# permission checker.py (rollback: permission_checker_rollback.py)
-ready for AWS lambda, `can be set with Cloud Watch and crone job`
-checks if all users or roles in account have all needed permissions based on prepared policy json file
-can check on more accounts
-list of exceptions can be used for not attaching policies to specific users/roles

# Configuration needs:

## AWS Lambda function:
-in AWS Lambda create new Lambda function
-trigger can be set during creating new function or later
-IAM role have to be set to Lambda function with policy to have permission for SQS, STS (Security Token Services) and IAM
-resource is admins-team role arn, this role then has to be in every account you want to access to
-insert code from file permission_checker.py which `will work also in Python 2.7 Lambda env` (`from __future__ import` is already in code, script will behave as written in Python 2.7 for Lambda function)
-set all needed parameters `parameter_...` to attach/detach policies in roles/user in code for your own use

For rollback of whole work Lambda with `permission_checker_rollback.py` can be set

## AWS SQS service:
in AWS SQS service on the same account where Lambda runs, create new Queue
IAM role has to be set for Lambda function with sqs:SendMessage, sqs:GetQueueUrl


##Configuration for giving Labda permission to do job for you:
on every account you want access to set new role (logging role - in example it is `admins-team`)
on each new role (each account one) `Trust Relationships` have to be set with ID of account where Lambda function runs
each `admins-team` role should have policy to allow changes on IAM service

Something like: 

```
{
    "Version": "2018-03-30",
    "Statement": [
        {
            "Sid": "auto-generated",
            "Effect": "Allow",
            "Action": [
                "iam:AttachRolePolicy",
                "iam:AttachUserPolicy",
                "iam:DetachRolePolicy",
                "iam:DetachUserPolicy",
                "iam:GetPolicy",
                "iam:GetRole",
                "iam:GetRolePolicy",
                "iam:GetUser"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```
