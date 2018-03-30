#!/usr/local/bin/python
from __future__ import print_function
import boto3

client = boto3.client('iam')
iam = boto3.resource('iam')
sqs = boto3.resource('sqs')
sts = boto3.client('sts')

# Assume Role - cross-accounts account number
account_IDs = ['parameter_role_a', 'parameter_role_b']

# List of exceptions - add role names/user names
roles_not_to_attach_policies = 'parameter_admins-team'
users_not_to_attach_policies = 'parameter_example_user'

# SQS service configuration, allows handle messages about attached policies in roles and users on AWS IAM service and errors
queue = sqs.get_queue_by_name(QueueName='parameter_lambda_permission_checker')


def lambda_handler(event, context):
    for account in account_IDs:
        policies_to_remove = [iam.Policy(arn='arn:aws:iam::' + account + ':policy/parameter_policy_A')]
        logging_role = 'arn:aws:iam::' + account + ':role/parameter_admins-team'

        # Assume Role - cross-account access, roles set in RoleArn
        response = sts.assume_role(
            RoleArn=logging_role,
            RoleSessionName='parameter_permission-checker-admins-team'
        )
        # Assume Role - get credentials for cross-account access
        access_key = response['Credentials']['AccessKeyId']
        secret = response['Credentials']['SecretAccessKey']
        session_token = response['Credentials']['SessionToken']

        session = boto3.session.Session(aws_access_key_id=access_key,
                                        aws_secret_access_key=secret,
                                        aws_session_token=session_token
                                        )

        iam_client = session.client('iam')
        iam_resource = session.resource('iam')

        # Function for detaching policies on Roles, on Amazon Web Services IAM service (except roles defined in 'roles_not_to_attach_policies')
        paginator = iam_client.get_paginator('list_roles')
        response_iterator = paginator.paginate(
            PaginationConfig={
                'PageSize': 200,
                'MaxItems': 350,
            }
        )

        for roles in response_iterator:
            for role in roles['Roles']:
                role_name = role['RoleName']
                role_arn = role['Arn']
                role = iam_resource.Role(role_name)
                policies_on_role = role.attached_policies.all()
                policies_attached_to_role = iam_client.list_attached_role_policies(RoleName=role.name)
                # List of policies attached on roles for SQS service
                policy_names = []
                for policy in policies_attached_to_role['AttachedPolicies']:
                    policy_names.append(policy['PolicyName'])

                # Check if role name starts with letters from List of exceptions 'roles_not_to_detach_policies'
                if role_name.startswith(roles_not_to_detach_policies):
                    print("Role %r is in list of exceptions! No changes enabled." % role_name)

                    queue.send_message(MessageBody='Message: Role %r in list of exceptions - list of policies %s' % (
                        role_name, policy_names), MessageAttributes={
                        'Role': {
                            'StringValue': role_arn,
                            'DataType': 'String'
                        }
                    })
                    continue

                # Detach policies, send 'error' message or 'list_all_attached_policies on role' message on AWS SQS service
                try:
                    for policy in policies_to_remove:
                        print("Checking if policy %s is in role %r." % (policy, role_name))
                        if policy in policies_on_role:
                            print("Policy %r is in role %r, detaching..." % (policy, role_name))
                            role.detach_policy(PolicyArn=policy.arn)
                            policies_attached_to_role = iam_client.list_attached_role_policies(RoleName=role.name)
                            policy_names = []
                            for policy in policies_attached_to_role['AttachedPolicies']:
                                policy_names.append(policy['PolicyName'])
                        else:
                            print("Policy %s is not in role %r. Nothing to detach..." % (policy, role_name))
                        queue.send_message(
                            MessageBody='Message: Role %r - list of policies %s' % (role_name, policy_names),
                            MessageAttributes={
                                'Role': {
                                    'StringValue': role_arn,
                                    'DataType': 'String'
                                }
                            })
                except Exception as exc:
                    print('Error:', exc)
                    queue.send_message(MessageBody='ERROR [ role: %r ]: %s' % (role_name, exc), MessageAttributes={
                        'Role': {
                            'StringValue': role_arn,
                            'DataType': 'String'
                        }
                    })

        # Function for detaching policies on Users, on Amazon Web Services IAM service (except users defined in 'users_not_to_detach_policies')
        paginator = iam_client.get_paginator('list_users')
        response_iterator = paginator.paginate(
            PaginationConfig={
                'PageSize': 200,
                'MaxItems': 350,
            }
        )

        for users in response_iterator:
            for user in users['Users']:
                user_name = user['UserName']
                user_arn = user['Arn']
                user = iam_resource.User(user_name)
                policies_on_user = user.attached_policies.all()
                policies_attached_to_user = iam_client.list_attached_user_policies(UserName=user.name)
                # List of policies attached on roles for SQS service
                policy_names = []
                for policy in policies_attached_to_user['AttachedPolicies']:
                    policy_names.append(policy['PolicyName'])

                # Check if user name starts with letters from List of exceptions 'users_not_to_attach_policies'
                if user_name.startswith(users_not_to_detach_policies):
                    print("User %r is in list of exceptions! No changes enabled." % user_name)
                    queue.send_message(MessageBody='Message: User %r in list of exceptions - list of policies %s' % (
                        user_name, policy_names), MessageAttributes={
                        'Role': {
                            'StringValue': user_arn,
                            'DataType': 'String'
                        }
                    })
                    continue

                # Detach policies, send 'error' message or 'list_all_attached_policies on user' message on AWS SQS service
                try:
                    for policy in policies_to_remove:
                        print("Checking if policy %s is in user %r." % (policy, user_name))
                        if policy in policies_on_user:
                            print("Policy %r is in user %r, detaching..." % (policy, user_name))
                            user.detach_policy(PolicyArn=policy.arn)
                            policies_attached_to_user = iam_client.list_attached_user_policies(UserName=user.name)
                            policy_names = []
                            for policy in policies_attached_to_user['AttachedPolicies']:
                                policy_names.append(policy['PolicyName'])
                        else:
                            print("Policy %s is not in user %r. Nothing to detach..." % (policy, user_name))
                        queue.send_message(
                            MessageBody='Message: User %r -  list of policies %s' % (user_name, policy_names),
                            MessageAttributes={
                                'User': {
                                    'StringValue': user_arn,
                                    'DataType': 'String'
                                }
                            })
                except Exception as exc:
                    print('Error:', exc)
                    queue.send_message(MessageBody='ERROR [ user: %r ]: %s' % (user_name, exc), MessageAttributes={
                        'Role': {
                            'StringValue': user_arn,
                            'DataType': 'String'
                        }
                    })