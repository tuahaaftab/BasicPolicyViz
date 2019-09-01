import configparser
import json

import boto3

import util

def filter_account_authorization_details(account_authorization_details):
    """
    Filters account_authorization_details to keep only required information in a simpler format

    :param account_authorization_details: A dictionary containing information of (users, groups, roles, and policies)
    of the PolicyViz user AWS account

    :return: A filtered dictionary containing information of (users, groups, and policies)
    of the PolicyViz user AWS account
    """

    filtered_details = {}

    # filtering users
    filtered_details['UserDetailList'] = {}
    filtered_users = filtered_details['UserDetailList']
    users = account_authorization_details['UserDetailList']

    group_users = {}  # key=group name, value=list of users in group
    for user in users:
        filtered_user = {}
        user_name = user['UserName']
        filtered_user['UserName'] = user['UserName']
        filtered_user['AttachedManagedPolicies'] = []

        for policy_info in user['AttachedManagedPolicies']:
            filtered_user['AttachedManagedPolicies'].append(policy_info['PolicyName'])

        for group_name in user['GroupList']:
            if group_name not in group_users:
                group_users[group_name] = []
            group_users[group_name].append(user_name)

        filtered_users[user_name] = filtered_user

        # filtering users
        filtered_details['UserDetailList'] = {}
        filtered_users = filtered_details['UserDetailList']
        users = account_authorization_details['UserDetailList']

        group_users = {}  # key=group name, value=list of users in group
        for user in users:
            filtered_user = {}
            user_name = user['UserName']
            filtered_user['UserName'] = user['UserName']
            filtered_user['AttachedManagedPolicies'] = []

            for policy_info in user['AttachedManagedPolicies']:
                filtered_user['AttachedManagedPolicies'].append(policy_info['PolicyName'])

            for group_name in user['GroupList']:
                if group_name not in group_users:
                    group_users[group_name] = []
                group_users[group_name].append(user_name)

            filtered_users[user_name] = filtered_user


    # filtering groups
    filtered_details['GroupDetailList'] = {}
    filtered_groups = filtered_details['GroupDetailList']
    groups = account_authorization_details['GroupDetailList']

    for group in groups:
        filtered_group = {}
        group_name = group['GroupName']
        filtered_group['GroupName'] = group['GroupName']
        filtered_group['AttachedManagedPolicies'] = []

        for policy_info in group['AttachedManagedPolicies']:
            filtered_group['AttachedManagedPolicies'].append(policy_info['PolicyName'])

        if group_name in group_users.keys():
            filtered_group['GroupUsers'] = group_users[group_name]
        else:
            filtered_group['GroupUsers'] = []

        filtered_groups[group_name] = filtered_group


    # filtering policies
    filtered_details['Policies'] = {}
    filtered_policies = filtered_details['Policies']
    policies = account_authorization_details['Policies']

    for policy in policies:
        if policy['IsAttachable']:
            filtered_policy = {}
            policy_name = policy['PolicyName']
            filtered_policy['PolicyName'] = policy['PolicyName']

            for policy_version in policy['PolicyVersionList']:
                if policy_version['IsDefaultVersion']:
                    filtered_policy['Document'] = policy_version['Document']

            filtered_policies[policy_name] = filtered_policy

    return filtered_details

def fetch_account_details(pv_role_session):
    """
    Fetches a snapshot of the configuration of IAM permissions (users, groups, roles, and policies)
    from PolicyViz user account

    :param pv_role_session: A session object to communicate with PolicyViz user AWS account

    :return: A dictionary containing information of (users, groups, roles, and policies)
    of the PolicyViz user AWS account
    """

    print("\n======== Fetching account details =========\n")

    # iam_client used to interact with IAM API
    iam_client = pv_role_session.client('iam')

    account_authorization_details = iam_client.get_account_authorization_details(Filter=['User', 'Group', 'LocalManagedPolicy', 'AWSManagedPolicy'])

    return account_authorization_details

def create_pv_user_session(config, pv_session):
    """
    Assumes role "RoleForFastVisualizer" in the AWS account of PolicyViz user

    :param config: A dictionary that stores role information for "RoleForFastVisualizer"
    :param pv_session: A session used to communicate with PolicyViz AWS account

    :return: A session object to communicate with PolicyViz user AWS account
    """

    role_information = config['role_information']
    role_arn = role_information['role_arn']
    external_id = role_information['external_id']

    # STS client required to assume role in user account
    sts_client = pv_session.client('sts')

    # role_info of "RoleForFastVisualizer" in SultanFarooq(AWS account)
    role = sts_client.assume_role(
        RoleArn=role_arn,
        ExternalId=external_id,
        RoleSessionName='session5',
        DurationSeconds=900
    )

    # a session with AWS will be established using role_info
    pv_role_session = boto3.session.Session(
        aws_access_key_id=role['Credentials']['AccessKeyId'],
        aws_secret_access_key=role['Credentials']['SecretAccessKey'],
        aws_session_token=role['Credentials']['SessionToken']
    )

    return pv_role_session

def create_pv_session(config):
    """
    Creates session with PolicyViz AWS account

    :param config: A dictionary that stores credentials to access AWS account

    :return: A session object to communicate with PolicyViz AWS account
    """

    credentials = config['credentials']

    # TuahaAdmin credentials
    # credentials used to create session
    # session used by PolicyViz app to interact with AWS
    pv_session = boto3.session.Session(
        aws_access_key_id=credentials['aws_access_key_id'],
        aws_secret_access_key=credentials['aws_secret_access_key']
    )

    return pv_session


if __name__ == '__main__':
    print("=================== Main Flow  ======================\n")

    config = configparser.ConfigParser()
    config.read('config.ini')

    # create session with PolicyViz AWS account
    pv_session = create_pv_session(config)

    # create session with PolicyViz user AWS account
    pv_role_session = create_pv_user_session(config, pv_session)

    account_authorization_details = fetch_account_details(pv_role_session)

    print("\n==> account_authorization_details\n:", json.dumps(account_authorization_details, indent=2, default=str))

    account_authorization_details = filter_account_authorization_details(account_authorization_details)

    print("\n==> filtered account_authorization_details\n:", json.dumps(account_authorization_details, indent=2, default=str))

    user_specified_service_name = "rds"  # Policies will be summarized for this service

    service_categorized_actions_status = util.get_service_categorized_actions_status(user_specified_service_name)

    print(service_categorized_actions_status)

    print("==> ", json.dumps(service_categorized_actions_status, indent=2))

    groups = account_authorization_details['GroupDetailList']
    policies = account_authorization_details['Policies']

    # summarize policies for a single group only
    for group_name, group in groups.items():
        if group_name == 'QA':
            util.summarize_policies_for_group(group, policies, service_categorized_actions_status, user_specified_service_name)


    print("==> ", json.dumps(service_categorized_actions_status, indent=2))