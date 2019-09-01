import configparser
import json

import boto3

def fetch_attached_user_policies(pv_role_session, user_name):
    """
    Fetches managed policies that are attached to IAM User

    :param pv_role_session: A session object to communicate with PolicyViz user AWS account
    :param user_name: Name of the IAM User

    :return: List of policies attached
    """

    # iam_client used to interact with IAM API
    iam_client = pv_role_session.client('iam')

    response = iam_client.list_attached_user_policies(UserName=user_info['UserName'])  # list managed policies
    user_policy_infos = response['AttachedPolicies']  # user_policies_info contains policy names and ARNs

    """
    user_policy_documents = []  # stores the policy documents
    for user_policy_info in user_policy_infos:
        response = iam_client.list_policy_versions(user_policy_info['PolicyArn'])
        policy_versions = response['Versions']

        for policy_version in policy_versions:
            if policy_version['IsDefaultVersion'] == True:
                user_policy_documents.append(policy_version['Document'])
    """


def fetch_account_details(pv_role_session):
    """
    Fetches details of user, groups, etc from the PolicyViz user AWS account

    :param pv_role_session: A session object to communicate with PolicyViz user AWS account

    :return: A dictionary containing information of users, groups, etc of the PolicyViz user AWS account
    """

    print("\n======== Fetching account details =========\n")

    account_authorization_details = {}  # stores information of users, groups, etc

    # iam_client used to interact with IAM API
    iam_client = pv_role_session.client('iam')

    # Fetches a snapshot of the configuration of IAM permissions (users, groups, roles, and policies) in your account
    account_authorization_details = iam_client.get_account_authorization_details()

    """

    # IAM users in account
    response = iam_client.list_users()
    account_details['Users'] = response['Users']
    print("\nlist_users response: ", response)
    print("\nUsers: ", json.dumps(response['Users'], indent=2, default=str))

    # IAM groups in account
    response = iam_client.list_groups()
    account_details['Groups'] = response['Groups']
    print("\nlist_groups response: ", response)
    print("\nGroups: ", json.dumps(response['Groups'], indent=2, default=str))
    """


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

    print(json.dumps(account_authorization_details, indent=2, default=str))

    """
    # fetch users, groups from PolicyViz user AWS account
    account_details = fetch_account_details(pv_role_session)

    # fetch policies attached with one of the users
    user_info = account_details['Users'][0]
    user_name = user_info['UserName']

    fetch_policies_for_user(pv_role_session, user_name)

    print(user_policies)
    """