import configparser
import json

import boto3

def fetch_account_details(pv_user_session):
    print("\n======== Fetching account details =========\n")

    # iam_client used to interact with IAM API
    iam_client = pv_user_session.client('iam')

    # IAM users in client account
    response = iam_client.list_users()
    print("\nlist_users response: ", response)
    print("\nUsers: ", json.dumps(response['Users'], indent=2, default=str))

    # IAM groups in client account
    response = iam_client.list_groups()
    print("\nlist_groups response: ", response)
    print("\nGroups: ", json.dumps(response['Groups'], indent=2, default=str))



def create_pv_user_session(config, pv_session):
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
    pv_user_session = boto3.session.Session(
        aws_access_key_id=role['Credentials']['AccessKeyId'],
        aws_secret_access_key=role['Credentials']['SecretAccessKey'],
        aws_session_token=role['Credentials']['SessionToken']
    )

    return pv_user_session

def create_pv_session(config):
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
    pv_user_session = create_pv_user_session(config, pv_session)

    fetch_account_details(pv_user_session)

