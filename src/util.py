import csv
import re

DENIED = 0
EXPLICITLY_DENIED = -1
EXPLICITLY_ALLOWED = 1
ACCESS_LEVELS = ['List', 'Read', 'Write', 'Permissions management', 'Tagging']
SERVICES_CATEGORIZED_ACTIONS_FILE_PATH = "../resources/services_categorized_actions_files/"

def get_service_categorized_actions_status(service_name):
    """
    Reads file corresponding to service.
    The file contains possible actions along with access_level they belong to.
    The content is read into a dictionary which contains access_level as keys and corresponding actions, status as values

    :param service_name: Service name which PolicyViz user has proviced

    :return: A dictionay with contains access_level as keys.
    Actions and their status are appended as key, value pairs in the list of access_level they fall into
    """

    service_categorized_actions_status = {}
    for access_level in ACCESS_LEVELS:
        service_categorized_actions_status[access_level] = {}

    file_name = SERVICES_CATEGORIZED_ACTIONS_FILE_PATH + service_name + ".csv"
    with open(file_name, 'r') as service_categorized_actions_file:
        reader = csv.reader(service_categorized_actions_file)
        for row in reader:
            action_name = row[0]
            access_level = row[1]
            status = DENIED
            service_categorized_actions_status[access_level].update({action_name: status})
        service_categorized_actions_status['*'] = 0  # for all actions of service
    service_categorized_actions_file.close()

    return service_categorized_actions_status


def summarize_policies_for_group(group, policies, service_categorized_actions_status, user_specified_service_name):
    """
    Parse policies attached with the group and update service_categorized_actions_status accordingly

    :param group: policies attached with this group will be parsed
    :param policies: dictionary containing all fetched policies
    :param service_categorized_actions_status: dictionary that stores actions and their status. Updated while parsing policy

    :return: updated service_categorized_actions_status
    """

    for policy_name in group['AttachedManagedPolicies']:
        policy_document = policies[policy_name]['Document']

        for policy_statement in policy_document['Statement']:
            effect = policy_statement['Effect']
            action_list = []

            if isinstance(policy_statement['Action'], str):
                action_list.append(policy_statement['Action'])
            elif isinstance(policy_statement['Action'], list):
                action_list = policy_statement['Action']

            for action in action_list:
                action = action.split(':')
                service_name = action[0]
                action_name = action[1]

                # consider only one service specified by user while parsing policy
                if service_name != user_specified_service_name:
                    continue

                # ==> ALL services - ALL actions. Example: action = "*"
                if service_name == '*' and effect == 'Deny':
                    service_categorized_actions_status['*'] = EXPLICITLY_DENIED
                elif service_name == '*' and effect == 'Allow':
                    if service_categorized_actions_status['*'] != EXPLICITLY_DENIED:
                        service_categorized_actions_status['*'] = EXPLICITLY_ALLOWED

                    for access_level in ACCESS_LEVELS:
                        access_level_actions_status = service_categorized_actions_status[access_level]
                        for action_name_stored in access_level_actions_status.keys():
                            if access_level_actions_status[action_name_stored] != EXPLICITLY_DENIED:
                                access_level_actions_status[action_name_stored] = EXPLICITLY_ALLOWED

                # ==> ONE service - ALL actions. Example: action = "rds:*"
                elif action_name == '*' and effect == 'Deny':
                    service_categorized_actions_status['*'] = EXPLICITLY_DENIED
                elif action_name == '*' and effect == 'Allow':
                    if service_categorized_actions_status['*'] != EXPLICITLY_DENIED:
                        service_categorized_actions_status['*'] = EXPLICITLY_ALLOWED

                    for access_level in ACCESS_LEVELS:
                        access_level_actions_status = service_categorized_actions_status[access_level]
                        for action_name_stored in access_level_actions_status.keys():
                            if access_level_actions_status[action_name_stored] != EXPLICITLY_DENIED:
                                access_level_actions_status[action_name_stored] = EXPLICITLY_ALLOWED

                # ==> ONE service - MULTIPLE actions. Example: action = "rds:Describe*"
                elif '*' in action_name and effect == 'Deny':
                    for access_level in ACCESS_LEVELS:
                        access_level_actions_status = service_categorized_actions_status[access_level]
                        for action_name_stored in access_level_actions_status.keys():
                            action_name_regex = action_name.replace('*', '.*')
                            if re.match(action_name_regex, action_name_stored):
                                access_level_actions_status[action_name_stored] = EXPLICITLY_DENIED
                elif '*' in action_name and effect == 'Allow':
                    for access_level in ACCESS_LEVELS:
                        access_level_actions_status = service_categorized_actions_status[access_level]
                        for action_name_stored in access_level_actions_status.keys():
                            action_name_regex = action_name.replace('*', '.*')
                            if re.match(action_name_regex, action_name_stored):
                                if access_level_actions_status[action_name_stored] != EXPLICITLY_DENIED:
                                    access_level_actions_status[action_name_stored] = EXPLICITLY_ALLOWED

                # ==> ONE service - ONE action. Example: action = "rds:StartDBInstance"
                elif '*' not in action_name and effect == 'Deny':
                    for access_level in ACCESS_LEVELS:
                        access_level_actions_status = service_categorized_actions_status[access_level]
                        if action_name in access_level_actions_status:
                            access_level_actions_status[action_name] = EXPLICITLY_DENIED
                elif '*' not in action_name and effect == 'Allow':
                    for access_level in ACCESS_LEVELS:
                        access_level_actions_status = service_categorized_actions_status[access_level]
                        if action_name in access_level_actions_status:
                            if access_level_actions_status[action_name] != EXPLICITLY_DENIED:
                                access_level_actions_status[action_name] = EXPLICITLY_ALLOWED


