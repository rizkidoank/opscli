import boto3


def get_groups_by_names(group_names):
    client = boto3.client('ec2')
    groups = client.describe_security_groups(
        Filters=[
            {
                'Name': 'group-name',
                'Values': list(group_names)
            }
        ]
    )['SecurityGroups']
    return groups


def get_groups_by_tag_name(group_names):
    client = boto3.client('ec2')
    groups = client.describe_security_groups(
        Filters=[
            {
                'Name': 'group-name',
                'Values': list(group_names)
            }
        ]
    )['SecurityGroups']
    return groups


def describe_existing_groups(group_names):
    groups = get_groups_by_names(group_names) \
             + get_groups_by_tag_name(group_names)
    return {group['GroupId']: group for group in groups}.values()


def get_group_id(group_name):
    client = boto3.client('ec2')
    try:
        res = client.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': [group_name]
                },
            ],
        )
        return res['SecurityGroups'][0]['GroupId']
    except IndexError:
        res = client.describe_security_groups(
            Filters=[
                {
                    'Name': 'tag:Name',
                    'Values': [group_name]
                },
            ],
        )
        return res['SecurityGroups'][0]['GroupId']


def get_group_name(group_id):
    ec2 = boto3.resource('ec2')
    group = ec2.SecurityGroup(group_id)
    try:
        for tag in group.tags:
            if tag['Key'] == 'Name':
                return tag['Value']
    except TypeError:
        return group.group_name
