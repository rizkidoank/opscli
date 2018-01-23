import csv
from io import BytesIO
from ipaddress import ip_network

from tabulate import tabulate
from jira import JIRA
import boto3

from opscli.configure import read_config


class JiraTools:
    def __init__(self, server, project, username, password):
        self.session = None
        self.username = username
        self.password = password
        self.server_url = server
        self.project = project
        self.client = self.auth()

    def auth(self):
        try:
            client = JIRA(server=self.server_url, basic_auth=(self.username, self.password), max_retries=1)
            client.project(self.project)
            return client
        except:
            print("Authentication Error")

    def get_most_recent_attacment(self, ticket_id):
        attachments = self.client.issue(id=ticket_id).fields.attachment
        sorted_attachments = sorted([attachment.raw['created'] for attachment in attachments])
        for attachment in attachments:
            if attachment.raw['created'] == sorted_attachments[len(sorted_attachments) - 1]:
                return attachment

    def read_csv(self, ticket_id, detailed=False):
        try:
            # get all attachments in issue
            attachment = self.get_most_recent_attacment(ticket_id)
            # download attachment to memory
            attachment = attachment.get()
            # decode the downloaded object and create csv
            csv_data = BytesIO(attachment).getvalue().decode('utf-8').splitlines()
            # create list from csv to be printed by tabulate
            table = list(csv.reader(csv_data))
            print(tabulate(table, tablefmt="grid"))
            # if detailed view requested, show the details
            if detailed:
                self.connectivity_details(csv_data)

        except Exception as e:
            print(e)

    def describe_existing_security_groups(self, group_names):
        client = boto3.client('ec2')
        return client.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': list(group_names)
                }
            ]
        )['SecurityGroups']

    def remove_cidr(self, group_names):
        tmp = set()
        for group in group_names:
            try:
                # check if string is network adress
                ip_network(group)
            except:
                tmp.add(group)
        return tmp

    def connectivity_details(self, csv_data):
        print('\nConnectivity Details:')

        # read connectivity csv to dictionary
        reader = csv.DictReader(csv_data)

        # group name for filter
        group_names = {'src': set(), 'dst': set()}

        # get existing security groups from csv
        # using try-except because sometimes its 'Source' instead of 'SourceId'
        for row in reader:
            try:
                group_names['src'].add(row['Source'])
            except:
                group_names['src'].add(row['SourceId'])
            group_names['dst'].add(row['Destination'])

        # data cleanup, removing all cidr value if any
        group_names['src'] = self.remove_cidr(group_names['src'])
        group_names['dst'] = self.remove_cidr(group_names['dst'])

        # collect all existing security groups, send request to aws api
        existing_secgroups = {'from': self.describe_existing_security_groups(group_names['src']),
                              'to': self.describe_existing_security_groups(group_names['dst'])}

        # total of existing security groups for both inbound or outbound
        total_existing_groups = len(existing_secgroups['to'] + existing_secgroups['from'])

        # total of new security groups to creates
        total_group_names = abs(len(group_names['dst'].union(group_names['src'])) - total_existing_groups)

        # Show how many security groups to be created or updated
        # For any existing security groups, it will shown also the id
        print('Create {0} security group(s)'.format(total_group_names))
        print('Update {0} security group(s)'.format(total_existing_groups))
        for group in existing_secgroups['to'] + existing_secgroups['from']:
            print('  - {0} ({1})'.format(group['GroupName'], group['GroupId']))

        # # List legacy connection either in or out
        # for direction in existing_secgroups.keys():
        #     for group in existing_secgroups[direction]:
        #         if group['GroupName'] in LEGACY_CONNECTIONS:
        #             print('Legacy connection {0} {1}'.format(direction, group['GroupName']))


def describe_connectivity(args):
    conf = read_config()
    jira_tools = JiraTools(
        conf['jira']['server'],
        conf['jira']['project'],
        conf['jira']['username'],
        conf['jira']['password'])
    jira_tools.read_csv(args.ticket_id, args.detailed)



def get_group_id(group_name):
    client = boto3.client('ec2')
    res = client.describe_security_groups(
        Filters=[
            {
                'Name': 'group-name',
                'Values': [group_name]
            },
        ],
    )

    return res['SecurityGroups'][0]['GroupId']


def parse_group_rules(group_id):
    ec2 = boto3.resource('ec2')
    security_group = ec2.SecurityGroup(group_id)

    tmp = []

    group_rules = {
        'ingress': security_group.ip_permissions,
        'egress': security_group.ip_permissions_egress
    }

    for rule_type, rules in group_rules.items():
        for rule in rules:
            if rule['IpProtocol'] == '-1':
                rule['FromPort'] = 'all'
                rule['ToPort'] = 'all'

            ips = ['IpRanges', 'Ipv6Ranges']
            for version in ips:
                for ip in rule[version]:
                    tmp.append([
                        ip['CidrIp'],
                        rule['FromPort'],
                        rule['ToPort'],
                        rule['IpProtocol'],
                        rule_type
                    ])

            for group in rule['UserIdGroupPairs']:
                group_id = group['GroupId']
                group_name = ec2.SecurityGroup(group_id).group_name
                tmp.append([
                    "{} ({})".format(group_name, group['GroupId']),
                    rule['FromPort'],
                    rule['ToPort'],
                    rule['IpProtocol'],
                    rule_type])

    return {
        'group_id': security_group.group_id,
        'group_name': security_group.group_name,
        'rules': tmp
    }


def describe_security_group(args):
    if args.group_id and args.group_name:
        pass
    elif args.group_id:
        group_rules = parse_group_rules(args.group_id)
    elif args.group_name:
        group_id = get_group_id(args.group_name)
        group_rules = parse_group_rules(group_id)
    else:
        pass

    print("Group ID         : ", group_rules['group_id'])
    print("Group Name       : ", group_rules['group_name'])
    print("Rules Count      : ", len(group_rules['rules']))
    if args.detailed:
        headers = ["Source", "From Port", "To Port", "Protocol", "Type"]
        print(tabulate(group_rules['rules'], headers, tablefmt="grid"))
