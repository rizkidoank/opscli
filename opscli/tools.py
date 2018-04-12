import csv
from io import BytesIO
from ipaddress import ip_network
from tabulate import tabulate
from jira import JIRA
import os
import jinja2
import boto3
import opscli
from opscli.configure import read_config
import json


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
            client = JIRA(server=self.server_url, basic_auth=(
                self.username, self.password), max_retries=1)
            client.project(self.project)
            return client
        except:
            print("Authentication Error")

    def get_most_recent_attacment(self, ticket_id):
        try:
            attachments = self.client.issue(id=ticket_id).fields.attachment
            tmp = []
            for attachment in attachments:
                if str(attachment.filename).split('.')[-1] == 'csv':
                    tmp.append(attachment)

            sorted_attachments = sorted(
                [attachment.raw['created'] for attachment in tmp])
            for attachment in tmp:
                if attachment.raw['created'] == sorted_attachments[len(sorted_attachments) - 1]:
                    return attachment
        except Exception as e:
            print(e)

    def read_csv(self, ticket_id, detailed=False):
        try:
            # get all attachments in issue
            attachment = self.get_most_recent_attacment(ticket_id)
            # download attachment to memory
            attachment = attachment.get()
            # decode the downloaded object and create csv
            csv_data = BytesIO(attachment).getvalue().decode(
                'utf-8').splitlines()
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
        total_existing_groups = len(
            existing_secgroups['to'] + existing_secgroups['from'])

        # total of new security groups to creates
        total_group_names = abs(len(group_names['dst'].union(
            group_names['src'])) - total_existing_groups)

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
        # print('Legacy connection {0} {1}'.format(direction,
        # group['GroupName']))


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


def download_connectivity_file(args):
    conf = read_config()
    jira_tools = JiraTools(
        conf['jira']['server'],
        conf['jira']['project'],
        conf['jira']['username'],
        conf['jira']['password'])
    conn_file = jira_tools.get_most_recent_attacment(args.ticket_id)
    csv_data = BytesIO(conn_file.get()).getvalue().decode(
        'utf-8').lower().splitlines()
    csv_data[0] = 'source,destination,from_port,to_port,protocol'
    with open('connectivity.csv', 'w') as out_file:
        out_file.write("\n".join(csv_data))
        out_file.close()


def describe_connectivity(args):
    conf = read_config()
    jira_tools = JiraTools(
        conf['jira']['server'],
        conf['jira']['project'],
        conf['jira']['username'],
        conf['jira']['password'])
    jira_tools.read_csv(args.ticket_id, args.detailed)


def describe_security_group(args):
    try:
        if args.group_id and args.group_name:
            pass
        elif args.group_id:
            group_rules = parse_group_rules(args.group_id)
        elif args.group_name:
            group_id = get_group_id(args.group_name)
            group_rules = parse_group_rules(group_id)
        else:
            pass
    except Exception as e:
        print(e)

    print("Group ID         : {}".format(group_rules['group_id']))
    print("Group Name       : {}".format(group_rules['group_name']))
    print("Rules Count      : {}".format(len(group_rules['rules'])))
    if args.detailed:
        headers = ["Source", "From Port", "To Port", "Protocol", "Type"]
        print(tabulate(group_rules['rules'], headers, tablefmt="psql"))


def render(template, context):
    path, filename = os.path.split(template)
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(path or './'))
    return env.get_template(filename).render(context)


def generate_tf_group_rules(args):
    rules_template = os.path.dirname(
        opscli.__file__) + '/templates/security_group_rule.jinja2'
    try:
        group_id = get_group_id(args.group_name)
        new_group = False
    except:
        group_id = str('${{aws_security_group.{}.id}}'.format(args.group_name))
        new_group = True
    rules = []
    with open(args.input_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['destination'] == args.group_name:
                try:
                    row['source'] = {
                        'group_id': get_group_id(row['source']),
                        'group_name': row['source']
                    }
                except:
                    row['source'] = {
                        'group_id': str('${{aws_security_group.{}.id}}'.format(row['source'])),
                        'group_name': row['source']
                    }
                try:
                    row['destination'] = {
                        'group_id': get_group_id(row['destination']),
                        'group_name': row['destination']
                    }
                except:
                    row['destination'] = {
                        'group_id': str('${{aws_security_group.{}.id}}'.format(row['destination'])),
                        'group_name': row['destination']
                    }
                rules.append(row)
        context = {
            'group_id': group_id,
            'group_name': args.group_name,
            'rules': rules,
            'new_group': new_group
        }
        result = render(rules_template, context)
        print(result)


def connectivity_smoke_test(args):
    destination_group = set()
    source_group = set()
    rules_count = 0
    with open(args.input_file) as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            source_group.add(row['source'])
            destination_group.add(row['destination'])
            rules_count += 1

        client = boto3.client('ec2')
        srcs = client.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': list(source_group)
                },
            ]
        )['SecurityGroups']
        dests = client.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': list(destination_group)
                },
            ]
        )['SecurityGroups']
        input_file.seek(0)
        input_file.__next__()

        rules = []
        header = ['source', 'destination', 'from_port',
                  'to_port', 'protocol', 'rule_exist']
        for row in reader:
            exists = False
            ingress = None
            for group in dests:
                if group['GroupName'] == row['destination']:
                    ingress = group['IpPermissions']
            if ingress:
                for rule in ingress:
                    if (rule['FromPort'] == int(row['from_port'])) and (rule['ToPort'] == int(row['to_port'])):
                        src_id = None
                        for src in srcs:
                            if src['GroupName'] == row['source']:
                                src_id = src['GroupId']

                        for group in rule['UserIdGroupPairs']:
                            if group['GroupId'] == src_id:
                                exists = True
            rules.append([
                row['source'],
                row['destination'],
                row['from_port'],
                row['to_port'],
                row['protocol'],
                exists
            ])
        print('Rules count : {}'.format(rules_count))
        print(tabulate(rules, header, tablefmt='psql'))


def count_cidrs(attrs):
    count = 0
    for attr in attrs:
        attr = str(attr).split('.')
        if attr[0] == 'cidr_blocks' and attr[1] != "#":
            count = count + 1
    return count


def describe_group(group_id):
    try:
        ec2 = boto3.resource('ec2')
        security_group = ec2.SecurityGroup(group_id)
        if security_group.group_name:
            return security_group
    except Exception:
        session = boto3.Session(profile_name='si-data')
        client = session.resource('ec2')
        security_group = client.SecurityGroup(group_id)
        return security_group


def import_group_rules(args):
    rules_template = os.path.dirname(
        opscli.__file__) + '/templates/import_group_rules.jinja2'

    path, filename = os.path.split(rules_template)
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(path or './'))
    env.globals['describe_group'] = describe_group
    STATE_FILE = os.getcwd() + "/terraform.tfstate"

    if os.path.isfile(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            state_json = json.load(f)

        resources = state_json['modules'][0]['resources']
        for res_reff, res_data in resources.items():
            res_type, res_name = str(res_reff).split('.')
            if res_type == "aws_security_group_rule":
                if res_data['primary']['attributes']['security_group_id'] == args.group_id:
                    attrs = res_data['primary']['attributes']
                    context = {
                        'reference': res_name,
                        'attr': attrs,
                        'count_cidr': int(attrs['cidr_blocks.#'])
                    }
                    print(env.get_template(filename).render(context))
    else:
        print("Terraform state doesn't exist")
