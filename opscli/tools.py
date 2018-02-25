import csv
from StringIO import StringIO
from io import BytesIO

from botocore.exceptions import ClientError
from tabulate import tabulate
import os
import jinja2
import boto3
import opscli
from opscli.configure import read_config
from jira_tools import JiraTools
from opscli.csv_processor import *
from opscli.aws_tools import get_group_name, get_group_id
import logging

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


def auth_jira():
    conf = read_config()
    client = JiraTools()
    client.auth(
        conf['jira']['server'],
        (conf['jira']['username'], conf['jira']['password']),
        conf['jira']['project']
    )
    return client


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
                group_name = get_group_name(group_id)
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
    client = auth_jira()
    conn_file = client.get_latest_connectivity_file(args.ticket_id).get()
    csv_data = BytesIO(conn_file).getvalue()\
        .decode('utf-8').lower().splitlines()
    csv_data[0] = 'source,destination,from_port,to_port,protocol'
    with open('connectivity.csv', 'w') as out_file:
        out_file.write("\n".join(csv_data))
        out_file.close()


def describe_connectivity(args):
    client = auth_jira()
    csv_file = client.get_latest_connectivity_file(args.ticket_id).get()
    read_connectivity_file(csv_file, args.detailed)


def describe_security_group(args):
    try:
        if args.group_id and args.group_name:
            logger.error('should only use group id or group name')
        elif args.group_id:
            group_rules = parse_group_rules(args.group_id)
        elif args.group_name:
            group_id = get_group_id(args.group_name)
            group_rules = parse_group_rules(group_id)
        else:
            logger.error('invalid argument')
    except TypeError:
        logger.error('group not found', exc_info=True)
    except ClientError as err:
        logger.error(err.message)
    except Exception as e:
        logger.error(e, exc_info=True)

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
    rules_template = os.path.dirname(opscli.__file__) + \
                     '/templates/security_group_rule.jinja2'
    try:
        group_id = get_group_id(args.group_name)
        new_group = False
    except IndexError:
        group_id = str('${{aws_security_group.{}.id}}'.format(args.group_name))
        new_group = True
    rules = []
    client = auth_jira()
    csv_file = client.get_latest_connectivity_file(args.ticket_id).get()
    csv_file = StringIO(cleanup_connectivity_csv(csv_file))
    reader = csv.DictReader(csv_file)
    for row in reader:
        if row['Destination'] == args.group_name:
            try:
                row['Source'] = {
                    'group_id': get_group_id(row['Source']),
                    'group_name': row['Source']
                }
            except IndexError:
                row['source'] = {
                    'group_id': str(
                        '${{aws_security_group.{}.id}}'.format(row['Source'])),
                    'group_name': row['Source']
                }
            try:
                row['Destination'] = {
                    'group_id': get_group_id(row['Destination']),
                    'group_name': row['Destination']
                }
            except IndexError:
                row['Destination'] = {
                    'group_id': str(
                        '${{aws_security_group.{}.id}}'.format(
                            row['Destination'])),
                    'group_name': row['Destination']
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
        header = CONNECTIVITY_HEADER.splitlines(',').append('rule_exist')
        for row in reader:
            exists = False
            ingress = None
            for group in dests:
                if group['GroupName'] == row['destination']:
                    ingress = group['IpPermissions']
            if ingress:
                for rule in ingress:
                    if (rule['FromPort'] == int(row['from_port'])) \
                            and (rule['ToPort'] == int(row['to_port'])):
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
                row['proto'],
                exists
            ])
        print('Rules count : {}'.format(rules_count))
        print(tabulate(rules, header, tablefmt='psql'))
