from botocore.exceptions import ClientError
import os
import jinja2
from opscli.configure import read_config
from jira_tools import JiraTools
from opscli.csv_processor import *
from opscli.aws_tools import get_group_id
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


def download_connectivity_file(args):
    client = auth_jira()
    conn_file = client.get_latest_connectivity_file(args.ticket_id).get()
    csv_data = BytesIO(conn_file).getvalue() \
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
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(path or './'),
        autoescape=True
    )
    return env.get_template(filename).render(context)


def connectivity_smoke_test(args):
    client = auth_jira()
    csv_file = client.get_latest_connectivity_file(args.ticket_id).get()

    # source_group = get_unique_groups_by_direction(csv_file, 'source')
    # destination_group = get_unique_groups_by_direction(csv_file, 'destination')
