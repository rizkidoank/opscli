import csv
from StringIO import StringIO
from csv import reader, DictReader
from io import BytesIO
from pprint import pprint

from ipaddress import ip_network
from tabulate import tabulate
from aws_tools import describe_existing_groups
import logging

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

CONNECTIVITY_HEADER = 'source,destination,from_port,to_port,proto'


def cleanup_connectivity_csv(connectivity_file):
    decoded_string = BytesIO(connectivity_file).getvalue().decode('utf-8')
    csv_data = decoded_string.lower().splitlines()
    if csv_data[0] != CONNECTIVITY_HEADER:
        logger.error('invalid csv header')
        logger.error('expected : {}'.format(CONNECTIVITY_HEADER))
        logger.error('got      : {}'.format(csv_data[0]))
        csv_data[0] = CONNECTIVITY_HEADER
    return '\n'.join(csv_data)


def read_connectivity_file(connectivity_file, detailed=False):
    csv_data = cleanup_connectivity_csv(connectivity_file)
    csv_data = csv_data.splitlines()

    table = list(reader(csv_data))
    print(tabulate(table, tablefmt="psql"))
    if detailed:
        connectivity_details(csv_data)


def is_cidr(input_string):
    try:
        ip_network(input_string.decode('utf-8'))
        return True
    except ValueError:
        return False


def connectivity_details(csv_data):
    print('Connectivity Details:')
    csv_data = DictReader(csv_data)
    group_names = set()

    for row in csv_data:
        for direction in ['source', 'destination']:
            if not is_cidr(row[direction]):
                group_names.add(row[direction])

    existing_groups = describe_existing_groups(group_names)

    total_new_groups = abs(len(group_names) - len(existing_groups))
    print('Create {0} security group(s)'.format(total_new_groups))
    print('Update {0} security group(s)'.format(len(existing_groups)))
    for group in existing_groups:
        print('  - {0} ({1})'.format(group['GroupName'], group['GroupId']))


def get_unique_groups_by_direction(csv_file, direction):
    csv_file = StringIO(cleanup_connectivity_csv(csv_file))
    reader = csv.DictReader(csv_file)
    groups = set([row[direction] for row in reader])
    return groups
