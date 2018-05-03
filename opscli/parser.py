import argparse
from opscli.tools import *
from opscli.configure import configure


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version='1.0.0')

    subparser = parser.add_subparsers()

    configure_parser = subparser.add_parser('configure')
    configure_parser.set_defaults(func=configure)

    describe_connectivity_parser = subparser.add_parser(
        'describe-connectivity')
    describe_connectivity_parser.add_argument('--ticket-id')
    describe_connectivity_parser.add_argument(
        '--detailed', action='store_true', default=False)
    describe_connectivity_parser.set_defaults(func=describe_connectivity)

    describe_secgroup_parser = subparser.add_parser('describe-security-group')
    describe_secgroup_parser.add_argument('--group-id')
    describe_secgroup_parser.add_argument('--group-name')
    describe_secgroup_parser.add_argument('--detailed', action='store_true')
    describe_secgroup_parser.set_defaults(func=describe_security_group)

    download_connectivity_parser = subparser.add_parser(
        'download-connectivity')
    download_connectivity_parser.add_argument('--ticket-id')
    download_connectivity_parser.set_defaults(func=download_connectivity_file)

    generate_group_rules_parser = subparser.add_parser('generate-rules')
    generate_group_rules_parser.add_argument('--group-name')
    generate_group_rules_parser.add_argument('--input-file')
    generate_group_rules_parser.set_defaults(func=generate_tf_group_rules)

    connectivity_test_parser = subparser.add_parser('connectivity-smoke-test')
    connectivity_test_parser.add_argument('--input-file')
    connectivity_test_parser.set_defaults(func=connectivity_smoke_test)

    import_group_rules_parser = subparser.add_parser('import-group-rules')
    import_group_rules_parser.add_argument("--group-id")
    import_group_rules_parser.set_defaults(func=import_group_rules)
    return parser
