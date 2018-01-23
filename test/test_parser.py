import unittest
from opscli.parser import *


class CommandLineTest(unittest.TestCase):
    def setUp(self):
        parser = create_parser()
        self.parser = parser


class ParserTestCase(CommandLineTest):
    def test_parser(self):
        cases = [
            ['describe-connectivity --ticket-id TEST-123', describe_connectivity],
            ['estimate-point --ticket-id TEST-123', estimate_point],
            ['describe-security-group --group-id sg-12345', describe_security_group],
            ['describe-security-group --group-name test', describe_security_group]
        ]
        for case in cases:
            args = self.parser.parse_args(case[0].split(' '))
            self.assertEqual(args.func, case[1])


if __name__ == '__main__':
    unittest.main()
