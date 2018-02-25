import json
import sys
import getpass
import os
import logging

CONF_DIR = os.getenv('HOME') + '/.opscli/'
CONF_FILE = 'config.json'
CONF_PATH = CONF_DIR + CONF_FILE

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


def read_config():
    try:
        with open(CONF_PATH) as config:
            json_data = json.load(config)
            return json_data
    except IOError:
        logger.error("config not found, use 'configure' argument")
        sys.exit(-1)


def configure(args):
    try:
        if not os.path.exists(CONF_DIR):
            os.makedirs(CONF_DIR)
        with open(CONF_PATH) as config:
            config.seek(0)
            config.truncate()
            config.close()
    except IOError:
        pass

    config_data = {'jira': {}}
    config_data['jira']['server'] = raw_input('JIRA Server URL : ')
    config_data['jira']['username'] = raw_input('JIRA Username : ')
    config_data['jira']['password'] = getpass.getpass('JIRA Password : ')
    config_data['jira']['project'] = raw_input('JIRA Project : ')

    with open(CONF_PATH, 'w') as config:
        json.dump(config_data, config)
        config.close()
