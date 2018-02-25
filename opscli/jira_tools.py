from jira import JIRA
from jira.exceptions import JIRAError
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class JiraTools(object):
    def __init__(self):
        self.client = None

    def auth(self, server, basic_auth, project):
        try:
            self.client = JIRA(server, basic_auth=basic_auth)
            self.client.project(project)
        except JIRAError, err:
            logger.error(err.text, exc_info=True)

    def get_latest_connectivity_file(self, ticket_id):
        try:
            items = self.client.issue(ticket_id).fields.attachment
            csv_files = [item for item in items if item.mimeType == 'text/csv']
            return csv_files[0]
        except JIRAError, err:
            logger.error(err.text, exc_info=True)
