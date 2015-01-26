from random import randint
import uuid

from bwctl.config import get_config
from bwctl.server.coordinator import CoordinatorClient
from bwctl.server.limits import LimitsDB
from bwctl.server.rest_api_server import RestApiServer
from bwctl.server.scheduler import Scheduler
from bwctl.server.test_coordinator import TestCoordinator
from bwctl.server.tests_db import TestsDB
from bwctl.tools import get_tools, configure_tools

config_options = {
    "server_address": "string(default='')",
    "server_port": "integer(default=4824)",
    "coordinator_address": "string(default='127.0.0.1')",
    "coordinator_port":    "integer(default=%d)" % (randint(1025, 65535)),
    "coordinator_auth_key":    "string(default=%s)" % (uuid.uuid4().hex)
}


class BwctlServer:
    def __init__(self, config_file=None):
        self.config = get_config(command_config_options=config_options,
                                 config_file=config_file)

        # Set the tool configuration
        configure_tools(self.config)

        # XXX: we need to figure out what tools are executable

        self.coord_client = CoordinatorClient(server_address=self.config['coordinator_address'],
                                              server_port=self.config['coordinator_port'],
                                              auth_key=self.config['coordinator_auth_key'])

        self.scheduler = Scheduler()
        self.tests_db  = TestsDB()
        self.limits_db = LimitsDB()

        self.rest_api_server = RestApiServer(coordinator_client=self.coord_client,
                                             server_address=self.config['server_address'],
                                             server_port=self.config['server_port'])

        self.test_coordinator = TestCoordinator(server_address=self.config['coordinator_address'],
                                                server_port=self.config['coordinator_port'],
                                                auth_key=self.config['coordinator_auth_key'],
                                                scheduler=self.scheduler, tests_db=self.tests_db,
                                                limits_db=self.limits_db)

    def run(self):
        try:
            self.test_coordinator.start()
            self.rest_api_server.start()

            self.rest_api_server.join()
        except Exception as e:
            print "Exception: %s" % e
        finally:
            self.test_coordinator.kill_children()
            self.test_coordinator.terminate()
