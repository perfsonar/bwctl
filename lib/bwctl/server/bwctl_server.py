import optparse
from random import randint
import sys
import uuid

from bwctl.utils import init_logging

from bwctl.config import get_config
from bwctl.server.coordinator import CoordinatorClient
from bwctl.server.limits import LimitsDB
from bwctl.server.rest_api_server import RestApiServer
from bwctl.server.scheduler import Scheduler
from bwctl.server.test_coordinator import TestCoordinator
from bwctl.server.tests_db import TestsDB
from bwctl.tools import get_tools, get_available_tools, configure_tools
from bwctl.utils import get_logger

config_options = {
    "server_address": "string(default='')",
    "server_port": "integer(default=4824)",
    "coordinator_address": "string(default='127.0.0.1')",
    "coordinator_port":    "integer(default=%d)" % (randint(1025, 65535)),
    "coordinator_auth_key":    "string(default=%s)" % (uuid.uuid4().hex)
}


class BwctlServer:
    def __init__(self, config_file=None):
        self.logger = get_logger()

        self.config = get_config(command_config_options=config_options,
                                 config_file=config_file)

        # Set the tool configuration
        configure_tools(self.config)

        get_available_tools()

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
            logger.error("Exception: %s" % e)
        finally:
            self.test_coordinator.kill_children()
            self.test_coordinator.terminate()
            self.rest_api_server.kill_children()
            self.rest_api_server.terminate()

def bwctld():
    """Entry point for bwctld."""
    argv = sys.argv
    oparse = optparse.OptionParser()
    oparse.add_option("-c", "--config-file", dest="config_file", default="")
    oparse.add_option("-f", "--log-file", dest="log_file", default=None)
    oparse.add_option("-s", "--syslog-facility", dest="syslog_facility", default=None)
    oparse.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False)

    (opts, args) = oparse.parse_args(args=argv)

    init_logging("bwctld", syslog_facility=opts.syslog_facility, debug=opts.verbose)

    logger = get_logger()

    try:
        bwctld = BwctlServer(config_file=opts.config_file)
        bwctld.run()
    except Exception, e:
        logger.error("Problem with bwctld: %s" % e)
        sys.exit(1)
