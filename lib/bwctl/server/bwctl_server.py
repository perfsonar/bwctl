import optparse
from random import randint
import sys
import uuid

from bwctl.utils import init_logging

from bwctl.protocol.coordinator.client import Client as CoordinatorClient
from bwctl.config import get_config
from bwctl.server.limits import LimitsDB
from bwctl.server.rest_api_server import RestApiServer
from bwctl.server.legacy_servers import LegacyEndpointServer, LegacyBWCTLServer
from bwctl.server.scheduler import Scheduler
from bwctl.server.coordinator import Coordinator
from bwctl.server.tests_db.simple import SimpleDB
from bwctl.tools import get_tools, get_available_tools, configure_tools
from bwctl.utils import get_logger

config_options = {
    "coordinator_address": "string(default='127.0.0.1')",
    "coordinator_port":    "integer(default=%d)" % (randint(1025, 65535)),
    "coordinator_auth_key":    "string(default=%s)" % (uuid.uuid4().hex),
    "legacy_server_address": "string(default='')",
    "server_address": "string(default='')",
    "server_port": "integer(default=4824)",
    "legacy_server_address": "string(default='')",
    #"legacy_server_port": "integer(default=4823)",
    "legacy_server_port": "integer(default=4822)",
    "legacy_endpoint_server_address": "string(default='')",
    "legacy_endpoint_server_port": "integer(default=6001)",
}


class BwctlServer:
    def __init__(self, config_file=None):
        self.logger = get_logger()

        self.config = get_config(command_config_options=config_options,
                                 config_file=config_file)

        # Set the tool configuration
        configure_tools(self.config)

        get_available_tools()

        self.scheduler = Scheduler()
        self.tests_db  = SimpleDB()
        self.limits_db = LimitsDB()

        self.coordinator = Coordinator(scheduler=self.scheduler, tests_db=self.tests_db,
                                       limits_db=self.limits_db,
                                       server_address=self.config['coordinator_address'],
                                       server_port=self.config['coordinator_port'],
                                       auth_key=self.config['coordinator_auth_key'])

        self.coordinator_client = CoordinatorClient(server_address=self.config['coordinator_address'],
                                                    server_port=self.config['coordinator_port'],
                                                    auth_key=self.config['coordinator_auth_key'])

        self.rest_api_server = RestApiServer(coordinator=self.coordinator_client,
                                             server_address=self.config['server_address'],
                                             server_port=self.config['server_port'])

        self.legacy_endpoint_server = LegacyEndpointServer(server_address=self.config['legacy_endpoint_server_address'],
                                                           server_port=self.config['legacy_endpoint_server_port'])

        self.legacy_server = LegacyBWCTLServer(coordinator=self.coordinator_client,
                                               server_address=self.config['legacy_server_address'],
                                               server_port=self.config['legacy_server_port'])


    def run(self):
        try:
            self.coordinator.start()
            self.rest_api_server.start()
            self.legacy_server.start()
            self.legacy_endpoint_server.start()

            # XXX: handle the "join" differently
            self.coordinator.join()
            self.rest_api_server.join()
            self.legacy_server.join()
            self.legacy_endpoint_server.join()
        except Exception as e:
            logger.error("Exception: %s" % e)
        finally:
            self.legacy_endpoint_server.kill_children()
            self.legacy_endpoint_server.terminate()
            self.legacy_server.kill_children()
            self.legacy_server.terminate()
            self.rest_api_server.kill_children()
            self.rest_api_server.terminate()
            self.coordinator.kill_children()
            self.coordinator.terminate()

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

    bwctld = BwctlServer(config_file=opts.config_file)
    bwctld.run()

    try:
        bwctld = BwctlServer(config_file=opts.config_file)
        bwctld.run()
    except Exception, e:
        logger.error("Problem with bwctld: %s" % e)
        sys.exit(1)
