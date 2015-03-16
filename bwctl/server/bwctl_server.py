import optparse
from random import randint
import sys
import time
import uuid

from bwctl.utils import init_logging, daemonize

from bwctl.protocol.coordinator.client import Client as CoordinatorClient
from bwctl.config import get_config
from bwctl.server.limits import LimitsDB
from bwctl.server.coordinator_server import CoordinatorServer
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
    def __init__(self, config=None):
        self.config = config

        self.logger = get_logger()

        # Set the tool configuration
        configure_tools(self.config)

        get_available_tools()

        self.scheduler = Scheduler()
        self.tests_db  = SimpleDB()
        self.limits_db = LimitsDB()

        self.coordinator_client = CoordinatorClient(server_address=self.config['coordinator_address'],
                                                    server_port=self.config['coordinator_port'],
                                                    api_key=self.config['coordinator_auth_key'])

        self.coordinator = Coordinator(scheduler=self.scheduler, tests_db=self.tests_db,
                                       limits_db=self.limits_db, coordinator_client=self.coordinator_client)

        self.coordinator_server = CoordinatorServer(server_address=self.config['coordinator_address'],
                                                    server_port=self.config['coordinator_port'],
                                                    api_key=self.config['coordinator_auth_key'],
                                                    coordinator=self.coordinator)

        self.rest_api_server = RestApiServer(coordinator=self.coordinator_client,
                                             server_address=self.config['server_address'],
                                             server_port=self.config['server_port'],
                                             legacy_endpoint_port=self.config['legacy_endpoint_server_port'])

        self.legacy_endpoint_server = LegacyEndpointServer(server_address=self.config['legacy_endpoint_server_address'],
                                                           server_port=self.config['legacy_endpoint_server_port'])

        self.legacy_server = LegacyBWCTLServer(coordinator=self.coordinator_client,
                                               server_address=self.config['legacy_server_address'],
                                               server_port=self.config['legacy_server_port'])


    def run(self):
        try:
            for process in [ self.coordinator_server, self.rest_api_server, self.legacy_server, self.legacy_endpoint_server ]:
                 process.start()

            # Periodically check if processes have terminated
            process_exited = False
            while not process_exited:
                for process in [ self.coordinator_server, self.rest_api_server, self.legacy_server, self.legacy_endpoint_server ]:
                    if not process.is_alive():
                        process_exited = True
                        break

                time.sleep(5)
        except Exception as e:
            self.logger.error("Exception: %s" % e)
        finally:
            self.logger.debug("Killing legacy endpoint handler")
            self.legacy_endpoint_server.terminate()
            self.logger.debug("Killing legacy server")
            self.legacy_server.terminate()
            self.logger.debug("Killing REST API server")
            self.rest_api_server.terminate()
            self.logger.debug("Killing coordinator")
            self.coordinator_server.terminate()

def bwctld():
    """Entry point for bwctld."""
    argv = sys.argv
    oparse = optparse.OptionParser()
    oparse.add_option("-c", "--config-file", dest="config_file", default="")
    oparse.add_option("-p", "--pid-file", dest="pid_file", default="")
    oparse.add_option("-d", "--daemonize", action="store_true", dest="daemonize", default=False)
    oparse.add_option("-f", "--log-file", dest="log_file", default=None)
    oparse.add_option("-s", "--syslog-facility", dest="syslog_facility", default=None)
    oparse.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False)

    (opts, args) = oparse.parse_args(args=argv)

    init_logging("bwctld", syslog_facility=opts.syslog_facility,
                 log_file=opts.log_file, debug=opts.verbose,
                 screen=not opts.daemonize
                )

    logger = get_logger()

    config = get_config(command_config_options=config_options,
                             config_file=opts.config_file)

    if opts.daemonize:
        daemonize(pidfile=opts.pid_file)

    # Unfortunately, we need to initialize this after we daemonize so that we
    # can create processes using multiprocess.
    bwctld = BwctlServer(config=config)
    bwctld.run()
