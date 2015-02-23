import optparse
from random import randint
import sys
import uuid

from bwctl.utils import init_logging

from bwctl.config import get_config
from bwctl.server.limits import LimitsDB
from bwctl.server.rest_api_server import RestApiServer
from bwctl.server.scheduler import Scheduler
from bwctl.server.coordinator import Coordinator
from bwctl.server.tests_db.simple import SimpleDB
from bwctl.tools import get_tools, get_available_tools, configure_tools
from bwctl.utils import get_logger

config_options = {
    "server_address": "string(default='')",
    "server_port": "integer(default=4824)",
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
                                       limits_db=self.limits_db)

        self.rest_api_server = RestApiServer(coordinator=self.coordinator,
                                             server_address=self.config['server_address'],
                                             server_port=self.config['server_port'])

    def run(self):
        try:
            self.rest_api_server.start()

            self.rest_api_server.join()
        except Exception as e:
            logger.error("Exception: %s" % e)
        finally:
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
