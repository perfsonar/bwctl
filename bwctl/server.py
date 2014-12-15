from bwctl.rest_api_server import RestApiServer
from bwctl.tools import get_tool_types
from bwctl.config import init_config, get_config

from bwctl.server.scheduler import Scheduler
from bwctl.server.limits import LimitsDB

__version__ = "2.0"

class BwctlServer:
    def __init__(self):
        # XXX; read the configuration in

        # XXX: check what tools are available

        # XXX: build scheduler

        # XXX: setup scheduler
	pass

    def run(self):
        # Start Coordinator server

        # Run Rest API server

        # Run Legacy API server

        # Run Legacy Endpoint server

        # Wait for a SIGTERM, or for one of the children to exit
	pass

    def exit(self):
	# XXX: gracefully exit, killing all the various processes started.
