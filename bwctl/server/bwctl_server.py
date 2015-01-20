from random import randint
from configobj import ConfigObj, flatten_errors
from validate import Validator
import uuid

from bwctl.config import BwctlConfig
from bwctl.server.coordinator import CoordinatorClient
from bwctl.server.limits import LimitsDB
from bwctl.server.rest_api_server import RestApiServer
from bwctl.server.scheduler import Scheduler
from bwctl.server.test_coordinator import TestCoordinator
from bwctl.server.tests_db import TestsDB
from bwctl.tools import get_tools, configure_tools

config_options = {
    "coordinator_address": "string(default='127.0.0.1')",
    "coordinator_port":    "integer(default=%d)" % (randint(1025, 65535)),
    "coordinator_auth_key":    "string(default=%s)" % (uuid.uuid4().hex)
}

class BwctlServer:
    def __init__(self, config_file=None):
	# Initialize the configuration spec XXX: we should normalize how this
	# gets done.
        for tool in get_tools():
            for key, value in tool.config_options().iteritems():
                if key in config_options and \
                    value != config_options[key]:
                    raise ValidationException("Two tools use the config option '%s' but with different types" % key)

                config_options[key] = value 

        config_spec = []
        for option, type in config_options.iteritems():
            config_spec.append("%s = %s" % (option, type))

        config_line = []
        if config_file:
            config_line = [line.strip() for line in open(config_file)]

        self.config = ConfigObj(config_line, configspec=config_spec)

        validator = Validator()
        results = self.config.validate(validator)

        if results != True:
            for (section_list, key, _) in flatten_errors(config, results):
                if key is not None:
                    raise ValidationException('The "%s" key in the section failed validation' % key)

        configure_tools(self.config)

        self.coord_client = CoordinatorClient(server_address=self.config['coordinator_address'],
                                              server_port=self.config['coordinator_port'],
                                              auth_key=self.config['coordinator_auth_key'])

        self.scheduler = Scheduler()
        self.tests_db  = TestsDB()
        self.limits_db = LimitsDB()

        self.rest_api_server = RestApiServer(coordinator_client=self.coord_client)

        self.test_coordinator = TestCoordinator(server_address=self.config['coordinator_address'],
                                                server_port=self.config['coordinator_port'],
                                                auth_key=self.config['coordinator_auth_key'],
                                                scheduler=self.scheduler, tests_db=self.tests_db,
                                                limits_db=self.limits_db)

    def run(self):
        try:
            self.test_coordinator.start()
            self.rest_api_server.start()

            self.test_coordinator.join()
        except Exception as e:
            print "Exception: %s" % e
        finally:
            self.rest_api_server.kill_children()
            self.rest_api_server.terminate()
            self.test_coordinator.kill_children()
            self.test_coordinator.terminate()
