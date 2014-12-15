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

    def run(self):
        # Start Coordinator server

        # Run Rest API server

        # Run Legacy API server

        # Run Legacy Endpoint server

        # Wait for a SIGTERM, or for one of the children to exit

    def exit(self):
	# XXX: gracefully exit, killing all the various processes started.


class TestCoordinator(multiprocessing.Process):
    def __init__(self, coordinator_module=None, scheduler=None, limits_db=None, tests_db=None):
        self.coordinator_module=coordinator_module
        self.scheduler=scheduler
        self.limits_db=limits_db
        self.tests_db = tests_db

    def _setup_callbacks(self):
        def get_test_cb(**kwargs):
            return self.handle_get_test(kwargs)

        def get_test_results_cb(**kwargs):
            return self.handle_get_test_results(kwargs)

        def request_test_cb(**kwargs):
            return self.handle_get_test_results(kwargs)

        def finish_test_cb(**kwargs):
            return self.handle_finish_test(kwargs)

        def client_confirm_test_cb(**kwargs):
            return self.handle_client_confirm_test(kwargs)

        def server_confirm_test_cb(**kwargs):
            return self.handle_server_confirm_test(kwargs)

        self.coordinator.set_callbacks(get_test_cb=get_test_cb,
                                       get_test_results_cb=get_test_results_cb,
                                       request_test_cb=request_test_cb,
                                       finish_test_cb=finish_test_cb,
                                       client_confirm_test_cb=client_confirm_test_cb,
                                       server_confirm_test_cb=server_confirm_test_cb
                                      )

        return

    def handle_get_test(self, requesting_address=None, test_id=None, value=None):
        # 1. Read test from the DB
        # 2. Return a get-test-response message

        test = self.tests_db.get_test(test_id)
        if not test:
            raise Exception("Test not found")

        return BWCTLError(), test

    def handle_get_test_results(self, requesting_address=None, test_id=None, value=None):
        # 1. Read test results from the DB
        # 2. Return a get-test-response message

        results = self.tests_db.get_results(test_id)
        if not results:
            raise Exception("Test results not found")

        return BWCTLError(), results


    def handle_request_test(self, requesting_address=None, test_id=None, value=None):
        # 1. Save the test to the DB with a 'pending' status
        # 2. Do an initial limit check for the test
        #   - Mark it as rejected if the limit check fails, skip to #6
        # 3. Try scheduling the test
        #   - Mark it as rejected if scheduling fails, skip to #6
	# 4. Do a second limit check to make sure
	#   - Mark it as rejected if the limit check fails, and unschedule it.
	# 5. Mark the test as "confirmed", and update the 'scheduled' times
        # 6. Return a get-test-request-response message

        test_id = self.tests_db.add_test(value)
        if not test_id:
            raise Exception("Problem adding test to DB")

        ret_test = self.tests_db.get_test(test_id)

        return BWCTLError(), ret_test

    def handle_update_test(self, requesting_address=None, test_id=None, value=None):
        # 1. Check if the test's status is "client-confirmed" or higher
        #   - Return "update failed" if so
        # 2. Replace the test in the DB with the updated parameters, and a 'pending' status
        # 3. Unschedule the test
        # 4. Do an initial limit check for the test
        #   - Mark it as rejected if the limit check fails, skip to #8
        # 5. Try scheduling the test
        #   - Mark it as rejected if scheduling fails, skip to #8
	# 6. Do a second limit check to make sure
	#   - Mark it as rejected if the limit check fails, and unschedule it.
	# 7. Mark the test as "confirmed", and update the 'scheduled' times
        # 8. Return a get-test-request-response message
        pass

    def handle_client_confirm_test(self, requesting_address=None, test_id=None, value=None):
        # 1. If the test's status is already confirmed, goto #4
        # 2. Mark the test's status as "client-confirmed"
        # 3. Spawn a process to validate the test with the other side
        #    - Fail the test if the process can't be spawned
        # 4. Return a client-confirm-response message
        pass

    def handle_server_confirm_test(self, requesting_address=None, test_id=None, value=None):
        # 1. If the server status is already confirmed, goto #4
        # 2. Mark the server status as "server-confirmed"
        # 3. Spawn a process to exec the tool at the specified time
        #    - Fail the test if the process can't be spawned
        # 4. Return a client-confirm-response message
        pass

    def handle_finish_test(self, requesting_address=None, test_id=None, value=None):
	# 1. Make sure the test isn't already in a "finished" state
	#   - If it is, send back a "failed" response
	# 2. Save the test results in the DB
        # 3. Mark the test's status as the finish message notes it should be
        # 4. Unschedule this test
        # 5. Cleanly shut down -response message
        # 6. Return a fail-test-response message
        pass
