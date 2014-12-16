from bwctl.utils import BwctlProcess
from bwctl.server.scheduler import Scheduler
from bwctl.server.coordinator import CoordinatorServer
from bwctl.models import BWCTLError

class TestCoordinator(CoordinatorServer):
    def __init__(self, server_address="127.0.0.1", server_port=5678, auth_key="", scheduler=Scheduler(), limits_db=None, tests_db=None):
        self.scheduler=scheduler
        self.limits_db=limits_db
        self.tests_db = tests_db

        super(TestCoordinator, self).__init__(server_address=server_address, server_port=server_port, auth_key=auth_key)

    def handle_get_test(self, requesting_address=None, test_id=None):
        # 1. Read test from the DB
        # 2. Return the test

        try:
            test = self.tests_db.get_test(test_id)
        except Exception as e:
            raise e 

        return BWCTLError(), test

    def handle_get_test_results(self, requesting_address=None, test_id=None):
        # 1. Read test results from the DB
        # 2. Return a get-test-response message

        try:
            results = self.tests_db.get_results(test_id)
        except Exception as e:
            raise e

        return BWCTLError(), results


    def handle_request_test(self, requesting_address=None, test=None):
        # 1. Save the test to the DB with a 'pending' status
        # 2. Do an initial limit check for the test
        #   - Mark it as rejected if the limit check fails, skip to #6
        # 3. Try scheduling the test
        #   - Mark it as rejected if scheduling fails, skip to #6
	# 4. Do a second limit check to make sure
	#   - Mark it as rejected if the limit check fails, and unschedule it.
	# 5. Mark the test as "confirmed", and update the 'scheduled' times
        # 6. Return a get-test-request-response message

        # XXX: check limits

        if test.id:
            raise Exception("New test shouldn't have an id")

        print "Adding test\n"
        test_id = self.tests_db.add_test(test)
        if not test_id:
            raise Exception("Problem adding test to DB")

        print "Test added\n"
        ret_test = self.tests_db.get_test(test_id)

        print "Ret_test: %s\n" % ret_test

        return BWCTLError(), ret_test

    def handle_update_test(self, requesting_address=None, test_id=None, test=None):
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

    def handle_client_confirm_test(self, requesting_address=None, test_id=None):
        # 1. If the test's status is already confirmed, goto #4
        # 2. Mark the test's status as "client-confirmed"
        # 3. Spawn a process to validate the test with the other side
        #    - Fail the test if the process can't be spawned
        # 4. Return a client-confirm-response message
        test = self.tests_db.get_test(test_id)
        if not test:
            raise Exception("Test not found")

        return BWCTLError(), None

    def handle_server_confirm_test(self, requesting_address=None, test_id=None):
        # 1. If the server status is already confirmed, goto #4
        # 2. Mark the server status as "server-confirmed"
        # 3. Spawn a process to exec the tool at the specified time
        #    - Fail the test if the process can't be spawned
        # 4. Return a client-confirm-response message
        test = self.tests_db.get_test(test_id)
        if not test:
            raise Exception("Test not found")

        return BWCTLError(), None

    def handle_finish_test(self, requesting_address=None, test_id=None, results=None):
	# 1. Make sure the test isn't already in a "finished" state
	#   - If it is, send back a "failed" response
	# 2. Save the test results in the DB
        # 3. Mark the test's status as the finish message notes it should be
        # 4. Unschedule this test
        # 5. Cleanly shut down -response message
        # 6. Return a fail-test-response message
        return BWCTLError(), None
