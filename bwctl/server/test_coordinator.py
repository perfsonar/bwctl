from bwctl.utils import BwctlProcess, timedelta_seconds
from bwctl.server.scheduler import Scheduler
from bwctl.server.coordinator import CoordinatorServer, CoordinatorClient
from bwctl.models import BWCTLError, Results
from bwctl.exceptions import *

import datetime

class TestCoordinator(CoordinatorServer):
    def __init__(self, server_address="127.0.0.1", server_port=5678, auth_key="", scheduler=Scheduler(), limits_db=None, tests_db=None):
        self.scheduler = scheduler
        self.limits_db = limits_db
        self.tests_db  = tests_db
        self.test_processes = {}

        super(TestCoordinator, self).__init__(server_address=server_address, server_port=server_port, auth_key=auth_key)

    def handle_get_test(self, requesting_address=None, test_id=None):
        # 1. Read test from the DB
        # 2. Return the test

        test = self.tests_db.get_test(test_id)

        return test

    def handle_get_test_results(self, requesting_address=None, test_id=None):
        # 1. Read test results from the DB
        # 2. Return a get-test-response message

        results = self.tests_db.get_results(test_id)

        return results


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
            raise ValidationException("New test shouldn't have an id")

        test.change_state("accepted")

        test.scheduling_parameters.accepted_time = datetime.datetime.now() + datetime.timedelta(seconds=5)

        test.change_state("scheduled")

        test_id = self.tests_db.add_test(test)
        if not test_id:
            raise SystemProblemException("Problem adding test to DB")

        ret_test = self.tests_db.get_test(test_id)

        return ret_test

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
        print "handle_client_confirm_test: %s" % test_id
        # 1. If the test's status is already confirmed, goto #4
        # 2. Mark the test's status as "client-confirmed"
        # 3. Spawn a process to validate the test with the other side
        #    - Fail the test if the process can't be spawned
        # 4. Return a client-confirm-response message
        test = self.tests_db.get_test(test_id)
        if not test:
            raise ResourceNotFoundException("Test not found")

        if not test.status == "scheduled":
            raise TestInvalidActionException

        # XXX: we should check if we're past the test's start time, and fail if so.

        test.change_state("client-confirmed")

        self.tests_db.replace_test(test_id, test)

        validation_proc = ValidateRemoteTestProcess(
                                                     test_id=test_id,
                                                     coordinator_address=self.server_address,
                                                     coordinator_port=self.server_port,
                                                     auth_key=self.auth_key
                                                   )
        validation_proc.start()

        return

    def handle_server_confirm_test(self, requesting_address=None, test_id=None):
        # 1. If the server status is already confirmed, goto #4
        # 2. Mark the server status as "server-confirmed"
        # 3. Spawn a process to exec the tool at the specified time
        #    - Fail the test if the process can't be spawned
        # 4. Return a server-confirm-response message
        test = self.tests_db.get_test(test_id)
        if not test:
            raise ResourceNotFoundException("Test not found")

        # XXX: we should check if we're past the test's start time, and fail if so.

        test.change_state("server-confirmed")

        self.tests_db.replace_test(test_id, test)

        start_failure_proc = TestTimeoutFailureProcess(
                                                       test_id=test_id,
                                                       coordinator_address=self.server_address,
                                                       coordinator_port=self.server_port,
                                                       auth_key=self.auth_key
                                                     )
        start_failure_proc.start()

        return

    def handle_finish_test(self, requesting_address=None, test_id=None, results=None):
        # 1. Make sure the test isn't already in a "finished" state
        #   - If it is, send back a "failed" response
        # 2. Save the test results in the DB
        # 3. Mark the test's status as the finish message notes it should be
        # 4. Unschedule this test
        # 5. Cleanly shut down -response message
        # 6. Return a fail-test-response message
        test = self.tests_db.get_test(test_id)
        if not test:
            raise ResourceNotFoundException("Test not found")

        if test.status == "finished":
           raise TestAlreadyFinishedException

        test.change_state("finished")

        self.tests_db.add_results(test_id, results)

        return

class TestActionHandlerProcess(BwctlProcess):
    def __init__(self, test_id=None, test=None, coordinator_address=None,
                       coordinator_port=None, auth_key=None):

        coordinator_client = CoordinatorClient(server_address=coordinator_address,
                                               server_port=coordinator_port,
                                               auth_key=auth_key)

        self.coordinator_client = coordinator_client
        self.test_id            = test_id
        self.test               = test

        super(TestActionHandlerProcess, self).__init__()


    def run(self):
        err = None

        try:
            self.handler()
        except BwctlException as e:
            err = e
        except Exception as e:
            import traceback
            print "Stack trace: %s" % traceback.format_exc()
            err = SystemProblemException(str(e))

        if err:
            self.handle_failure(err.as_bwctl_error())

    def refresh_test(self):
        self.test = self.coordinator_client.get_test(self.test_id)
        return self.test

    def handler(self):
        raise SystemProblemException("The handler function needs overwritten")

    def handle_failure(self, err):
        results = Results(
                      status = "failed",
                      bwctl_errors = [ err ],
                  )

        self.coordinator_client.finish_test(self.test_id, results)

class TestHandlerProcess(TestActionHandlerProcess):
    def handler(self):
        # Wait until a couple seconds past the time the test was supposed to start.
        td = datetime.datetime.now() - self.test.scheduling_parameters.accepted_time
        td = td + datetime.timedelta(seconds=2) # Wait for 2 seconds after

        sleep_time = timedelta_seconds(td)
        if sleep_time > 0:
            time.sleep(sleep_time)

        # Check if the test is currently running or finished, and raise an
        # error if not.
        test = self.refresh_test()
        if test.status != "running" and test.status != "finished":
            raise TestStartTimeFailure

        return

class ValidateRemoteTestProcess(TestActionHandlerProcess):
    def handler(self):
        # XXX: actually validate the test
        # XXX: timeout if we'd be validating longer than the test would take to
        #      start

        self.coordinator_client.server_confirm_test(self.test_id)

        return
