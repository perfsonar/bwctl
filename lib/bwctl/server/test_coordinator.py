from bwctl.utils import BwctlProcess, timedelta_seconds, ip_matches
from bwctl.server.scheduler import Scheduler
from bwctl.tool_runner import ToolRunner
from bwctl.server.coordinator import CoordinatorServer, CoordinatorClient
from bwctl.models import BWCTLError, Results
from bwctl.exceptions import *
from bwctl.protocol.v2.client import Client

import datetime
import time
from bwctl.dependencies.IPy import IP

def lock_test(f):
    def inner(self, *args, **kwargs):
        test_id = kwargs.get('test_id', None)

        try:
            if test_id:
                self.tests_db.lock_test(test_id)
            
            return f(self, *args, **kwargs)
        finally:
            if test_id:
                self.tests_db.unlock_test(test_id)

    return inner

class TestCoordinator(CoordinatorServer):
    def __init__(self, server_address="127.0.0.1", server_port=5678, auth_key="", scheduler=Scheduler(), limits_db=None, tests_db=None):
        self.scheduler = scheduler
        self.limits_db = limits_db
        self.tests_db  = tests_db
        self.test_processes = {}

        super(TestCoordinator, self).__init__(server_address=server_address, server_port=server_port, auth_key=auth_key)

    @lock_test
    def get_test(self, requesting_address=None, test_id=None):
        return self.tests_db.get_test(test_id)

    @lock_test
    def get_test_results(self, requesting_address=None, test_id=None):
        return self.tests_db.get_results(test_id)

    def request_test(self, requesting_address=None, test=None):
        if test.id:
            raise ValidationException("New test shouldn't have an id")

        # Fill in the client address
        test.client.address = requesting_address

        # Validate the test before we add it to the database
        validate_test(test=test)

        test.change_state("accepted")

        test_id = self.tests_db.add_test(test)
        if not test_id:
            raise SystemProblemException("Problem adding test to DB")

        test = self.tests_db.get_test(test_id)

        error_state = ""
        err = None

        try:
            # XXX: validate test

            # Check the limits before we schedule to make sure that we don't
            # bother doing the scheduling if it's just going to fail anyway.
            self.limits_db.check_test(test, address=requesting_address)

            # Try to schedule the test
            scheduled_time = self.scheduler.add_test(test)

            # Set the times for the given test
            test.scheduling_parameters.reservation_start_time = scheduled_time.reservation_start_time
            test.scheduling_parameters.reservation_end_time = scheduled_time.reservation_end_time
            test.scheduling_parameters.test_start_time = scheduled_time.test_start_time

            # Allocate a test port for the test we're the server side
            if not test.local_client:
                test.local_endpoint.test_port = test.tool_obj.port_range.get_port()

            test.change_state("scheduled")

            # Save the new test settings in the DB
            self.tests_db.replace_test(test_id, test)

            # Check the limits after it's been scheduled, and a test port
            # allocated in case somehow that makes a limit fail.
            self.limits_db.check_test(test, address=requesting_address)
        except (LimitViolatedException, NoAvailablePortsException, NoAvailableTimeslotException) as e:
            error_state = "rejected"
            err = e
        except BwctlException as e:
            error_state = "failed"
            err = e
        except Exception as e:
            error_state = "failed"
            err = SystemProblemException(str(e))

        # Save the error results and raise an exception
        if err:
            results = Results(status=error_state, bwctl_errors=[ err.as_bwctl_error() ])
            self.finish_test(test_id=test_id, status=error_state, results=results)
            raise err

        return test

    @lock_test
    def update_test(self, requesting_address=None, test_id=None, test=None):
        old_test = self.tests_db.get_test(test_id)
        if not old_test:
            raise ResourceNotFoundException("Test not found")

        if not old_test.client_can_modify:
            raise TestInvalidActionException("Test can not be modified")

        if not ip_matches(old_test.client.address, requesting_address):
            raise TestInvalidActionException("Not permitted to modify test")

        err = None
        error_state = ""

        try:
            validate_test(test=test)

            validate_test_changes(new_test=test, old_test=old_test)

            # Check if the new test exceeds any limits
            self.limits_db.check_test(test, address=requesting_address)

            # If the priority or fuzz changed (i.e. our scheduling assumptions
            # are now wrong), or if the requested time is now later than the
            # test time, we've given, we'll need to reschedule the test.
            if test.fuzz != old_test.fuzz or \
               test.scheduling_parameters.priority != test.scheduling_parameters.priority or \
               old_test.scheduling_parameters.test_start_time < test.scheduling_parameters.requested_time or \
               test.scheduling_parameters.latest_acceptable_time < old_test.scheduling_parameters.test_start_time:

                self.scheduler.remove_test(old_test)

                # Try to schedule the test
                scheduled_time = self.scheduler.add_test(test)

                # Set the times for the given test
                test.scheduling_parameters.reservation_start_time = scheduled_time.reservation_start_time
                test.scheduling_parameters.reservation_end_time = scheduled_time.reservation_end_time
                test.scheduling_parameters.test_start_time = scheduled_time.test_start_time

            test.change_state("scheduled")

            # Save the new test settings in the DB
            self.tests_db.replace_test(test_id, test)

            # Check if the new test exceeds any limits
            self.limits_db.check_test(test, address=requesting_address)
        except (LimitViolatedException, NoAvailablePortsException, NoAvailableTimeslotException) as e:
            error_state = "rejected"
            err = e
        except BwctlException as e:
            error_state = "failed"
            err = e
        except Exception as e:
            error_state = "failed"
            err = SystemProblemException(str(e))

        # Save the error results and raise an exception
        if err:
            results = Results(status=error_state, bwctl_errors=[ err.as_bwctl_error() ])
            self.finish_test(test_id=test_id, status=error_state, results=results)
            raise err

        return test

    @lock_test
    def client_confirm_test(self, requesting_address=None, test_id=None):
        # 1. If the test's status is already confirmed, goto #4
        # 2. Mark the test's status as "client-confirmed"
        # 3. Spawn a process to validate the test with the other side
        #    - Fail the test if the process can't be spawned
        # 4. Return a client-confirm-response message
        test = self.tests_db.get_test(test_id)
        if not test:
            raise ResourceNotFoundException("Test not found")

        if not ip_matches(test.client.address, requesting_address):
            raise TestInvalidActionException("Not permitted to confirm test")

        if not test.status == "scheduled":
            raise TestInvalidActionException

        # XXX: we should check if we're past the test's start time, and fail if so.

        test.change_state("client-confirmed")

        self.tests_db.replace_test(test_id, test)

        # Only do the remote validation process if we're not going to wait for
        # the far side to post it's status.
        if not test.remote_endpoint.posts_endpoint_status:
            validation_proc = ValidateRemoteTestProcess(
                                                         test=test,
                                                         coordinator_address=self.server_address,
                                                         coordinator_port=self.server_port,
                                                         auth_key=self.auth_key
                                                       )
            validation_proc.start()

        return

    @lock_test
    def server_confirm_test(self, requesting_address=None, test_id=None):
        # 1. If the server status is already confirmed, goto #4
        # 2. Mark the server status as "server-confirmed"
        # 3. Spawn a process to exec the tool at the specified time
        #    - Fail the test if the process can't be spawned
        # 4. Return a server-confirm-response message
        test = self.tests_db.get_test(test_id)
        if not test:
            raise ResourceNotFoundException("Test not found")

        if test.status == "remote-confirmed":
            self.spawn_tool_runner(requesting_address=requesting_address, test_id=test_id) 
        else:
            test.change_state("server-confirmed")

            self.tests_db.replace_test(test_id, test)

        return

    @lock_test
    def remote_confirm_test(self, requesting_address=None, test_id=None, test=None):
	# XXX: We should really require that the requesting address either be
	# the remote endpoint, or that

        # 1. If the server status is already confirmed, goto #4
        # 2. Mark the server status as "server-confirmed"
        # 3. Spawn a process to exec the tool at the specified time
        #    - Fail the test if the process can't be spawned
        # 4. Return a server-confirm-response message
        test = self.tests_db.get_test(test_id)
        if not test:
            raise ResourceNotFoundException("Test not found")

        if not ip_matches(test.remote_endpoint.address, requesting_address):
            raise TestInvalidActionException("Not permitted to confirm test: %s != %s" % (test.remote_endpoint.address, requesting_address))

        if test.status == "server-confirmed":
            self.spawn_tool_runner(requesting_address=requesting_address, test_id=test_id) 
        else:
            test.change_state("remote-confirmed")

            self.tests_db.replace_test(test_id, test)

        # If the far side is posting it's status, verify the test parameters
        # here.
        if test.remote_endpoint.posts_endpoint_status:
            self.server_confirm_test(test_id=test_id)

        return

    @lock_test
    def spawn_tool_runner(self, requesting_address=None, test_id=None):
        test = self.tests_db.get_test(test_id)
        if not test:
            raise ResourceNotFoundException("Test not found")

        test.change_state("pending")

        self.tests_db.replace_test(test_id, test)

        # The ToolRunner callback happens in a separate process so we need to
        # use the coordinator to respond.
        def handle_results_cb(results):
            coordinator_client = CoordinatorClient(server_address=self.server_address,
                                                   server_port=self.server_port,
                                                   auth_key=self.auth_key)

            coordinator_client.finish_test(test_id, results)

        tool_runner_proc = ToolRunner(test=test, results_cb=handle_results_cb)

        tool_runner_proc.start()

        self.test_processes[test.id] = tool_runner_proc

        return

    @lock_test
    def cancel_test(self, requesting_address=None, test_id=None, results=None):
        if not results:
            results = Results(status="cancelled")

        if not ip_matches(test.client.address, requesting_address) and \
           not ip_matches(test.remote_endpoint.address, requesting_address):
            raise TestInvalidActionException("Not permitted to cancel test")

        return self.finish_test(requesting_address=None, test_id=test_id, results=results, status="cancelled")

    @lock_test
    def finish_test(self, requesting_address=None, status=None, test_id=None, results=None):
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

        if requesting_address and \
            ip_matches(test.client.address, requesting_address) and \
            ip_matches(test.remote_endpoint.address, requesting_address):
            raise TestInvalidActionException("Not permitted to finish test")

        if test.finished:
           raise TestAlreadyFinishedException

        if not status:
            status = results.status

        test.change_state(status)

	# Add the results to the database, and update the test status to
	# "finished"
        self.tests_db.add_results(test_id, results)

        self.tests_db.replace_test(test_id, test)

        # Remove the test from the scheduler
        self.scheduler.remove_test(test)

        if not test.local_client and test.local_endpoint.test_port:
            test.tool_obj.port_range.release_port(test.local_endpoint.test_port)

        # Kill off the test process if it's still around
        if test.id in self.test_processes:
            try:
                self.test_processes[test.id].terminate()
            except:
                pass

            del(self.test_processes[test.id])

        return

class TestActionHandlerProcess(BwctlProcess):
    def __init__(self, test=None, coordinator_address=None,
                       coordinator_port=None, auth_key=None):

        coordinator_client = CoordinatorClient(server_address=coordinator_address,
                                               server_port=coordinator_port,
                                               auth_key=auth_key)

        self.coordinator_client = coordinator_client
        self.test               = test

        super(TestActionHandlerProcess, self).__init__()


    def run(self):
        err = None

        try:
            self.handler()
        except BwctlException as e:
            err = e
        except Exception as e:
            err = SystemProblemException(str(e))

        if err:
            self.handle_failure(err.as_bwctl_error())

    def handler(self):
        raise SystemProblemException("The handler function needs overwritten")

    def handle_failure(self, err):
        results = Results(
                      status = "failed",
                      bwctl_errors = [ err ],
                  )

        self.coordinator_client.finish_test(test_id=self.test.id, results=results)

class ValidateRemoteTestProcess(TestActionHandlerProcess):
    def handler(self):
        # XXX: actually validate the test
        client_url = "http://[%s]:%d%s" % (self.test.remote_endpoint.address, \
                                          self.test.remote_endpoint.peer_port, \
                                          self.test.remote_endpoint.base_path)

        client = Client(client_url, source_address=self.test.local_endpoint.address)

        try:
	    # Wait until the far side has confirmed the test (i.e. the client
	    # can't make changes to it)
            while datetime.datetime.utcnow() < self.test.scheduling_parameters.reservation_start_time:
                remote_test = client.get_test(self.test.remote_endpoint.test_id)

                if remote_test.status == "client-confirmed" or \
                   remote_test.status == "server-confirmed":
                    break

                # Wait before retrying
                time.sleep(0.2)

            # Make sure we didn't timeout waiting for the test to start
            if datetime.datetime.utcnow() > self.test.scheduling_parameters.reservation_start_time:
                raise TestStartTimeFailure

            # Confirm the test locally
            self.coordinator_client.server_confirm_test(self.test.id)

            # Confirm the test with the remote endpoint if needed
            client.remote_accept_test(self.test.remote_endpoint.test_id, self.test)

            # If we're posting our status, we're not going to get the
            # remote_accept from the side to alert us, so we'll need to confirm
            # it ourselves. It'd probably be good to wait for it 
            if self.test.local_endpoint.posts_endpoint_status:
                remote_test = None

                # Wait until the far side has confirmed the final state of
                # the test
                while datetime.datetime.utcnow() < self.test.scheduling_parameters.reservation_start_time:
                    remote_test = client.get_test(self.test.remote_endpoint.test_id)

                    if remote_test.status == "pending":
                        break

                # Wait before retrying
                time.sleep(0.2)

                # Make sure we didn't timeout waiting for the test to start
                if datetime.datetime.utcnow() > self.test.scheduling_parameters.reservation_start_time:
                    raise TestStartTimeFailure

                self.coordinator_client.remote_confirm_test(self.test.id, remote_test, \
                                                            requesting_address=self.test.remote_endpoint.address)
        except:
            raise TestRemoteEndpointValidationFailure

        return

def validate_test(test=None):
    if not test.sender_endpoint.local and not test.receiver_endpoint.local:
        raise ValidationException("No local endpoints for this test")

    if test.sender_endpoint.local and test.receiver_endpoint.local:
        raise ValidationException("Both endpoints can't be local")

    if test.sender_endpoint.posts_endpoint_status and \
       test.receiver_endpoint.posts_endpoint_status:
        raise ValidationException("Both endpoints can't post their status")

    # Make sure that it's a known tool, and that the tool parameters are all
    # valid.
    try:
        tool_obj = test.tool_obj

        tool_obj.validate_test(test)
    except InvalidToolException:
        raise ValidationException("Unknown tool type: %s" % test.tool)

def validate_endpoint(endpoint=None):
    try:
        ip = IP(endpoint.address)
    except:
        raise ValidationException("Invalid address for endpoint")

    if endpoint.local and endpoint.legacy_client_endpoint:
        raise ValidationException("Local endpoint isn't a legacy client")

def validate_test_changes(new_test=None, old_test=None):
    if old_test.id != new_test.id:
        raise ValidationException("Can't change the test id")

    if old_test.scheduling_parameters.test_start_time != new_test.scheduling_parameters.test_start_time or \
       old_test.scheduling_parameters.reservation_start_time != new_test.scheduling_parameters.reservation_start_time or \
       old_test.scheduling_parameters.reservation_end_time != new_test.scheduling_parameters.reservation_end_time:
        raise ValidationException("Can't change the scheduling parameters")

    validate_endpoint_changes(new_endpoint=new_test.sender_endpoint,
                              old_endpoint=old_test.sender_endpoint)

    validate_endpoint_changes(new_endpoint=new_test.receiver_endpoint,
                              old_endpoint=old_test.receiver_endpoint)

def validate_endpoint_changes(new_endpoint=None, old_endpoint=None):
    if new_endpoint.local and not old_endpoint.local:
        raise ValidationException("Can't change which endpoint is local")

    if new_endpoint.local and \
       new_endpoint.test_port != old_endpoint.test_port:
        raise ValidationException("Can't change the local test port")
