from bwctl.utils import BwctlProcess, timedelta_seconds, ip_matches, get_logger
from bwctl.server.scheduler import Scheduler
from bwctl.tool_runner import ToolRunner
from bwctl.models import BWCTLError, Results
from bwctl.exceptions import *
from bwctl.protocol.v2.client import Client
from bwctl.protocol.legacy.client import Client as LegacyClient

import threading
import multiprocessing
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

class Coordinator(object):
    def __init__(self, scheduler=Scheduler(), limits_db=None, tests_db=None,
                 coordinator_client=None):
        self.scheduler = scheduler
        self.limits_db = limits_db
        self.tests_db  = tests_db
        self.test_procs = {}
        self.lock = threading.RLock()
        self.logger = get_logger()

        self.coordinator_client = coordinator_client

        super(Coordinator, self).__init__()

    def __add_test_process(self, test_id=None, process=None):
        with self.lock:
            self.test_procs[test_id] = process 

        return

    @lock_test
    def get_test(self, requesting_address=None, user=None, test_id=None):
        return self.tests_db.get_test(test_id)

    @lock_test
    def get_test_results(self, requesting_address=None, user=None, test_id=None):
        return self.tests_db.get_results(test_id)

    def request_test(self, requesting_address=None, user=None, test=None):
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
    def update_test(self, requesting_address=None, user=None, test_id=None, test=None):
        old_test = self.tests_db.get_test(test_id)
        if not old_test:
            raise ResourceNotFoundException("Test not found")

        if not old_test.client_can_modify:
            raise TestInvalidActionException("Test can not be modified")

        if requesting_address and \
           not ip_matches(old_test.client.address, requesting_address):
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
    def client_confirm_test(self, requesting_address=None, user=None, test_id=None):
        # 1. If the test's status is already confirmed, goto #4
        # 2. Mark the test's status as "client-confirmed"
        # 3. Spawn a process to validate the test with the other side
        #    - Fail the test if the process can't be spawned
        # 4. Return a client-confirm-response message
        test = self.tests_db.get_test(test_id)
        if not test:
            raise ResourceNotFoundException("Test not found")

        if requesting_address and \
           not ip_matches(test.client.address, requesting_address):
            raise TestInvalidActionException("Not permitted to confirm test")

        if not test.status == "scheduled":
            raise TestInvalidActionException

        # XXX: we should check if we're past the test's start time, and fail if so.

        test.change_state("client-confirmed")

        self.tests_db.replace_test(test_id, test)

        # If we're not a legacy endpoint, but the remote is, we'll need to
        # handle either the endpoint client handling, or we'll need to confirm
        # the test locally since the far side can't. If we are a legacy
        # endpoint, the legacy server module will handle the server/remote
        # confirmation.
        if not test.remote_endpoint.bwctl_protocol:
            # XXX: we need to validate that this is ok earlier
            # Handle the confirmation since the far side can't
            self.remote_confirm_test(test_id=test_id, test=test)

            self.server_confirm_test(test_id=test_id)
        elif test.remote_endpoint.bwctl_protocol == 1.0:
            if not test.remote_endpoint.legacy_client_endpoint:
                ep_client_process = LegacyEndpointClientHandlerProcess(
                                                                     test_id=test_id,
                                                                     coordinator=self.coordinator_client,
                                                                   )

                self.__add_test_process(test_id=test_id, process=ep_client_process)

                ep_client_process.start()
            elif test.local_endpoint.bwctl_protocol == 2.0: 
                # XXX: handle the confirmation since the far side can't, and
                # it's not a legacy connection so the legacy server won't
                self.remote_confirm_test(test_id=test_id, test=test)

                self.server_confirm_test(test_id=test_id)
        elif test.remote_endpoint.bwctl_protocol == 2.0 \
             and not test.remote_endpoint.posts_endpoint_status:
            validation_process = ValidateRemoteTestProcess(
                                                         test_id=test_id,
                                                         coordinator=self.coordinator_client,
                                                       )

            self.__add_test_process(test_id=test_id, process=validation_process)

            validation_process.start()

        return

    @lock_test
    def server_confirm_test(self, requesting_address=None, user=None, test_id=None):
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
    def remote_confirm_test(self, requesting_address=None, user=None, test_id=None, test=None):
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

        if requesting_address and \
           not ip_matches(test.remote_endpoint.address, requesting_address):
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
    def spawn_tool_runner(self, requesting_address=None, user=None, test_id=None):
        test = self.tests_db.get_test(test_id)
        if not test:
            raise ResourceNotFoundException("Test not found")

        test.change_state("pending")

        self.tests_db.replace_test(test_id, test)

        spawning_process = ToolHandlerProcess(
                                               test_id=test_id,
                                               coordinator=self.coordinator_client,
                                           )

        self.__add_test_process(test_id=test_id, process=spawning_process)

        spawning_process.start()

    @lock_test
    def cancel_test(self, requesting_address=None, user=None, test_id=None, results=None):
        test = self.tests_db.get_test(test_id)
        if not test:
            raise ResourceNotFoundException("Test not found")

        if not results:
            results = Results(status="cancelled")

        if requesting_address and \
           not ip_matches(test.client.address, requesting_address) and \
           not ip_matches(test.remote_endpoint.address, requesting_address):
            raise TestInvalidActionException("Not permitted to cancel test")

        return self.finish_test(requesting_address=None, user=None, test_id=test_id, results=results, status="cancelled")

    @lock_test
    def finish_test(self, requesting_address=None, user=None, status=None, test_id=None, results=None):
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

        # Stop the test processes if they're still doing their thing
        with self.lock:
            if test.id in self.test_procs:
                try:
                    self.test_procs[test.id].terminate()
                except:
                    pass

                del(self.test_procs[test.id])

        return

class TestActionHandlerProcess(BwctlProcess):
    def __init__(self, coordinator=None, test_id=None):
        super(TestActionHandlerProcess, self).__init__()

        self.coordinator = coordinator
        self.test_id     = test_id
        self.logger = get_logger()

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
 
        self.coordinator.finish_test(test_id=self.test_id, results=results)
 
class ToolHandlerProcess(TestActionHandlerProcess):
    def __init__(self, coordinator=None, test_id=None):
        self.results_queue = multiprocessing.Queue() # Needs to be multiprocess for the ToolRunner

        super(ToolHandlerProcess, self).__init__(coordinator=coordinator, test_id=test_id)

    def handler(self):
        test = self.coordinator.get_test(test_id=self.test_id)

        def results_cb(results):
            self.results_queue.put(results.to_json())

        tool_runner = ToolRunner(test=test, results_cb=results_cb)
        tool_runner.start()

        results = self.results_queue.get()

        tool_runner.terminate()

        parsed_results = Results(results)

        self.coordinator.finish_test(test_id=self.test_id, results=parsed_results)

        return

class LegacyEndpointClientHandlerProcess(TestActionHandlerProcess):
    def handler(self):
        client = None

        test = self.coordinator.get_test(test_id=self.test_id)

        # XXX: connect to the endpoint, and verify we're not too far off.
        try:
            # XXX: actually validate the test
            client = LegacyClient(source_address=test.local_endpoint.address,
                                  server_address=test.remote_endpoint.address,
                                  server_port=test.remote_endpoint.peer_port)

            client.connect()

            server_greeting = client.get_server_greeting()

            server_ok = client.send_client_greeting()

            # Confirm the test locally
            self.coordinator.server_confirm_test(test_id=test.id)

            self.coordinator.remote_confirm_test(test_id=test.id, test=test)
        except:
            if client:
                client.close()
            raise TestRemoteEndpointValidationFailure

        try:
            # Wait a few seconds after the reservation finishes
            deadline = test.scheduling_parameters.reservation_end_time + datetime.timedelta(seconds=3)

            # Wait for a StopSession message from the far side
            while datetime.datetime.utcnow() < deadline:
                msg_type, msg, results = client.get_msg(deadline=deadline)
                if msg_type == MessageTypes.StopSession:
                    break

            # Send an empty stop session message since the far side is just
            # going to throw them away anyway
            client.send_stop_session()
        except:
            pass
        finally:
            client.close()

        return

class ValidateRemoteTestProcess(TestActionHandlerProcess):
    def handler(self):
        try:
            test = self.coordinator.get_test(test_id=self.test_id)

            # XXX: actually validate the test
            client_url = "http://[%s]:%d%s" % (test.remote_endpoint.address, \
                                               test.remote_endpoint.peer_port, \
                                               test.remote_endpoint.base_path)

            client = Client(client_url, source_address=test.local_endpoint.address)

            # Wait until the far side has confirmed the test (i.e. the client
            # can't make changes to it)
            while datetime.datetime.utcnow() < test.scheduling_parameters.reservation_start_time:
                remote_test = client.get_test(test.remote_endpoint.test_id)

                if remote_test.status == "client-confirmed" or \
                   remote_test.status == "server-confirmed":
                    break

                # Wait before retrying
                time.sleep(0.2)

            # Make sure we didn't timeout waiting for the test to start
            if datetime.datetime.utcnow() > test.scheduling_parameters.reservation_start_time:
                raise TestStartTimeFailure

            # Confirm the test locally
            self.coordinator.server_confirm_test(test_id=test.id)

            # Confirm the test with the remote endpoint if needed
            client.remote_accept_test(test.remote_endpoint.test_id, test)

            # If we're posting our status, we're not going to get the
            # remote_accept from the side to alert us, so we'll need to confirm
            # it ourselves. It'd probably be good to wait for it 
            if test.local_endpoint.posts_endpoint_status:
                remote_test = None

                # Wait until the far side has confirmed the final state of
                # the test
                while datetime.datetime.utcnow() < test.scheduling_parameters.reservation_start_time:
                    remote_test = client.get_test(test_id=test.remote_endpoint.test_id)

                    if remote_test.status == "pending":
                        break

                    # Wait before retrying
                    time.sleep(0.2)

                # Make sure we didn't timeout waiting for the test to start
                if datetime.datetime.utcnow() > test.scheduling_parameters.reservation_start_time:
                    raise TestStartTimeFailure

                self.coordinator.remote_confirm_test(test_id=test.id, test=remote_test, \
                                                        requesting_address=test.remote_endpoint.address)
        except:
            raise TestRemoteEndpointValidationFailure

        return

def validate_test(test=None):
    if not test.local_endpoint:
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

    if endpoint.local and endpoint.bwctl_protocol < 2.0:
        raise ValidationException("Invalid local protocol")

    if endpoint.local and endpoint.legacy_client_endpoint:
        raise ValidationException("Local endpoint isn't a legacy client")

    if endpoint.local and not is_loopback(endpoint.address):
        raise ValidationException("Local endpoint doesn't have a valid address for this host")

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
