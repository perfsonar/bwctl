import datetime
import socket
import threading
import time

from bwctl.ntp import ntp_adjtime
from bwctl.utils import BwctlProcess, get_logger, timedelta_seconds
from bwctl.protocol.legacy.client import ControlConnection
from bwctl.protocol.legacy.models import MessageTypes, Tools, Modes, AcceptType, TestRequest

from bwctl.protocol.legacy.utils import gen_sid, datetime_to_bwctl_epoch_time

from bwctl.tools import get_available_tools

class LegacyServer(BwctlProcess):
    def __init__(self, server_address="", server_port=0):
        self.server_address = server_address
        self.server_port = server_port
        self.logger = get_logger()

        self.sock = None

        super(LegacyServer, self).__init__()

    def run(self):
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(( self.server_address, self.server_port ))

        self.sock.listen(20)

        try:
            while True:
                sock = None

                try:
                    sock, addr = self.sock.accept()
                    self.logger.debug("Connection from [%s]:%s" % (addr[0], str(addr[1])))
    
                    conn = ControlConnection(socket=sock)
    
                    handler = self.handler_class(control_connection=conn, server=self)
                    handler.start()
                except Exception as e:
                    logger.error("Problem handling connection: %s" % e)
                #finally:
                    #if sock:
                    #    sock.close()
        finally:
            self.sock.close()


class LegacyEndpointServer(LegacyServer):
    def __init__(self, server_address="", server_port=6001):
        self.handler_class = LegacyEndpointHandler

        super(LegacyEndpointServer, self).__init__(server_address=server_address, server_port=server_port)

class LegacyBWCTLServer(LegacyServer):
    def __init__(self, server_address="", server_port=4823, coordinator=None):
        self.handler_class = LegacyBWCTLHandler
        self.coordinator = coordinator

        super(LegacyBWCTLServer, self).__init__(server_address=server_address, server_port=server_port)

class LegacyEndpointHandler(threading.Thread):
    def __init__(self, control_connection=None, server=None):
        self.control_connection = control_connection
        self.logger = get_logger()

        super(LegacyEndpointHandler, self).__init__()

    def run(self):
        try:
            # The server greeting doesn't much matter so we just leave it with
            # defaults.
            self.control_connection.send_server_greeting()

            # We don't care about the client greeting either
            client_greeting = self.control_connection.get_client_greeting()

            self.control_connection.send_server_ok()

            while True:
                msg_type, msg, results = self.control_connection.get_msg(deadline=datetime.datetime.now() + datetime.timedelta(minutes=10)) # XXX: handle this better
                if msg_type == MessageTypes.TimeRequest:
                    self.handle_time_request(msg)
                elif msg_type == MessageTypes.StopSession:
                    self.handle_stop_session(msg, results)
                    break
                else:
                    raise Exception("Invalid request received: %d", msg_type)
        #except Exception as e:
        #    self.logger.error(str(e))
        finally:
            self.control_connection.close()

    def handle_time_request(self, time_request):
        synchronized = False
        error = 0.1
        time = datetime.datetime.utcnow()

        s_time = datetime.datetime.now()
        timex = ntp_adjtime()
        e_time = datetime.datetime.now()

        if timex:
            time = time + datetime.timedelta(seconds=timex.offset_sec)
            error = timex.maxerror_sec
            synchronized = timex.synchronized

            # XXX: hack because we kept getting "time is too far off" errors
            # that I think had to do with it taking longer for python to answer
            # the query than the C server.
            if error < 1.0:
                error = 1.0

	# We need to tack on the time to run ntp_adjtime since it can take an
	# inordinate amount of time on some hosts, and bwctl 1.x expects it to
	# run in a negligible amount of time.
        error = error + timedelta_seconds(e_time - s_time)

        self.logger.debug("Received TimeRequest, sending TimeResponse")
        self.control_connection.send_time_response(timestamp=time, time_error=error, synchronized=synchronized)

        return
        
    def handle_stop_session(self, stop_session, results):
        # Send an empty set of results
        self.logger.debug("Received StopSession, sending StopSession response")
        self.control_connection.send_stop_session()

        return

class LegacyBWCTLHandler(threading.Thread):
    def __init__(self, control_connection=None, server=None):
        self.coordinator = server.coordinator
        self.control_connection = control_connection
        self.logger = get_logger()
        self.available_tools = []
        for tool in get_available_tools():
            tool_id = Tools.id_by_name(tool)
            if tool_id:
                self.available_tools.append(tool_id)

        self.peername = control_connection.peername()

        self.test = None
        self.test_sid = gen_sid()
        self.reservation_time = None
        self.reservation_end_time = None
        self.test_port = 0
        self.peer_port = 0

        super(LegacyBWCTLHandler, self).__init__()

    def run(self):
        try:
            # The server greeting doesn't much matter so we just leave it with
            # defaults.
            self.control_connection.send_server_greeting()

            # We don't care about the client greeting either
            client_greeting = self.control_connection.get_client_greeting()
            if not client_greeting.mode & Modes.OPEN:
                raise Exception("Only open mode supported")

            self.control_connection.send_server_ok(tools=self.available_tools)

            while True:
                msg_type, msg, results = self.control_connection.get_msg()
                if msg_type == MessageTypes.TimeRequest:
                    self.logger.debug("TimeRequest from legacy connection: %s" % self.peername)
                    self.control_connection.send_time_response()
                elif msg_type == MessageTypes.TestRequest:
                    accept_type = None

                    try:
                        # TestRequest's can be one of three different things:
                        #  - Request a new test
                        #  - Update an existing test (if an existing test has been requested)
                        #  - Cancel a test (if the requested time is zero)
                        if msg.requested_time.time == None:
                            self.logger.debug("Cancel TestRequest from connection: %s" % self.peername)
                            self.cancel_test()
                            accept_type = AcceptType.REJECT
                        elif self.test:
                            self.logger.debug("Update TestRequest from connection: %s" % self.peername)
                            accept_type = self.update_test(msg)
                        else:
                            self.logger.debug("New TestRequest from connection: %s" % self.peername)
                            accept_type = self.new_test(msg)
                    except Exception as e:
                        self.logger.debug("Failure while TestRequest test: %s: %s" % (self.peername, e))
                        accept_type = AcceptType.FAILURE

                    self.control_connection.send_test_accept(accept_type=accept_type,
                                                             data_port=self.test_port,
                                                             sid=self.test_sid,
                                                             reservation_time=self.reservation_time)

                    if accept_type != AcceptType.ACCEPT:
                        break
                elif msg_type == MessageTypes.StartSession:
                    self.logger.debug("StartSession from connection: %s" % self.peername)
                    try:
                        accept_type = self.accept_test(msg)
                    except Exception as e:
                        self.logger.debug("Failure while accepting test: %s: %s" % (self.peername, e))
                        accept_type = AcceptType.FAILURE

                    peer_port = 0
                    if self.test.remote_endpoint.legacy_client_endpoint:
                        peer_port = 6001 # XXX: 

                    self.control_connection.send_start_ack(accept_type=accept_type,
                                                           peer_port=peer_port)

                    if accept_type != AcceptType.ACCEPT:
                        break
                elif msg_type == MessageTypes.StopSession:
                    self.logger.debug("StopSession from connection: %s" % self.peername)
                    results = ""
                    try:
                        results = self.finish_test(msg)
                        accept_type = AcceptType.ACCEPT
                    except Exception as e:
                        self.logger.debug("Failure while finishing test: %s: %s" % (self.peername, e))
                        accept_type = AcceptType.FAILURE

                    retval = self.control_connection.send_stop_session(result_status=accept_type,
                                                                       results=results)
                    break
                else:
                    self.logger.debug("Invalid message from %s" % self.peername)
                    raise Exception("Invalid request received: %d", msg_type)
        #except Exception as e:
        #    self.logger.error("Exception handling legacy client %s: %s" % (self.peername, str(e)))
        finally:
            self.control_connection.close()

    def new_test(self, test_request):
        test = test_request.to_internal()

        # XXX: Should probably handle this elsewhere...
        timex = ntp_adjtime()
        if timex:
            test.local_endpoint.ntp_error = timex.maxerror_sec

        self.logger.debug("Requesting new test for %s" % self.test_sid)

        added_test = self.coordinator.request_test(test=test, requesting_address=self.peername)

        if added_test.status == "rejected":
            self.logger.debug("Requested test was rejected for %s" % self.test_sid)
            return AcceptType.REJECTED
        elif added_test.status != "scheduled":
            self.logger.debug("Requested test wasn't in state 'scheduled' for %s" % self.test_sid)
            return AcceptType.FAILURE

        self.test = added_test
        self.reservation_time = added_test.scheduling_parameters.test_start_time
        self.reservation_end_time = added_test.scheduling_parameters.reservation_end_time
        if added_test.local_endpoint.test_port:
            self.test_port = added_test.local_endpoint.test_port

        if added_test.remote_endpoint.peer_port:
            self.peer_port = added_test.local_endpoint.peer_port

        self.logger.debug("Requested test was accepted for %s" % self.peername)

        return AcceptType.ACCEPT

    def update_test(self, test_request):
        self.logger.debug("Updating new test for %s" % self.peername)

        # XXX: this check needs done
        #if not test_request.sid == self.test_sid:
        #    print "SID: %s" % test_request.sid
        #    print "Old SID: %s" % self.test_sid
        #    raise ValidationException("Invalid test update: SID doesn't match")

	# XXX: we should do something more than this, but bwctl client only
	# updates the times.

        self.test.scheduling_parameters.requested_time = test_request.requested_time.time
        self.test.scheduling_parameters.latest_acceptable_time = test_request.latest_time.time

        updated_test = self.coordinator.update_test(test=self.test, test_id=self.test.id,
                                                    requesting_address=self.peername)

        if updated_test.status == "rejected":
            self.logger.debug("Updated test was rejected for %s" % self.peername)
            return AcceptType.REJECTED
        elif updated_test.status != "scheduled":
            self.logger.debug("Updated test wasn't in state 'scheduled' for %s" % self.peername)
            return AcceptType.FAILURE

        self.test = updated_test
        self.reservation_time = updated_test.scheduling_parameters.test_start_time
        self.reservation_end_time = updated_test.scheduling_parameters.reservation_end_time
        if updated_test.local_endpoint.test_port:
            self.test_port = updated_test.local_endpoint.test_port

        return AcceptType.ACCEPT

    def accept_test(self, msg):
        self.logger.debug("Accepting test for %s" % self.peername)

        # 1. Do a "client accept" for the test we've requested
        # 2. Busy-wait until the test is 'pending', 'failed' or what-have-you
        # 3. If 'pending', send a StartAck response containing the
        #     local peer port.
        # 4. If 'failed' or 'other' send a StartAck response, and exit.

	# If we're passed a port, we need to update the test in the coordinator
	# to account for the peer port we've been given.
        if msg.peer_port:
            self.logger.debug("Updating remote peer port on test for %s" % self.peername)
            self.test.remote_endpoint.peer_port = msg.peer_port

            updated_test = self.coordinator.update_test(test=self.test, test_id=self.test.id,
                                                        requesting_address=self.peername)

            if updated_test.scheduling_parameters.test_start_time != self.reservation_time:
                raise Exception("The scheduling parameters changed after the client has accepted the time")

            self.test = updated_test

        self.logger.debug("Doing client confirm for %s" % self.peername)
        self.coordinator.client_confirm_test(test_id=self.test.id, requesting_address=self.peername)

        # XXX: We should be doing endpoint handling directly, but we can ignore that for now
        if not self.test.local_endpoint.legacy_client_endpoint:
            self.logger.debug("Doing server confirm for %s since we're not a legacy client" % self.peername)
            self.coordinator.server_confirm_test(test_id=self.test.id)

            self.logger.debug("Doing remote confirm for %s since it's a legacy client" % self.peername)
            self.coordinator.remote_confirm_test(test_id=self.test.id, test=self.test)

        self.logger.debug("Waiting for test to go pending for %s" % self.peername)

        # Wait until the test goes to pending (or otherwise finishes)
        while datetime.datetime.utcnow() < self.reservation_time:
            test = self.coordinator.get_test(test_id=self.test.id)

            if test.status == "pending" or test.finished:
                break

            # Wait before retrying
            time.sleep(0.2)

        if test.status != "pending":
            self.logger.debug("Test never went to pending for %s: status: %s" % (self.peername, test.status))
            self.coordinator.get_test_results(test_id=self.test.id)
            raise Exception("The test didn't go to pending")

        self.logger.debug("Test accepted, and went pending for %s" % self.peername)

        return AcceptType.ACCEPT

    def finish_test(self, msg):
        self.logger.debug("Finishing test for %s" % self.peername)

        # Wait a few seconds past the end
        end_time = self.reservation_end_time + datetime.timedelta(seconds=3)

        self.logger.debug("Waiting for test to finish for %s" % self.peername)

        while datetime.datetime.utcnow() < end_time:
            test = self.coordinator.get_test(test_id=self.test.id)

            if test.finished:
                break

            # Wait before retrying
            time.sleep(1.0)

        self.logger.debug("Grabbing test results for %s" % self.peername)
        results = self.coordinator.get_test_results(test_id=self.test.id)

        return self.convert_results(results)

    def cancel_test(self):
        self.logger.debug("Cancelling test for %s" % self.peername)

        self.coordinator.cancel_test(test_id=self.test.id, requesting_address=self.peername)

        return AcceptType.REJECTED

    def convert_results(self, results):
        results_str = ""

        if self.test.local_client:
            start_time = self.test.scheduling_parameters.test_start_time
        else:
            start_time = self.test.scheduling_parameters.reservation_start_time

        end_time = self.test.scheduling_parameters.reservation_end_time

        start_time = datetime_to_bwctl_epoch_time(start_time)
        end_time = datetime_to_bwctl_epoch_time(end_time)

        results_str = results_str + "bwctl: start_endpoint: %s\n" % start_time
        results_str = results_str + "bwctl: start_tool: %s\n" % start_time

        results_str = results_str + "bwctl: run_endpoint: sender: %s\n" % self.test.sender_endpoint.address
        results_str = results_str + "bwctl: run_endpoint: receiver: %s\n" % self.test.receiver_endpoint.address
        if results.results and "command_line" in results.results:
            results_str = results_str + "bwctl: exec_line: %s\n" % results.results["command_line"]
        results_str = results_str + "bwctl: run_tool: tester: %s\n" % self.test.tool
        results_str = results_str + "bwctl: run_tool: sender: %s\n" % self.test.sender_endpoint.address
        results_str = results_str + "bwctl: run_tool: receiver: %s\n" % self.test.receiver_endpoint.address

        if results.results and "output" in results.results:
            results_str = results_str + results.results["output"]

        if results.bwctl_errors:
            for error in results.bwctl_errors:
                results_str = results_str + "bwctl: error: %s" % error.error_msg

        results_str = results_str + "bwctl: stop_tool: %s\n" % end_time
        results_str = results_str + "bwctl: stop_endpoint: %s\n" % end_time

        #fprintf(tsess->localfp,"bwctl: stop_tool: %f\n",
        #fprintf(tsess->localfp,"bwctl: stop_endpoint: %f\n",
        return results_str
