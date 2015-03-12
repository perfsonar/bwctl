import socket
import datetime

from bwctl.utils import timedelta_seconds

from .models import *

class ControlConnection(object):
    def __init__(self, socket=None):
        self.sock = socket

        self.peeked_data = ""

    def peername(self):
        return self.sock.getpeername()[0]

    def peek_sock(self, size, deadline=None):
        data = self.read_sock(size, deadline=deadline)
        self.peeked_data = data
        return self.peeked_data

    def read_sock(self, size, deadline=None):
        timeout = None
        if deadline:
            timeout = timedelta_seconds(deadline - datetime.datetime.now())

        self.sock.settimeout(timeout)

        data = ""

        if len(self.peeked_data) > size:
            data = self.peeked_data[0:size-1]
            self.peeked_data = self.peeked_data[size:]
        elif len(self.peeked_data) > 0:
            data = self.peeked_data
            self.peeked_data = ""

        while len(data) < size:
            new_data = self.sock.recv(size - len(data))
            if not new_data:
                raise Exception("Connection closed")

            data = data + new_data

        return data

    def get_obj(self, type=None, size=0, deadline=None):
        data = self.read_sock(size, deadline=deadline)
        return type.parse(data)

    def get_msg(self, deadline=None):
        msg = None
        results = None
        msg_type = MessageType.parse(self.peek_sock(1, deadline=deadline))

        if msg_type.message_type == MessageTypes.TestRequest:
            msg = self.get_test_request(deadline=deadline)
        elif msg_type.message_type == MessageTypes.StartSession:
            msg = self.get_start_session(deadline=deadline)
        elif msg_type.message_type == MessageTypes.StopSession:
            msg, results = self.get_stop_session(deadline=deadline)
        elif msg_type.message_type == MessageTypes.TimeRequest:
            msg = self.get_time_request(deadline=deadline)
        else:
            raise Exception("Invalid message type: %d", msg_type.message_type)

        return msg_type.message_type, msg, results

    def send_server_greeting(self):
        server_greeting = ServerGreeting()

        self.send(server_greeting)

    def get_server_greeting(self, deadline=None):
        return self.get_obj(size=32, type=ServerGreeting, deadline=deadline)

    def send_client_greeting(self, deadline=None):
        client_greeting = ClientGreeting()

        self.send(client_greeting)

        return self.get_server_ok(deadline=deadline)

    def get_client_greeting(self, deadline=None):
        return self.get_obj(size=68, type=ClientGreeting, deadline=deadline)

    def send_server_ok(self, tools=[], uptime=0.0, accept_type=AcceptType.ACCEPT):
        server_ok = ServerOK(uptime=uptime, tools=tools, accept_type=accept_type)

        self.send(server_ok)

    def get_server_ok(self, deadline=None):
        return self.get_obj(size=48, type=ServerOK, deadline=deadline)

    def send_time_request(self, deadline=None):
        time_request = TimeRequest()

        self.send(time_request)

        return self.get_time_response(deadline=deadline)

    def get_time_request(self, deadline=None):
        return self.get_obj(size=32, type=TimeRequest, deadline=deadline)

    def send_time_response(self, timestamp=datetime.datetime.utcnow()):
        timestamp_obj = Timestamp(time=timestamp)
        error_estimate = ErrorEstimate() # use a default error estimate since we can't currently grab it.
        time_response = TimeResponse(timestamp=timestamp_obj, error_estimate=error_estimate)

        self.send(time_response)

    def get_time_response(self, deadline=None):
        return self.get_obj(size=32, type=TimeResponse, deadline=deadline)

    def get_test_request(self, deadline=None):
        return self.get_obj(size=128, type=TestRequest, deadline=deadline)

    def send_test_request(self, test_request, deadline=None):
        self.send(test_request)

        return self.get_test_accept(deadline=deadline)

    def send_test_accept(self, accept_type=AcceptType.ACCEPT, data_port=0, sid='', reservation_time=None, deadline=None):
        time_obj = Timestamp(time=reservation_time)

        test_accept = TestAccept(accept_type=accept_type, 
                                 data_port=data_port,
                                 sid=sid,
                                 reservation_time=time_obj)

        self.send(test_accept)

    def get_test_accept(self, deadline=None):
        return self.get_obj(size=32, type=TestAccept, deadline=deadline)

    def send_start_session(self, peer_port=0, deadline=None):
        start_session = StartSession(peer_port=peer_port)

        self.send(start_session)

        return self.get_start_ack(deadline=deadline)

    def get_start_session(self, deadline=None):
        return self.get_obj(size=32, type=StartSession, deadline=deadline)

    def get_start_ack(self, deadline=None):
        return self.get_obj(size=32, type=StartAck, deadline=deadline)

    def send_start_ack(self, accept_type=AcceptType.ACCEPT, peer_port=0):
        start_ack = StartAck(accept_type=accept_type, peer_port=peer_port)

        self.send(start_ack)

    def send_stop_session(self, result_status=AcceptType.ACCEPT, results=""):
        stop_session = StopSession(result_status=result_status, result_length=len(results))

        self.send(stop_session)

        if len(results) > 0:
            self.send(Results(results=results))

    def get_results(self, results_length=0, deadline=None):
        if results_length == 0:
            return Results(results="")
 
        total_size = Results.message_size(results_length=results_length)

        results = Results.parse(self.read_sock(total_size, deadline=deadline), results_length=results_length)

        return results

    def get_stop_session(self, deadline=None):
        stop_session_msg = StopSession.parse(self.read_sock(32, deadline=deadline))
        results = self.get_results(results_length=stop_session_msg.result_length, deadline=deadline)

        return stop_session_msg, results.results

    def send(self, object):
        return self.send_raw(object.unparse())

    def send_raw(self, str):
        return self.sock.sendall(str)

    def close(self):
        self.sock.close()
        self.connected = False

class Client(ControlConnection):
    def __init__(self, source_address=None, server_address=None, server_port=4823):
        self.source_address = source_address
        self.server_address = server_address
        self.server_port = server_port

        self.connected = False

        super(Client, self).__init__()

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.source_address:
            self.sock.bind(( self.source_address, 0 ))

        self.sock.connect((self.server_address, self.server_port))

        self.connected = True

    def send_raw(self, str):
        if not self.connected:
            raise Exception("Not connected")

        return super(Client, self).send_raw(str)

    def close(self):
        self.connected = False

        return super(Client, self).close()
