import multiprocessing
import zmq
import sys
import time

from bwctl import jsonobject
from bwctl.models import Test, BWCTLError, Results
from bwctl.utils import BwctlProcess
from bwctl.exceptions import *

class GenericRequestMessage(jsonobject.JsonObject):
    requesting_address = jsonobject.StringProperty()
    test_id = jsonobject.StringProperty(required=False)
    value   = jsonobject.ObjectProperty(jsonobject.JsonObject, required=False)

class GenericResponseMessage(jsonobject.JsonObject):
    status  = jsonobject.ObjectProperty(BWCTLError, required=True)
    value   = jsonobject.ObjectProperty(jsonobject.JsonObject, required=False)

class TestRequestMessage(GenericRequestMessage):
    value   = jsonobject.ObjectProperty(Test, required=True)

class TestResponseMessage(GenericResponseMessage):
    value   = jsonobject.ObjectProperty(Test, required=False)

class ResultsRequestMessage(GenericRequestMessage):
    value   = jsonobject.ObjectProperty(Results, required=True)

class ResultsResponseMessage(GenericResponseMessage):
    value   = jsonobject.ObjectProperty(Results, required=False)

message_types = {
    "get-test": GenericRequestMessage,
    "get-test-response": TestResponseMessage,
    "get-test-results": GenericRequestMessage,
    "get-test-results-response": ResultsResponseMessage,
    "client-confirm-test": GenericRequestMessage,
    "client-confirm-test-response": GenericResponseMessage,
    "server-confirm-test": GenericRequestMessage,
    "server-confirm-test-response": GenericResponseMessage,
    "request-test": TestRequestMessage,
    "request-test-response": TestResponseMessage,
    "finish-test": ResultsRequestMessage,
    "finish-test-response": GenericResponseMessage,
}

class CoordinatorClient:
    def __init__(self, server_address="127.0.0.1", server_port=5678, auth_key=""):
        self.server_address = server_address
        self.server_port = server_port
        self.auth_key = auth_key
        self.connected = False

    def connect(self):
        self.context = zmq.Context()
        self.sock = self.context.socket(zmq.REQ)

        self.sock.connect("tcp://[%s]:%d" % (self.server_address, self.server_port))

        self.connected = True

    def get_test(self, test_id, requesting_address=None):
        return self._send_msg(test_id=test_id, message_type="get-test", requesting_address=requesting_address)

    def get_test_results(self, test_id, requesting_address=None):
        return self._send_msg(test_id=test_id, message_type="get-test-results", requesting_address=requesting_address)

    def request_test(self, test, requesting_address=None):
        return self._send_msg(value=test, message_type="request-test", requesting_address=requesting_address)

    def update_test(self, test, test_id=None, requesting_address=None):
        return self._send_msg(value=test, message_type="update-test", test_id=test_id, requesting_address=requesting_address)

    def client_confirm_test(self, test_id, requesting_address=None):
        return self._send_msg(test_id=test_id, message_type="client-confirm-test", requesting_address=requesting_address)

    def server_confirm_test(self, test_id, requesting_address=None):
        return self._send_msg(test_id=test_id, message_type="server-confirm-test", requesting_address=requesting_address)

    def cancel_test(self, test_id, requesting_address=None):
        value = Results()
        return self._send_msg(test_id=test_id, value=value, message_type="finish-test", requesting_address=requesting_address)

    def finish_test(self, test_id, results, requesting_address=None):
        return self._send_msg(test_id=test_id, value=results, message_type="finish-test", requesting_address=requesting_address)

    def _send_msg(self, message_type="", test_id=None, value=None, requesting_address=None):
        if not self.connected:
            self.connect()

        if not message_type in message_types:
            raise Exception("Invalid message type specified")

        msg = message_types[message_type](test_id=test_id, value=value, requesting_address=requesting_address)

        coord_req = unparse_coordinator_msg(msg, message_type, self.auth_key)
        print "Unparsed request: %s" % coord_req
        self.sock.send_json(coord_req)
        coord_resp = self.sock.recv_json()
        print "Unparsed response: %s" % coord_resp
        msg_type, resp_msg = parse_coordinator_msg(coord_resp, self.auth_key)

        if msg_type == "" or resp_msg == None:
            raise SystemProblemException("Invalid response received from coordinator")

        BwctlException.from_bwctl_error(resp_msg.status).raise_if_error()

        return resp_msg.value

def parse_coordinator_msg(json, auth_key):
    msg = None
    msg_type = ""
    try:
        if json['auth_key'] != auth_key:
            raise SystemProblemException("Invalid coordinator authentication key")

        if not 'message_type' in json:
            raise SystemProblemException("No message type in coordinator message")

        if not 'message' in json:
            raise SystemProblemException("No coordinator message available")

        if not json['message_type'] in message_types.keys():
            raise SystemProblemException("Unknown coordinator message type")

        msg_type = json['message_type']
        msg = message_types[json['message_type']](json['message'])
    except Exception as e:
        #print "json.auth_key: %s/self.auth_key: %s -- %s" % (json['auth_key'], auth_key, e)
        print "json.auth_key: %s/self.auth_key: %s -- %s" % (json, auth_key, e)
        msg = None

    print "Message: %s" % msg
    if msg:
        print "Message(json): %s" % msg.to_json()

    return msg_type, msg

def unparse_coordinator_msg(message, message_type, auth_key):
    if not message_type in message_types.keys():
        raise Exception("Unknown message type")

    return {
        'auth_key': auth_key,
        'message_type': message_type,
        'message': message.to_json()
    }

class CoordinatorServer(BwctlProcess):
    def __init__(self, server_address="127.0.0.1", server_port=5678, auth_key=""):
        self.server_address = server_address
        self.server_port = server_port
        self.auth_key = auth_key

        self.sock = None
        self.context = None

        super(CoordinatorServer, self).__init__()

    def setup_listener(self):
        self.context = zmq.Context()
        self.sock = self.context.socket(zmq.REP)

        self.sock.bind("tcp://[%s]:%d" % (self.server_address, self.server_port))

    def main_loop(self):
        while True:
            type, msg = self.get_msg()
            self.handle_msg(type, msg)

    def get_msg(self):
        coord_msg = self.sock.recv_json()
        return parse_coordinator_msg(coord_msg, self.auth_key)

    def run(self):
        self.setup_listener()
        self.main_loop()

    def handle_msg(self, msg_type, msg):
        status = None
        value  = None

        try:
            if msg_type == 'get-test':
                value = self.handle_get_test(requesting_address=msg.requesting_address, test_id=msg.test_id)
            elif msg_type == 'get-test-results':
                value = self.handle_get_test_results(requesting_address=msg.requesting_address, test_id=msg.test_id)
            elif msg_type == 'request-test' and msg.test_id:
                value = self.handle_update_test(requesting_address=msg.requesting_address, test_id=msg.test_id, test=msg.value)
            elif msg_type == 'request-test':
                value = self.handle_request_test(requesting_address=msg.requesting_address, test=msg.value)
            elif msg_type == 'client-confirm-test':
                self.handle_client_confirm_test(requesting_address=msg.requesting_address, test_id=msg.test_id)
            elif msg_type == 'server-confirm-test':
                self.handle_server_confirm_test(requesting_address=msg.requesting_address, test_id=msg.test_id)
            elif msg_type == 'finish-test':
                self.handle_finish_test(requesting_address=msg.requesting_address, test_id=msg.test_id, results=msg.value)
            else:
                raise SystemProblemException("Unknown message type: %s" % msg_type)
        except BwctlException as e:
            status = e
            value  = None
        except Exception as e:
            status = SystemProblemException(str(e))
            value  = None

        if not status:
            status = Success()

        response_msg_type = "%s-response" % msg_type
        if not response_msg_type in message_types:
            response_msg = GenericResponseMessage(status=status.as_bwctl_error(), value=value)
        else:
            response_msg = message_types[response_msg_type](status=status.as_bwctl_error(), value=value)

        try:
            coord_resp = unparse_coordinator_msg(response_msg, response_msg_type, self.auth_key)
            self.sock.send_json(coord_resp)
        except:
            # XXX: log an error here
            pass

        return


