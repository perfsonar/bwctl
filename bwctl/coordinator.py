import multiprocessing
import zmq
import sys
import time

from bwctl import jsonobject
from bwctl.models import Test, BWCTLError, Results

class GenericRequestMessage(jsonobject.JsonObject):
    requesting_address = jsonobject.StringProperty()
    test_id = jsonobject.StringProperty(required=False)

class GenericResponseMessage(jsonobject.JsonObject):
    status  = jsonobject.ObjectProperty(BWCTLError, required=True)
    value   = jsonobject.ObjectProperty(jsonobject.JsonObject, required=False)

class TestRequestMessage(GenericRequestMessage):
    value   = jsonobject.ObjectProperty(Test, required=True)

class TestResponseMessage(GenericResponseMessage):
    value   = jsonobject.ObjectProperty(Test, required=True)

class ResultsRequestMessage(GenericRequestMessage):
    value   = jsonobject.ObjectProperty(Results, required=True)

class ResultsResponseMessage(GenericResponseMessage):
    value   = jsonobject.ObjectProperty(Results, required=True)

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

    def connect(self):
        self.context = zmq.Context()
        self.sock = self.context.socket(zmq.REQ)

        self.sock.connect("tcp://[%s]:%d" % (self.server_address, self.server_port))

    def _test_action_request(self, test_id="", message_type=""):
        msg = TestActionMessage(test_id=test_id)
        result = self._send_msg(msg, message_type=message_type)
        return { 'error_code': result.status.error_code, 'error_msg': result.status.error_msg }

    def get_test(self, test_id):
        return self._send_msg(test_id=test_id, message_type="get-test")

    def get_test_results(self, test_id):
        return self._send_msg(test_id=test_id, message_type="get-test-results")

    def request_test(self, test):
        return self._send_msg(value=test, message_type="get-test-results")

    def client_confirm_test(self, test_id):
        return self._send_msg(test_id=test_id, message_type="client-confirm-test")

    def server_confirm_test(self, test_id):
        return self._send_msg(test_id=test_id, message_type="server-confirm-test")

    def cancel_test(self, test_id):
        value = Results()
        return self._send_msg(test_id=test_id, value=value, message_type="finish-test")

    def finish_test(self, test_id, results):
        return self._send_msg(test_id=test_id, value=results, message_type="finish-test")

    def _send_msg(self, message_type="", test_id=None, value=None):
        if not message_type in message_types:
            raise Exception("Invalid message type specified")

        msg = message_types[message_type](test_id=test_id, value=value)

        coord_req = unparse_coordinator_msg(msg, message_type, self.auth_key)
        self.sock.send_json(coord_req)
        print "Waiting for %s message" % msg.test_id
        coord_resp = self.sock.recv_json()
        print "Got %s" % coord_resp
        msg_type, resp_msg = parse_coordinator_msg(coord_resp, self.auth_key)

        if msg_type == "" or resp_msg == None:
            raise Exception("Invalid response received from coordinator")

        return resp_msg.status, resp_msg.value

def parse_coordinator_msg(json, auth_key):
    msg = None
    msg_type = ""
    try:
        if json['auth_key'] != auth_key:
            raise Exception("Invalid authentication key")

        if not 'message_type' in json:
            raise Exception("No message type in message")

        if not 'message' in json:
            raise Exception("No message available")

        if not json['message_type'] in message_types.keys():
            raise Exception("Unknown message type")

        msg_type = json['message_type']
        msg = message_types[json['message_type']](json['message'])
    except Exception as e:
        #print "json.auth_key: %s/self.auth_key: %s -- %s" % (json['auth_key'], auth_key, e)
        print "json.auth_key: %s/self.auth_key: %s -- %s" % (json, auth_key, e)
        msg = None

    print "Message: %s" % msg
    if msg:
        print "Message(json): %s" % msg.to_json

    return msg_type, msg

def unparse_coordinator_msg(message, message_type, auth_key):
    if not message_type in message_types.keys():
        raise Exception("Unknown message type")

    return {
        'auth_key': auth_key,
        'message_type': message_type,
        'message': message.to_json()
    }

class CoordinatorServer:
    def __init__(self, server_address="127.0.0.1", server_port=5678, auth_key=""):
        self.server_address = server_address
        self.server_port = server_port
        self.auth_key = auth_key

        self.callbacks = {}

    def set_callbacks(self, get_test_cb=None, get_test_results_cb=None,
                      request_test_cb=None, finish_test_cb=None,
                      client_confirm_cb=None, server_confirm_cb=None):
        self.callbacks['get-test'] = get_test_cb
        self.callbacks['get-test-results'] = get_test_results_cb
        self.callbacks['request-test'] = request_test_cb
        self.callbacks['finish-test'] = finish_test_cb
        self.callbacks['client-confirm-test'] = client_confirm_cb
        self.callbacks['server-confirm-test'] = server_confirm_cb

    def setup_listener(self):
        self.context = zmq.Context()
        self.sock = self.context.socket(zmq.REP)

        self.sock.bind("tcp://[%s]:%d" % (server_address, server_port))

    def run(self):
        while True:
            type, msg = self.get_msg()
            self.handle_msg(type, msg)

    def handle_msg(self, msg_type, msg):
        status = None
        value  = None

        try:
            if not msg_type in self.callbacks:
                raise Exception("Unknown message type: %s" % msg_type)
            if not self.callbacks[msg_type]:
                raise Exception("Unsupported message: %s" % msg_type)

            status, value = self.callbacks[msg_type](requesting_address=msg.requesting_address, test_id=msg.test_id, value=msg.value)
        except Exception as e:
            status = BWCTLError(error_code=-1, error_msg=str(e))
            value  = None

        print "Response status: %s" % status

        response_msg_type = "%s-response" % msg_type
        if not response_msg_type in message_types:
            response_msg = GenericResponseMessage(status=status, value=value)
        else:
            response_msg = message_types[response_msg_type](status=status, value=value)

        try:
            coord_resp = unparse_coordinator_msg(response_msg, response_msg_type, self.auth_key)
            self.sock.send_json(coord_resp)
        except:
            # XXX: log an error here
            pass

        return

    def get_msg(self):
        coord_msg = self.sock.recv_json()
        return parse_coordinator_msg(coord_msg, self.auth_key)
