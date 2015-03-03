import multiprocessing
import zmq
import sys
import time

from bwctl.protocol.coordinator.models import build_request_msg, unparse_coordinator_msg, parse_coordinator_msg

from bwctl.utils import BwctlProcess, get_logger
from bwctl.exceptions import BwctlException

class Client:
    def __init__(self, server_address="127.0.0.1", server_port=5678, auth_key=""):
        self.server_address = server_address
        self.server_port = server_port
        self.auth_key = auth_key
        self.connected = False
        self.logger = get_logger()

    def connect(self):
        self.context = zmq.Context()
        self.sock = self.context.socket(zmq.REQ)

        self.sock.connect("tcp://[%s]:%d" % (self.server_address, self.server_port))

        self.connected = True

    def get_test(self, test_id=None, requesting_address=None, user=None):
        return self._send_msg(test_id=test_id, message_type="get-test", requesting_address=requesting_address, user=user)

    def get_test_results(self, test_id=None, requesting_address=None, user=None):
        return self._send_msg(test_id=test_id, message_type="get-test-results", requesting_address=requesting_address, user=user)

    def request_test(self, test=None, requesting_address=None, user=None):
        return self._send_msg(value=test, message_type="request-test", requesting_address=requesting_address, user=user)

    def update_test(self, test=None, test_id=None, requesting_address=None, user=None):
        return self._send_msg(value=test, message_type="request-test", test_id=test_id, requesting_address=requesting_address, user=user)

    def client_confirm_test(self, test_id=None, requesting_address=None, user=None):
        return self._send_msg(test_id=test_id, message_type="client-confirm-test", requesting_address=requesting_address, user=user)

    def remote_confirm_test(self, test_id=None, test=None, requesting_address=None, user=None):
        return self._send_msg(test_id=test_id, value=test, message_type="remote-confirm-test", requesting_address=requesting_address, user=user)

    def server_confirm_test(self, test_id=None, requesting_address=None, user=None):
        return self._send_msg(test_id=test_id, message_type="server-confirm-test", requesting_address=requesting_address, user=user)

    def cancel_test(self, test_id=None, requesting_address=None, user=None):
        return self._send_msg(test_id=test_id, message_type="cancel-test", requesting_address=requesting_address, user=user)

    def finish_test(self, test_id=None, results=None, requesting_address=None, user=None):
        return self._send_msg(test_id=test_id, value=results, message_type="finish-test", requesting_address=requesting_address, user=user)

    def _send_msg(self, message_type="", test_id=None, value=None, requesting_address=None, user=None):
        if not self.connected:
            self.connect()

        msg = build_request_msg(message_type=message_type, test_id=test_id, value=value, requesting_address=requesting_address, user=user)

        coord_req = unparse_coordinator_msg(msg, message_type, self.auth_key)
        self.logger.debug("Sending request: %s" % coord_req)
        self.sock.send_json(coord_req)
        coord_resp = self.sock.recv_json()
        self.logger.debug("Received response: %s" % coord_resp)
        msg_type, resp_msg = parse_coordinator_msg(coord_resp, self.auth_key)

        if msg_type == "" or resp_msg == None:
            raise SystemProblemException("Invalid response received from coordinator")

        BwctlException.from_bwctl_error(resp_msg.status).raise_if_error()

        return resp_msg.value
