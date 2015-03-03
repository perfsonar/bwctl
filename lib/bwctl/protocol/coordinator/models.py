import multiprocessing
import zmq
import sys
import time

from bwctl import jsonobject
from bwctl.models import Results, BWCTLError, Test

class GenericRequestMessage(jsonobject.JsonObject):
    requesting_address = jsonobject.StringProperty(required=False)
    user = jsonobject.StringProperty(required=False)
    test_id = jsonobject.StringProperty(required=False)
    value   = jsonobject.ObjectProperty(jsonobject.JsonObject, required=False)

class GenericResponseMessage(jsonobject.JsonObject):
    status  = jsonobject.ObjectProperty(BWCTLError, required=False)
    value   = jsonobject.ObjectProperty(jsonobject.JsonObject, required=False)

class TestRequestMessage(GenericRequestMessage):
    value   = jsonobject.ObjectProperty(Test, required=False)

class TestResponseMessage(GenericResponseMessage):
    value   = jsonobject.ObjectProperty(Test, required=False)

class ResultsRequestMessage(GenericRequestMessage):
    value   = jsonobject.ObjectProperty(Results, required=False)

class ResultsResponseMessage(GenericResponseMessage):
    value   = jsonobject.ObjectProperty(Results, required=False)

message_types = {
    "get-test": GenericRequestMessage,
    "get-test-response": TestResponseMessage,
    "get-test-results": GenericRequestMessage,
    "get-test-results-response": ResultsResponseMessage,
    "client-confirm-test": GenericRequestMessage,
    "client-confirm-test-response": GenericResponseMessage,
    "remote-confirm-test": TestRequestMessage,
    "remote-confirm-test-response": GenericResponseMessage,
    "server-confirm-test": GenericRequestMessage,
    "server-confirm-test-response": GenericResponseMessage,
    "request-test": TestRequestMessage,
    "request-test-response": TestResponseMessage,
    "cancel-test": GenericRequestMessage,
    "cancel-test-response": GenericResponseMessage,
    "finish-test": ResultsRequestMessage,
    "finish-test-response": GenericResponseMessage,
}

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
        msg = None

    return msg_type, msg

def build_request_msg(message_type="", test_id=None, value=None, requesting_address=None, user=None):
    class_type = message_types.get(message_type, GenericRequestMessage)

    request_msg = class_type(test_id=test_id, value=value, requesting_address=requesting_address, user=user)

    return request_msg

def build_response_msg(message_type="", status=None, value=None):
    class_type = message_types.get(message_type, GenericResponseMessage)

    response_msg = class_type(status=status, value=value)

    return response_msg

def unparse_coordinator_msg(message, message_type, auth_key):
    if not message_type in message_types.keys():
        raise Exception("Unknown message type")

    return {
        'auth_key': auth_key,
        'message_type': message_type,
        'message': message.to_json()
    }
