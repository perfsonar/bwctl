import socket

from os.path import dirname, realpath, sep, pardir
import sys
sys.path.append(dirname(realpath(__file__)) + sep + pardir)

from bwctl.protocol.legacy.client import Client
from bwctl.protocol.legacy.models import *

client = Client(server_address="localhost", server_port=4823)

client.connect()

server_greeting = client.get_server_greeting()

print "Server Greeting: %s" % server_greeting.modes

server_ok = client.send_client_greeting()

print "Server OK: %s %d" % (server_ok.tools, server_ok.accept_type)

time_response = client.send_time_request()

print "Time Response: %s, %f" % (time_response.timestamp.time, time_response.error_estimate.error)

import time
time.sleep(10)

client.send_stop_session()

import time
time.sleep(1)

client.close()
