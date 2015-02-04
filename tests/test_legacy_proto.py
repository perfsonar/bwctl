import socket

from bwctl.legacy.protocol.messages import ServerGreeting, Modes, ClientGreeting, AcceptType, Tools, ServerOK, TimeRequest, TimeResponse

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.connect(("localhost", 4823))
s.connect(("localhost", 1024))

server_greeting_data = s.recv(32)
server_greeting = ServerGreeting.parse(server_greeting_data)

print "Server Greeting: %s" % server_greeting.modes

client_greeting = ClientGreeting(mode=Modes.OPEN, username="fdsa")
client_greeting_data = client_greeting.unparse()

print "Data: %d" % len(client_greeting_data)

s.sendall(client_greeting_data)
server_ok_data = ""
while len(server_ok_data) < 48:
    data = s.recv(48 - len(server_ok_data))
    server_ok_data = server_ok_data + data

print "Server OK(data length): %d" % len(server_ok_data)
try:
    ClientGreeting.parse(server_ok_data)
    print "Got a client greeting back"
except:
    pass

try:
    ServerGreeting.parse(server_ok_data)
    print "Got a server greeting back"
except:
    pass

server_ok = ServerOK.parse(server_ok_data)
print "Server OK: %s %d" % (server_ok.tools, server_ok.accept_type)

timerequest_msg = TimeRequest().unparse(include_msg_hdr=True)
print "Message size: %d" % len(timerequest_msg)
s.sendall(timerequest_msg)

timeresponse_data = ""
while len(timeresponse_data) < 32:
    data = s.recv(32 - len(timeresponse_data))
    timeresponse_data = timeresponse_data + data
    print "Length: %d" % len(timeresponse_data)

timeresponse_msg = TimeResponse.parse(timeresponse_data)
print "Time Response: %s, %f" % (timeresponse_msg.timestamp.time, timeresponse_msg.error_estimate.error)
timeresponse_msg_2 = TimeResponse.parse(timeresponse_msg.unparse())
print "Time Response 2: %s, %f" % (timeresponse_msg_2.timestamp.time, timeresponse_msg_2.error_estimate.error)
timeresponse_msg_3 = TimeResponse.parse(timeresponse_msg.unparse())
print "Time Response 3: %s, %f" % (timeresponse_msg_3.timestamp.time, timeresponse_msg_3.error_estimate.error)

s.close()
