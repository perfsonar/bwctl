from bwctl.server.scheduler import Scheduler
from bwctl.models import Test, SchedulingParameters, Endpoint, ClientSettings
import datetime

scheduler = Scheduler()
tests = []
count = 10

for index in range(0, count):
    if index % 4 == 3:
        tool = "iperf"
        tool_parameters = { "duration": 20 }
    else:
        tool = "owamp"
        tool_parameters = { "packet_count": 10, "inter_packet_time": 1 }
    requested_time = datetime.datetime.now() + datetime.timedelta(seconds=index)
    scheduling_parameters = SchedulingParameters(requested_time=requested_time)
    sender_endpoint = Endpoint(address="local-%d" % index, local=True)
    receiver_endpoint = Endpoint(address="remote-%d" % index, local=True)
    client_settings = ClientSettings(address="client-%d" % index, time=datetime.datetime.now())

    test = Test(id="test-%d" % index, tool=tool, sender_endpoint=sender_endpoint, receiver_endpoint=receiver_endpoint, tool_parameters=tool_parameters, scheduling_parameters=scheduling_parameters, client=client_settings)
    tests.append(test)

for test in tests:
    print "Adding test %s at %s" % (test.id, test.scheduling_parameters.requested_time)
    scheduler.add_test(test)

print "Removing tests"
for index, test in enumerate(tests):
    #if index % 2 == 0:
    #    scheduler.remove_test(test)
    scheduler.remove_test(test)
