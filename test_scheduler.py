from bwctl.server.scheduler import Scheduler
from bwctl.models import Test, SchedulingParameters
import datetime

scheduler = Scheduler()
tests = []

for index in range(0, 10):
#for index in range(0, 2):
    if index % 4 == 3:
        tool = "iperf"
        tool_parameters = { "duration": 20 }
    else:
        tool = "owamp"
        tool_parameters = { "packet_count": 10, "inter_packet_time": 1 }
    scheduling_parameters = SchedulingParameters()
    scheduling_parameters.requested_time = datetime.datetime.now() + datetime.timedelta(seconds=index)

    test = Test(id="test-%d" % index, tool=tool, tool_parameters=tool_parameters, scheduling_parameters=scheduling_parameters)
    tests.append(test)

for test in tests:
    print "Adding test %s at %s" % (test.id, test.scheduling_parameters.requested_time)
    scheduler.add_test(test)

print "Removing tests"
for index, test in enumerate(tests):
    #if index % 2 == 0:
    #    scheduler.remove_test(test)
    scheduler.remove_test(test)
