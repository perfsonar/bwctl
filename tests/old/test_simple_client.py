from bwctl.client.simple import SimpleClient
from bwctl.models import Test, SchedulingParameters, Endpoint, ClientSettings
import datetime
import time

client = SimpleClient('http://localhost:4824/bwctl')

print client.get_status()
#test = Test(tool="iperf",
#            client=ClientSettings(
#                address="127.0.0.1",
#                time=datetime.datetime.now()
#            ),
#            sender_endpoint=Endpoint(
#                #local=True,
#                address="127.0.0.1"
#            ),
#            receiver_endpoint=Endpoint(
#                local=True,
#                address="127.0.0.1"
#            ),
#            tool_parameters={
#                'duration': 30
#            },
#            scheduling_parameters=SchedulingParameters(
#                requested_time=datetime.datetime.now()+datetime.timedelta(seconds=2)
#            )
#       )


test = Test(tool="owamp",
#test = Test(tool="ping",
            client=ClientSettings(
                address="127.0.0.1",
                time=datetime.datetime.now()
            ),
            sender_endpoint=Endpoint(
                #local=True,
                address="127.0.0.1"
            ),
            receiver_endpoint=Endpoint(
                local=True,
                address="127.0.0.1"
            ),
            tool_parameters={
                'packet_count': 20,
                'inter_packet_time': 0.5
            },
            scheduling_parameters=SchedulingParameters(
                requested_time=datetime.datetime.now()+datetime.timedelta(seconds=2)
            )
       )

#test = Test(tool="traceroute",
#            client=ClientSettings(
#                address="127.0.0.1",
#                time=datetime.datetime.now()
#            ),
#            sender_endpoint=Endpoint(
#                local=True,
#                #address="127.0.0.1"
#                address="207.75.165.179"
#            ),
#            receiver_endpoint=Endpoint(
#                address="198.124.252.141" # chic-pt1.es.net
#            ),
#            tool_parameters={
#                'packet_size': 20,
#                'first_ttl': 1,
#                'maximum_duration': 20
#            },
#            scheduling_parameters=SchedulingParameters(
#                requested_time=datetime.datetime.now()+datetime.timedelta(seconds=2)
#            )
#       )


print "Test: %s" % test.to_json()

ret_test = client.request_test(test)

print "Test ID: %s" % ret_test.id

ret_test.scheduling_parameters.requested_time = datetime.datetime.now()+datetime.timedelta(seconds=5)

ret_test = client.update_test(ret_test.id, ret_test)

client.accept_test(ret_test.id)

client.remote_accept_test(ret_test.id)

while ret_test.status != "finished":
    time.sleep(1)
    ret_test = client.get_test(ret_test.id)

results = client.get_test_results(ret_test.id)
print "Results: %s" % results
