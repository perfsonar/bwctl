from bwctl.client.simple import SimpleClient
from bwctl.models import Test, SchedulingParameters, Endpoint, ClientSettings
import datetime

client = SimpleClient('http://localhost:8080/bwctl')

print client.get_status()

test = Test(tool="owamp",
            client=ClientSettings(
                address="127.0.0.1",
                time=datetime.datetime.now()
            ),
            sender_endpoint=Endpoint(
                address="127.0.0.1"
            ),
            receiver_endpoint=Endpoint(
                address="127.0.0.1"
            ),
            scheduling_parameters=SchedulingParameters(
                requested_time=datetime.datetime.now()
            )
       )

ret_test = client.request_test(test)

print "Test ID: %s" % ret_test.id

client.accept_test(ret_test.id)

client.get_test_results(ret_test.id)
