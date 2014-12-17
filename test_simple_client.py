from bwctl.client.simple import SimpleClient
from bwctl.models import Test

client = SimpleClient('http://localhost:8080/bwctl')

print client.get_status()

test = Test(tool="owamp")

ret_test = client.request_test(test)

print "Test ID: %s" % ret_test.id

client.accept_test(ret_test.id)

client.get_test_results(ret_test.id)
