from os.path import dirname, realpath, sep, pardir
import sys
sys.path.insert(0, dirname(realpath(__file__)) + sep + pardir)

import unittest
import httpretty

from bwctl.protocol.v2.client import Client
from bwctl.exceptions import *

class V2JsonResponses(object):
    status_success = """
        {
            "legacy_endpoint_port": 6001,
            "protocol": 2.0,
            "ntp_error": 0.0006,
            "version": "2.0",
            "time": "2015-04-01T14:39:34.507710Z",
            "available_tools": ["iperf3", "traceroute", "ping", "owamp", "iperf", "tracepath"]
        }
    """

    test = """
        {
            "id": "824b8c78-66ae-11e4-9011-001b214e9203",
            "status": "scheduled",
            "client": {
                "protocol": 2.0,
                "time": "2014-11-18T06:37:04.12345Z",
                "ntp_error": 0.8
            },
            "sender_endpoint": {
                "address": "192.168.0.2",
                "test_port": 5012,
                "bwctl_protocol": 2.0, 
                "ntp_error": 1.2,
                "peer_port": 80,
                "base_path": "/bwctl",
                "test_id": "824b8c78-66ae-11e4-9011-001b214e9203"
            },
            "receiver_endpoint": {
                "address": "10.0.0.2",
                "bwctl_protocol": 2.0, 
                "ntp_error": 0.5,
                "peer_port": 80,
                "base_path": "/bwctl"
            },
            "tool": "owamp",
            "tool_parameters": {
                "packet_count": 10,
                "inter_packet_time": 1.0,
                "packet_size": 8000
            },
            "scheduling_parameters": {
                "requested_time": "2014-11-18T06:37:04.12345Z",
                "latest_acceptable_time": "2014-11-18T06:37:10.5678Z",
                "reservation_start_time": "2014-11-18T06:37:05.12345Z",
                "test_start_time": "2014-11-18T06:37:05.12345Z",
                "reservation_end_time": "2014-11-18T06:47:05.12345Z"
            }
        }
    """

    test_results = """
        {
            "status": "finished",
            "results": {
                "output": "...the output of owping..."
            }
        }
    """


class ClientTest(unittest.TestCase):
  """Unit tests for the v2 client """

  @httpretty.activate
  def test_v2_status_success(self):
    httpretty.register_uri(httpretty.GET, "http://localhost/bwctl/v2/status",
        body=V2JsonResponses.status_success,
        status=Success.http_error)

    client = Client(base_url="http://localhost/bwctl")
    status = client.get_status()
    self.assertEqual(status.legacy_endpoint_port, 6001)
    self.assertEqual(status.protocol, 2.0)
    self.assertEqual(status.ntp_error, 0.0006)
    self.assertEqual(status.version, "2.0")
    for tool in [ "iperf3", "traceroute", "ping", "owamp", "iperf", "tracepath" ]:
        self.assertTrue(tool in status.available_tools)
    self.assertNotEqual(status.time, None)

  @httpretty.activate
  def test_v2_get_test_success(self):
    httpretty.register_uri(httpretty.GET, "http://localhost/bwctl/v2/tests/824b8c78-66ae-11e4-9011-001b214e9203",
        body=V2JsonResponses.test,
        status=Success.http_error)

    client = Client(base_url="http://localhost/bwctl")
    test = client.get_test("824b8c78-66ae-11e4-9011-001b214e9203")
    self.assertEqual(test.id, "824b8c78-66ae-11e4-9011-001b214e9203")
    self.assertEqual(test.status, "scheduled")
    self.assertEqual(test.tool, "owamp")
    self.assertTrue(test.client != None)
    self.assertTrue(test.scheduling_parameters != None)
    self.assertTrue(test.receiver_endpoint != None)
    self.assertTrue(test.sender_endpoint != None)

  @httpretty.activate
  def test_v2_get_test_results_success(self):
    httpretty.register_uri(httpretty.GET, "http://localhost/bwctl/v2/tests/824b8c78-66ae-11e4-9011-001b214e9203/results",
        body=V2JsonResponses.test_results,
        status=Success.http_error)

    client = Client(base_url="http://localhost/bwctl")
    results = client.get_test_results("824b8c78-66ae-11e4-9011-001b214e9203")
    self.assertEqual(results.status, "finished")
    self.assertTrue("output" in results.results)

if __name__ == "__main__":
  unittest.main()
