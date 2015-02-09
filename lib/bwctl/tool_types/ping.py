import datetime
import time

from subprocess import Popen, PIPE

from bwctl.tool_types.latency_base import LatencyBase
from bwctl.utils import is_ipv6, timedelta_seconds

class Ping(LatencyBase):
    name = "ping"
    known_parameters = [ "packet_count", "inter_packet_time", " packet_size", "packet_ttl", "tos_bits" ]

    def config_options(self):
        options = LatencyBase.config_options(self).copy()

        options.update({
            "ping_cmd":     "string(default='ping')",
            "ping6_cmd":    "string(default='ping6')",
        })

        return options

    def check_available(self):
        retval = True

        for cmd in [ "ping_cmd", "ping6_cmd" ]:
            loopback_addr = "127.0.0.1"
            if "6" in cmd:
                loopback_addr = "::1"

            cmd_line = [ self.get_config_item(cmd), "-c", "1", loopback_addr ]
            try:
                p = Popen(cmd_line, stdout=PIPE, stderr=PIPE)
                (stdout, stderr) = p.communicate()
                if p.returncode != 0:
                    raise Exception("Invalid exit code from command: %d" % p.returncode)
            except Exception as e:
                print "Problem running %s: %s" % (" ".join(cmd_line), e)
                retval = False

        return retval

    def run_test(self, test, end_time=None):
        # We only have to run the ping command if we're sending the pings, i.e.
        # we're the sender
        if test.local_sender:
            return LatencyBase.run_test(self, test)
    
        # Just do nothing, and return after the test is over
        timeout = 10
        if end_time:
            timeout = timedelta_seconds(end_time - datetime.datetime.now())

        while not end_time or datetime.datetime.now() < end_time:
            time.sleep(timeout)

            if end_time:
                timeout = timedelta_seconds(end_time - datetime.datetime.now())

        # Return an empty results since it doesn't matter
        return self.get_results(test=test)

    def build_command_line(self, test):
        cmd_line = []

        if test.local_sender:
            if is_ipv6(test.remote_endpoint.address):
                cmd_line.append(self.get_config_item('ping6_cmd'))
            else:
                cmd_line.append(self.get_config_item('ping_cmd'))

            cmd_line.extend(["-W", "1"])

            if "packet_count" in test.tool_parameters:
                cmd_line.extend(["-c", str(test.tool_parameters['packet_count'])])

            if "inter_packet_time" in test.tool_parameters:
                cmd_line.extend(["-i", str(test.tool_parameters['inter_packet_time'])])

            if "packet_size" in test.tool_parameters:
                cmd_line.extend(["-s", str(test.tool_parameters['packet_size'])])

            if "packet_ttl" in test.tool_parameters:
                cmd_line.extend(["-t", str(test.tool_parameters['packet_ttl'])])

            if "tos_bits" in test.tool_parameters:
                cmd_line.extend(["-Q", str(test.tool_parameters['tos_bits'])])

            cmd_line.extend(["-I", test.local_endpoint.address])
            cmd_line.extend([test.remote_endpoint.address])

        return cmd_line
