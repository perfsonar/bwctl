import datetime
import time

from subprocess import Popen, PIPE

from bwctl.tools import ToolTypes
from bwctl.tool_types.base import Base
from bwctl.utils import is_ipv6, timedelta_seconds

class Traceroute(Base):
    name = "traceroute"
    known_parameters = [ "first_ttl", "last_ttl", "packet_size", "tos_bits", "maximum_duration" ]
    type = ToolTypes.TRACEROUTE

    def config_options(self):
        options = super(Traceroute, self).config_options().copy()

        options.update({
            "traceroute_cmd":     "string(default='traceroute')",
            "traceroute6_cmd":    "string(default='traceroute6')",
        })

        return options

    def check_available(self):
        retval = True

        for cmd in [ "traceroute_cmd", "traceroute6_cmd" ]:
            loopback_addr = "127.0.0.1"
            if "6" in cmd:
                loopback_addr = "::1"

            cmd_line = [ self.get_config_item(cmd), loopback_addr ]
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
        # We only have to run the traceroute command if we're sending the traceroutes, i.e.
        # we're the sender
        if test.local_sender:
            return super(Traceroute, self).run_test(test)

        # Just do nothing, and return after the test is over
        timeout = 10
        if end_time:
            timeout = timedelta_seconds(end_time - datetime.datetime.utcnow())

        while not end_time or datetime.datetime.utcnow() < end_time:
            time.sleep(timeout)

            if end_time:
                timeout = timedelta_seconds(end_time - datetime.datetime.now())

        # Return an empty results since it doesn't matter
        return self.get_results(test=test)

    def build_command_line(self, test):
        cmd_line = []

        if test.local_sender:
            if is_ipv6(test.remote_endpoint.address):
                cmd_line.append(self.get_config_item('traceroute6_cmd'))
            else:
                cmd_line.append(self.get_config_item('traceroute_cmd'))

            if "first_ttl" in test.tool_parameters:
                cmd_line.extend(["-f", str(test.tool_parameters['first_ttl'])])

            if "last_ttl" in test.tool_parameters:
                cmd_line.extend(["-m", str(test.tool_parameters['last_ttl'])])

            if "tos_bits" in test.tool_parameters:
                cmd_line.extend(["-Q", str(test.tool_parameters['tos_bits'])])

            cmd_line.extend(["-s", test.local_endpoint.address])

            cmd_line.extend([test.remote_endpoint.address])

            if "packet_size" in test.tool_parameters:
                cmd_line.extend([str(test.tool_parameters['packet_size'])])

        return cmd_line
