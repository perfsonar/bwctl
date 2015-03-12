import datetime
import time

from subprocess import Popen, PIPE

from bwctl.tool_types.base import Base
from bwctl.tools import ToolTypes, ToolParameter
from bwctl.utils import is_ipv6, timedelta_seconds

class Tracepath(Base):
    name = "tracepath"
    type = ToolTypes.TRACEROUTE
    known_parameters = [
        ToolParameter(name="packet_size", type='integer(min=0)'),
        ToolParameter(name="maximum_duration", type='float(min=0.1)'),
    ]

    def config_options(self):
        options = super(Tracepath, self).config_options().copy()

        options.update({
            "tracepath_cmd":     "string(default='tracepath')",
        })

        return options

    def check_available(self):
        retval = True

        try:
            loopback_addr = "127.0.0.1"

            cmd_line = [ self.get_config_item("tracepath_cmd"), loopback_addr ]
            p = Popen(cmd_line, stdout=PIPE, stderr=PIPE)
            (stdout, stderr) = p.communicate()
            if p.returncode != 0:
                raise Exception("Invalid exit code from command: %d" % p.returncode)
        except Exception as e:
            self.logger.error("Tracepath is not available: %s" % str(e))
            retval = False

        return retval

    def run_test(self, test, end_time=None):
        # We only have to run the tracepath command if we're sending the traceoutes, i.e.
        # we're the sender
        if test.local_sender:
            return super(Tracepath, self).run_test(test)

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
            cmd_line.append(self.get_config_item('tracepath_cmd'))

            if "packet_size" in test.tool_parameters:
                cmd_line.extend(["-l", str(test.tool_parameters['packet_size'])])

            cmd_line.extend([test.remote_endpoint.address])

        return cmd_line
