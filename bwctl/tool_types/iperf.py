from bwctl.tool_types.base import Base
from bwctl.tools import ToolTypes, ToolParameter

from subprocess import Popen, PIPE
import re

class Iperf(Base):
    name = "iperf"
    type = ToolTypes.THROUGHPUT
    known_parameters = [
        ToolParameter(name="duration", type='integer(min=0)'),
        ToolParameter(name="protocol", type='option("tcp","udp")'),
        ToolParameter(name="bandwidth", type='integer(min=0)'),
        ToolParameter(name="parallel_streams", type='integer(min=0)'),
        ToolParameter(name="report_interval", type='float(min=0)'),
        ToolParameter(name="window_size", type='integer(min=0)'),
        ToolParameter(name="buffer_size", type='integer(min=0)'),
        ToolParameter(name="omit_seconds", type='float(min=0)'),
        ToolParameter(name="tos_bits", type='string'), # XXX: Needs a better validator
        ToolParameter(name="units", type='string'), # XXX: Needs a better validator
        ToolParameter(name="output_format", type='string'), # XXX: Needs a better validator
    ]

    def config_options(self):
        options = super(Iperf, self).config_options().copy()

        options.update({
            "iperf_cmd":  "string(default='iperf')",
            "iperf_ports": "port_range(default=None)",
        })

        return options

    def check_available(self):
        retval = False

        try:
            cmd_line = [ self.get_config_item("iperf_cmd"), "-v" ]

            p = Popen(cmd_line, stdout=PIPE, stderr=PIPE)

            (stdout, stderr) = p.communicate()

            if p.returncode != 0 and p.returncode != 1:
                raise Exception("Invalid exit code from iperf")

            for output in stdout, stderr:
                if re.search("iperf version ", output):
                    retval = True
                    break
        except Exception as e:
            self.logger.error("Iperf is not available: %s" % str(e))
            pass

        return retval

    def get_results(self, test=None, timed_out=False, errors=[], exit_status=0, stdout="", stderr=""):
        if not test.local_client:
            if timed_out:
                timed_out = False
                exit_status = 0

        return super(Iperf, self).get_results(test=test, errors=errors, exit_status=exit_status, stdout=stdout, stderr=stderr)

    def build_command_line(self, test):
        cmd_line = []

        cmd_line.append(self.get_config_item("iperf_cmd"))

        # Print the MTU as well
        cmd_line.extend(["-m"])

        cmd_line.extend(["-i", "1"])

        cmd_line.extend(["-B", test.local_endpoint.address])

        if test.local_client:
            cmd_line.extend(["-c", test.remote_endpoint.address])
            cmd_line.extend(["-p", str(test.remote_endpoint.test_port)])
        else:
            cmd_line.extend(["-s"])
            cmd_line.extend(["-p", str(test.local_endpoint.test_port)])

        cmd_line.extend(["-t", str(test.tool_parameters['duration'])])

        if "units" in test.tool_parameters:
            cmd_line.extend(["-f", str(test.tool_parameters['units'])])

        if "tos_bts" in test.tool_parameters:
            cmd_line.extend(["-S", str(test.tool_parameters['tos_bits'])])

        if "output_format" in test.tool_parameters:
            cmd_line.extend(["-y", str(test.tool_parameters['output_format'])])

        if "parallel_streams" in test.tool_parameters:
            cmd_line.extend(["-P", str(test.tool_parameters['parallel_streams'])])

        return cmd_line
