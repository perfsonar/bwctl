from bwctl.tool_types.base import Base
from bwctl.tools import ToolTypes, ToolParameter

from subprocess import Popen, PIPE
import re

class Iperf3(Base):
    name = "iperf3"
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
        ToolParameter(name="tos_bits", type='integer(min=0,max=255)'), # XXX: Needs a better validator
        ToolParameter(name="units", type='option("k", "m", "g", "K", "M", "G")'),
        ToolParameter(name="output_format", type='option("J")'),
        ToolParameter(name="receiver_connects", type='boolean'),
    ]

    def config_options(self):
        options = super(Iperf3, self).config_options().copy()

        options.update({
            "iperf3_cmd":  "string(default='iperf3')",
            "iperf3_ports": "port_range(default=None)",
        })

        return options

    def check_available(self):
        retval = False

        try:
            cmd_line = [ self.get_config_item("iperf3_cmd"), "-v" ]

            p = Popen(cmd_line, stdout=PIPE, stderr=PIPE)

            (stdout, stderr) = p.communicate()

            if p.returncode != 0 and p.returncode != 1:
                raise Exception("Invalid exit code from iperf")

            for output in stdout, stderr:
                if re.search("iperf 3\.0\.1[0-9]", output):
                    retval = True
                    break

                if re.search("iperf 3\.1", output):
                    retval = True
                    break
        except Exception as e:
            self.logger.error("Iperf3 is not available: %s" % str(e))
            pass

        return retval

    def get_results(self, test=None, timed_out=False, errors=[], exit_status=0, stdout="", stderr=""):
        if not test.local_client:
            if timed_out:
                timed_out = False
                exit_status = 0

        return super(Iperf3, self).get_results(test=test, errors=errors, exit_status=exit_status, stdout=stdout, stderr=stderr)

    def build_command_line(self, test):
        cmd_line = []

        cmd_line.append(self.get_config_item("iperf3_cmd"))

        cmd_line.extend(["-B", test.local_endpoint.address])

        # Print the MTU as well
        cmd_line.extend(["-f", "m"])

        if test.local_client:
            cmd_line.extend(["-c", test.remote_endpoint.address])
            cmd_line.extend(["-p", str(test.remote_endpoint.test_port)])
        else:
            cmd_line.extend(["-s"])
            cmd_line.extend(["-p", str(test.local_endpoint.test_port)])

        if "units" in test.tool_parameters:
            cmd_line.extend(["-f", str(test.tool_parameters['units'])])

        if "report_interval" in test.tool_parameters:
            cmd_line.extend(["-i", str(test.tool_parameters['report_interval'])])

        if "output_format" in test.tool_parameters and \
           test.tool_parameters["output_format"] == "J":
            cmd_line.extend(["-J"])

        if test.local_client:
            cmd_line.extend(["-t", str(test.tool_parameters['duration'])])

            # Set zerocopy mode by default (for backwards coampatibility of results)
            cmd_line.extend(["-Z"])

            if "tos_bits" in test.tool_parameters:
                cmd_line.extend(["-S", str(test.tool_parameters['tos_bits'])])

            if "omit_seconds" in test.tool_parameters:
                cmd_line.extend(["-O", str(test.tool_parameters['omit_seconds'])])

            if "window_size" in test.tool_parameters:
                cmd_line.extend(["-w", str(test.tool_parameters['window_size'])])

            if "receiver_connects" in test.tool_parameters and \
               test.tool_parameters["receiver_connects"]:
                cmd_line.extend(["--reverse"])

            if "protocol" in test.tool_parameters and \
               test.tool_parameters["output_format"] == "udp":
                cmd_line.extend(["-u"])

            if "bandwidth" in test.tool_parameters:
                cmd_line.extend(["-b", str(test.tool_parameters['bandwidth'])])

            if "buffer_size" in test.tool_parameters:
                cmd_line.extend(["-l", str(test.tool_parameters['buffer_size'])])

            if "parallel_streams" in test.tool_parameters:
                cmd_line.extend(["-P", str(test.tool_parameters['parallel_streams'])])

        return cmd_line
