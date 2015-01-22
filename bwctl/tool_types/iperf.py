from bwctl.tool_types.base import Base
from bwctl.tools import ToolTypes

class Iperf(Base):
    name = "iperf"
    type = ToolTypes.THROUGHPUT
    known_parameters = [ "duration", "protocol", "bandwidth", "parallel_streams", "report_interval", "window_size", "buffer_size", "omit_seconds", "tos_bits", "units", "output_format" ]

    def config_options(self):
        options = Base.config_options(self).copy()

        options.update({
            "iperf_cmd":  "string(default='iperf')",
            "iperf_ports": "port_range(default=None)",
            "disable_iperf": "boolean(default=False)",
        })

        return options

    def build_command_line(self, test):
        cmd_line = []

        cmd_line.append(self.get_config_item("iperf_cmd"))

        # Print the MTU as well
        cmd_line.extend(["-m"])

        if test.local_receiver:
            cmd_line.extend(["-B", test.receiver_endpoint.address])
        else:
            cmd_line.extend(["-B", test.sender_endpoint.address])

        if test.local_receiver:
            cmd_line.extend(["-s"])
        else:
            cmd_line.extend(["-c", test.receiver_endpoint.address])
            cmd_line.extend(["-p", str(test.receiver_endpoint.test_port)])

        cmd_line.extend(["-t", str(test.tool_parameters['duration'])])

        if "units" in test.tool_parameters:
            cmd_line.extend(["-f", test.tool_parameters['units']])

        if "tos_bts" in test.tool_parameters:
            cmd_line.extend(["-S", test.tool_parameters['tos_bits']])

        if "output_format" in test.tool_parameters:
            cmd_line.extend(["-y", test.tool_parameters['output_format']])

        if "parallel_streams" in test.tool_parameters:
            cmd_line.extend(["-P", test.tool_parameters['parallel_streams']])

        return cmd_line
