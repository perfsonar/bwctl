from bwctl.tool_types.base import Base
from bwctl.tools import ToolTypes

from bwctl.config import get_config

class Iperf(Base):
    name = "iperf"
    type = ToolTypes.THROUGHPUT
    known_parameters = [ "duration", "protocol", "bandwidth", "parallel_streams", "report_interval", "window_size", "buffer_size", "omit_seconds", "tos_bits", "units", "output_format" ]
    default_server_tool = "iperf"
    default_client_tool = "iperf"

    def build_command_line(cls, test):
        cmd_line = []

        cmd_line.extend(["iperf"])

        # Print the MTU as well
        cmd_line.extend(["-m"])

        if test.local_sender:
            cmd_line.extend(["-B", test.sender_endpoint.address])
        else:
            cmd_line.extend(["-B", test.receiver_endpoint.address])

        if test.local_sender:
            cmd_line.extend(["-c", test.receiver_endpoint.address])
            cmd_line.extend(["-p", test.receiver_endpoint.test_port])
        else:
            cmd_line.extend(["-s"])

        cmd_line.extend(["-t", test.tool_parameters['duration']])

        if "units" in test.tool_parameters:
            cmd_line.extend(["-f", test.tool_parameters['units']])

        #if "tos_bts" in test.tool_parameters:
        #    cmd_line.extend(["-S", test.tool_parameters['units']])

        if "output_format" in test.tool_parameters:
            cmd_line.extend(["-y", test.tool_parameters['output_format']])

        if "parallel_streams" in test.tool_parameters:
            cmd_line.extend(["-P", test.tool_parameters['parallel_streams']])

        return cmd_line
