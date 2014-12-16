from bwctl.tool_types.base import Base
from bwctl.tools import ToolTypes

from bwctl.config import get_config

class Iperf(Base):
    name = "iperf"
    type = ToolTypes.THROUGHPUT
    known_parameters = [ "duration", "protocol", "bandwidth", "parallel_streams", "report_interval", "window_size", "buffer_size", "omit_seconds", "tos_bits", "units", "output_format", "receiver_connects" ]
    default_server_tool = "iperf"
    default_client_tool = "iperf"

    def build_command_line(cls, test):
        cmd_line = []

        is_sender = False
        if test.sender_endpoint.is_local():
            is_sender = True

        cmd_line.append("iperf")

        # Print the MTU as well
        cmd_line.append("-m")

        if is_sender:
            cmd_line.append("-B", test.sender_endpoint.address)
        else:
            cmd_line.append("-B", test.receiver_endpoint.address)

        if is_sender:
            cmd_line.append("-c", test.receiver_endpoint.address)
            cmd_line.append("-p", test.receiver_endpoint.tool_port)
        else:
            cmd_line.append("-s")

        cmd_line.append("-t", test.test_parameters['duration'])

        if "units" in test.test_parameters:
            cmd_line.append("-f", test.test_parameters['units'])

        #if "tos_bts" in test.test_parameters:
        #    cmd_line.append("-S", test.test_parameters['units'])

        if "output_format" in test.test_parameters:
            cmd_line.append("-y", test.test_parameters['output_format'])

        if "parallel_streams" in test.test_parameters:
            cmd_line.append("-P", test.test_parameters['parallel_streams'])

        return cmd_line
