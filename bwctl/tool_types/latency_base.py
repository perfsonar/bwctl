from bwctl.tool_types.base import Base
from bwctl.tools import ToolTypes

class LatencyBase(Base):
    type = ToolTypes.LATENCY
    known_parameters = [ "packet_count", "inter_packet_time", " packet_size", "packet_ttl", "receiver_connects" ]

    def duration(self, test):
        """ Returns the test length, a required paramter. This is overwritten since
            the packet_count/inter_packet_time define the duration """

        if 'inter_packet_time' in test.tool_parameters and 'packet_count' in test.tool_parameters:
            return test.tool_parameters['inter_packet_time'] * test.tool_parameters['packet_count']
        else:
            raise Exception("Unknown test duration")

    def bandwidth(self, test):
        """ Returns the network bandwidth this test uses. This is overwritten since
            the inter_packet_time/packet_size define the bandwidth """

        if 'inter_packet_time' in test.tool_parameters and 'packet_size' in test.tool_parameters:
            # Convert to bps
            return 1/test.tool_parameters['inter_packet_time'] * test.tool_parameters['packet_size'] * 8
        else:
            return 0
