from bwctl.tool_types.latency_base import LatencyBase

from bwctl.config import get_config

class Owamp(LatencyBase):
    name = "owamp"
    known_parameters = [ "packet_count", "inter_packet_time", " packet_size", "packet_ttl", "receiver_connects" ]
    default_server_tool = "owampd"
    default_client_tool = "owping"
