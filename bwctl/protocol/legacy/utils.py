from .models import Tools
import base64
import os

tool_mappings = [
    [ Tools.IPERF, "iperf" ],
    [ Tools.NUTTCP, "nuttcp" ],
    [ Tools.IPERF3, "iperf3" ],
    [ Tools.PING, "ping" ],
    [ Tools.OWAMP, "owamp" ],
    [ Tools.TRACEROUTE, "traceroute" ],
    [ Tools.TRACEPATH, "tracepath" ],
    [ Tools.PARIS_TRACEROUTE, "paris-traceroute" ],
]

def gen_sid():
   return filter(lambda s: s.isalpha(), base64.b64encode(os.urandom(32)))[:16]

def tool_id_by_name(tool_name):
    global tool_mappings

    for mapping in tool_mappings:
        if mapping[1] == tool_name:
            return mapping[0]

    return None

def tool_name_by_id(tool_id):
    global tool_mappings

    for mapping in tool_mappings:
        if mapping[0] == tool_id:
            return mapping[1]

    return None


