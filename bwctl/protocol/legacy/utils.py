from .models import Tools
import base64
import datetime
import time
import os

from bwctl.utils import timedelta_seconds

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

def datetime_to_bwctl_epoch_time(dt):
   # dt is in UTC, so subtract off the NTP epoch (1900), and get the difference
   return timedelta_seconds(dt - datetime.datetime(1900, 1, 1))

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


