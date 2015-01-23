from subprocess import Popen, PIPE

from bwctl.tool_types.latency_base import LatencyBase

class Owamp(LatencyBase):
    name = "owamp"
    known_parameters = [ "packet_count", "inter_packet_time", " packet_size", "receiver_connects" ]

    def config_options(self):
        options = LatencyBase.config_options(self).copy()

        options.update({
            "owping_cmd":  "string(default='owping')",
            "owampd_cmd":  "string(default='owampd')",
            "owamp_ports": "port_range(default=None)",
            "disable_owamp": "boolean(default=False)",
        })

        return options

    def check_available(self):
        retval = True

        for cmd in [ "owping_cmd", "owampd_cmd" ]:
            cmd_line = [ self.get_config_item(cmd), "-h" ]
            try:
                p = Popen(cmd_line, stdout=PIPE, stderr=PIPE)
                (stdout, stderr) = p.communicate()
                if p.returncode != 0:
                    raise Exception("Invalid exit code from command: %d" % p.returncode)
            except Exception as e:
                print "Problem running %s: %s" % (" ".join(cmd_line), e)
                retval = False

        return retval

    def build_command_line(self, test):
        cmd_line = []

        if test.local_client:
            cmd_line.append(self.get_config_item('owping_cmd'))

            if "packet_count" in test.tool_parameters:
                cmd_line.extend(["-c", str(test.tool_parameters['packet_count'])])

            if "inter_packet_time" in test.tool_parameters:
                cmd_line.extend(["-i", str(test.tool_parameters['inter_packet_time'])])

            if "packet_size" in test.tool_parameters:
                cmd_line.extend(["-s", str(test.tool_parameters['packet_size'])])

            if test.local_receiver:
                cmd_line.extend([test.sender_endpoint.address])
            else:
                cmd_line.extend(["-t", test.receiver_endpoint.address])
        else:
            cmd_line.append(self.get_config_item('owampd_cmd'))

            cmd_line.extend(["-S", test.receiver_endpoint.address])

        return cmd_line
