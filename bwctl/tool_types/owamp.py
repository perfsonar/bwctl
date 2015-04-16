import os
from tempfile import mkdtemp
from shutil import rmtree
from subprocess import Popen, PIPE

from bwctl.tool_types.latency_base import LatencyBase
from bwctl.tools import ToolParameter

class Owamp(LatencyBase):
    name = "owamp"
    known_parameters = [
        ToolParameter(name="packet_count", type='integer(min=1)'),
        ToolParameter(name="inter_packet_time", type='float(min=0.01)'),
        ToolParameter(name="packet_size", type='integer(min=0)'),
        ToolParameter(name="maximum_duration", type='float(min=0.1)'),
        ToolParameter(name="receiver_connects", type='boolean'),
    ]

    def pre_test_run(self, test):
        dir = mkdtemp("", "tmp",self.get_config_item("owamp_tmp_dir"))
        test.owamp_temp_directory = dir

    def post_test_run(self, test):
        if test.owamp_temp_directory:
            rmtree(test.owamp_temp_directory)

    def config_options(self):
        options = super(Owamp, self).config_options().copy()

        options.update({
            "owping_cmd":  "string(default='owping')",
            "owampd_cmd":  "string(default='owampd')",
            "owamp_ports": "port_range(default=None)",
            "owamp_tmp_dir": "string(default='/tmp/bwctl_owamp')",
        })

        return options

    def check_available(self):
        retval = True

        try:
            tmp_dir = self.get_config_item("owamp_tmp_dir")

            if not os.path.exists(tmp_dir):
                os.makedirs(tmp_dir, 0700)
            elif not os.path.isdir(tmp_dir):
                raise Exception("Temporary directory %s isn't a directory")

            # Try to create, and then remove a directory
            dir = mkdtemp("", "tmp",self.get_config_item("owamp_tmp_dir"))
            rmtree(dir)

            for cmd in [ "owping_cmd", "owampd_cmd" ]:
                cmd_line = [ self.get_config_item(cmd), "-h" ]
                p = Popen(cmd_line, stdout=PIPE, stderr=PIPE)
                (stdout, stderr) = p.communicate()
                if p.returncode != 0:
                    raise Exception("Invalid exit code from command: %d" % p.returncode)
        except Exception as e:
            self.logger.error("OWAMP is not available: %s" % str(e))
            retval = False

        return retval

    def get_results(self, test=None, timed_out=False, errors=[], exit_status=0, stdout="", stderr=""):
        if not test.local_client:
            if timed_out:
                timed_out = False
                exit_status = 0

        return super(Owamp, self).get_results(test=test, errors=errors, exit_status=exit_status, stdout=stdout, stderr=stderr)

    def get_port(self):
        tool_port = self.port_range.get_port()
        min_port  = self.port_range.get_port()
        max_port  = self.port_range.get_port()

        while min_port != tool_port + 1 or \
              max_port != min_port + 1:
            self.port_range.release_port(tool_port)
            self.port_range.release_port(min_port)
            self.port_range.release_port(max_port)

            tool_port = self.port_range.get_port()
            min_port  = self.port_range.get_port()
            max_port  = self.port_range.get_port()

        return tool_port

    def release_port(self, port):
        self.port_range.release_port(port)
        self.port_range.release_port(port + 1)
        self.port_range.release_port(port + 2)

    def build_command_line(self, test):
        cmd_line = []

        server_addr = ""
        if test.local_client:
            server_addr = "[%s]:%d" % (test.remote_endpoint.address, test.remote_endpoint.test_port)
        else:
            server_addr = "[%s]:%d" % (test.local_endpoint.address, test.local_endpoint.test_port)

        if test.local_client:
            cmd_line.append(self.get_config_item('owping_cmd'))

            if "packet_count" in test.tool_parameters:
                cmd_line.extend(["-c", str(test.tool_parameters['packet_count'])])

            if "inter_packet_time" in test.tool_parameters:
                cmd_line.extend(["-i", str(test.tool_parameters['inter_packet_time'])])

            if "packet_size" in test.tool_parameters:
                cmd_line.extend(["-s", str(test.tool_parameters['packet_size'])])

            if not test.local_receiver:
                cmd_line.extend(["-t"])

            cmd_line.extend([ server_addr ])
        else:
            cmd_line.append(self.get_config_item('owampd_cmd'))

            cmd_line.extend(["-S", server_addr])

            cmd_line.extend(["-Z"])

            cmd_line.extend([ "-R", test.owamp_temp_directory ]) # pid files
            cmd_line.extend([ "-d", test.owamp_temp_directory ]) # data files

            # The UDP port range is the two ports beyond the test port.
            port_range = "%d-%d" % (test.local_endpoint.test_port + 1, test.local_endpoint.test_port + 2)

            cmd_line.extend([ "-P", port_range ])

        return cmd_line
