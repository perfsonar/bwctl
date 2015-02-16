import datetime
import os
import select
from subprocess import Popen, PIPE

from bwctl.tools import ToolTypes
from bwctl.utils import timedelta_seconds, get_logger
from bwctl.exceptions import ValidationException, SystemProblemException

class Base(object):
    name = ""
    type = ToolTypes.UNKNOWN
    known_parameters = []

    def __init__(self):
        self.config = {}
        self.logger = get_logger()

    def config_options(self):
        return {
                  "test_ports": "port_range(default='5100-6000')",
                  "disable_%s" % self.name: "boolean(default=False)",
               }

    def check_available(self):
        disable_var = "disable_%s" % self.name
        if self.get_config_item(disable_var):
            return False

        raise SystemProblemException("'is_available' function needs to be overwritten")

    def validate_test(self, test):
        for parameter in test.tool_parameters.keys():
            if not parameter in self.known_parameters:
                raise ValidationException("Unknown parameter: %s" % parameter)

        return

    def configure(self, config):
        self.config = config
        self.logger = get_logger() # Re-build the logger

    def get_config_item(self, item):
        if not item in self.config:
            raise SystemProblemException("Unknown configuration item requested: %s" % item)
        return self.config[item]

    def build_command_line(self, test):
        raise Exception("build_command_line must be overwritten")

    def run_test(self, test, end_time=None):
        return_code = None
        stdout = ""
        stderr = ""
        bwctl_errors = []
        timed_out = False

        try:
            cmd_line = self.build_command_line(test)

            self.logger.debug("Executing %s" % " ".join(cmd_line))

            p = Popen(cmd_line, shell=False, stdout=PIPE, stderr=PIPE, close_fds=True)
            stdout_pipe = p.stdout
            stderr_pipe = p.stderr

            timeout=None

            if end_time:
                timeout = timedelta_seconds(end_time - datetime.datetime.now())

            while p.poll() == None and (not timeout or timeout > 0):
                (input, output, exceptions) = select.select([ stdout_pipe, stderr_pipe ], [], [], timeout)
                for pipe in input:
                    output = os.read(pipe.fileno(), 1024)
                    if pipe is stdout_pipe:
                        stdout = stdout + output
                    elif pipe is stderr_pipe:
                        stderr = stderr + output

                if end_time:
                    timeout = timedelta_seconds(end_time - datetime.datetime.now())

            # The process wasn't killed, so timeout
            return_code = p.poll()
            if return_code == None:
               return_code = -1
               timed_out = True
               p.terminate()
        except Exception as e:  # XXX: handle this better
            self.logger.debug("Test %s failed: %s" % (test.id, str(e)))

            bwctl_errors.append(SystemProblemException(str(e)).as_bwctl_error())
            return_code = -1

        return self.get_results(test=test, timed_out=timed_out, errors=bwctl_errors, exit_status=return_code, stdout=stdout, stderr=stderr)

    def get_results(self, test=None, timed_out=False, errors=[], exit_status=0, stdout="", stderr=""):
        from bwctl.models import Results

        status = "finished"
        if exit_status != 0 or timed_out:
            status = "failed"

        output = stderr+stdout
        if timed_out:
            output = output + "\nProcess timed out. Killing.\n"

        results={ 'output': stderr+stdout,
                  'command_line': " ".join(self.build_command_line(test))
                }

        self.logger.debug("Test %s %s:\n%s" % (test.id, status, results['output']))

        return Results(status=status, bwctl_errors=errors, results=results)

    def receiver_is_client(self, test):
        """ Returns which side of the test, sender or receiver, will be the
            client. The default is the sender unless the 'receiver_connects'
            option is available, and selected. """

        if "receiver_connects" in self.known_parameters and "receiver_connects" in test.tool_parameters:
            return test.tool_parameters["receiver_connects"]

        return False

    @property
    def port_range(self):
        tool_port_range = '%s_ports' % self.name
        if tool_port_range in self.config and \
            self.config[tool_port_range]:

            return self.config[tool_port_range]

        return self.config['test_ports']

    def duration(self, test):
	""" Returns the test length, a required paramter. If 'duration' or
	    'maximum_duration' isn't an available parameter for this tool, this
            function needs to be overwritten  """

        if 'duration' in test.tool_parameters:
            return test.tool_parameters['duration']
        elif 'maximum_duration' in test.tool_parameters:
            return test.tool_parameters['maximum_duration']
        else:
            raise Exception("Unknown test duration")

    def bandwidth(self, test):
        """ Returns the network bandwidth this test uses. If 'bandwidth' isn't an
            available parameter for this tool.  """

        if 'bandwidth' in test.tool_parameters:
            return test.tool_parameters['bandwidth']
        else:
            return 0
