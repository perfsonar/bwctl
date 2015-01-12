import datetime
import os
import select
from subprocess import Popen, PIPE
import time
from bwctl.utils import timedelta_seconds

class CmdResults:
    def __init__(self, start_time=None, end_time=None, return_code=0, stdout="", stderr=""):
        self.start_time = start_time
        self.end_time   = end_time
        self.return_code = return_code
        self.stdout     = stdout
        self.stderr     = stderr

class CmdRunner:
    def __init__(self, start_time=None, end_time=None, cmd_line=[]):
        self.start_time = start_time
        self.end_time   = end_time
        self.cmd_line   = map(lambda x: str(x), cmd_line)

        self.results = None

    def run_cmd(self):
        return_code = None
        stdout = ""
        stderr = ""
        actual_start_time = None
        actual_end_time = None

        try:
            # Time to pause before spawning the test
            now = datetime.datetime.now()

            if now < self.start_time:
                sleep_time = timedelta_seconds(self.start_time - now)
                time.sleep(sleep_time)

            print "Command line: %s" % self.cmd_line

            p = Popen(self.cmd_line, shell=False, stdout=PIPE, stderr=PIPE, close_fds=True)
            stdout_pipe = p.stdout
            stderr_pipe = p.stderr

            if self.end_time:
                timeout = timedelta_seconds(self.end_time - datetime.datetime.now())

            actual_start_time = datetime.datetime.now()

            while p.poll() == None and (not timeout or timeout > 0):
                (input, output, exceptions) = select.select([ stdout_pipe, stderr_pipe ], [], [], timeout)
                for pipe in input:
                    output = os.read(pipe.fileno(), 1024)
                    if pipe is stdout_pipe:
                        stdout = stdout + output
                    elif pipe is stderr_pipe:
                        stderr = stderr + output

                timeout = timedelta_seconds(self.end_time - datetime.datetime.now())

            actual_end_time = datetime.datetime.now()

            # The process wasn't killed, so timeout
            return_code = p.poll()
            if return_code == None:
               return_code = -1
               p.terminate()

        except Exception as e:  # XXX: handle this better
            stdout = stdout + "\n" + str(e)
            return_code = -1

        results = CmdResults(start_time=actual_start_time, end_time=actual_end_time, return_code=return_code, stdout=stdout, stderr=stderr)

        return results
