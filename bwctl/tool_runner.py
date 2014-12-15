import datetime
import multiprocessing
import os
import psutil
import select
from subprocess import Popen, PIPE
import time
from bwctl.utils import timedelta_seconds, BwctlProcess

# Generate a separate process to run the test itself so that we
# pseudo-guarantee that the test will start at the right time.
class ToolResults(object):
    def __init__(self, test_id=None, return_code=0, stdout="", stderr=""):
        self.test_id    = test_id
        self.return_code = return_code
        self.stdout     = stdout
        self.stderr     = stderr

class ToolRunner(BwctlProcess):
    def __init__(self, test_id=None, start_time=None, end_time=None, cmd_line=[], results_queue=None):
        self.start_time    = start_time
        self.end_time      = end_time
        self.cmd_line      = cmd_line
        self.test_id       = test_id
        self.results_queue = results_queue
        stop_pipe          = multiprocessing.Pipe()

        self.stop_pipe_client = stop_pipe[0]
        self.stop_pipe_server = stop_pipe[1]

        super(ToolRunner, self).__init__()

    def run(self):
        return_code = None
        stdout = ""
        stderr = ""

        try:
            # Time to pause before spawning the test
            now = datetime.datetime.now()

            if now < self.start_time:
                sleep_time = timedelta_seconds(self.start_time - now)
                time.sleep(sleeptime)

            p = Popen(self.cmd_line, shell=False, stdout=PIPE, stderr=PIPE, close_fds=True)
            stdout_pipe = p.stdout
            stderr_pipe = p.stderr

            if self.end_time:
                timeout = timedelta_seconds(self.end_time - datetime.datetime.now())

            while p.poll() == None and (not timeout or timeout > 0):
                (input, output, exceptions) = select.select([ stdout_pipe, stderr_pipe, self.stop_pipe_server ], [], [], timeout)
                for pipe in input:
                    output = os.read(pipe.fileno(), 1024)
                    if pipe is stdout_pipe:
                        stdout = stdout + output
                    elif pipe is stderr_pipe:
                        stderr = stderr + output

                if self.stop_pipe_server in input:
                    # XXX: handle the terminated early better
                    break

                timeout = timedelta_seconds(self.end_time - datetime.datetime.now())

            # The process wasn't killed, so timeout
            return_code = p.poll()
            if return_code == None:
               return_code = -1

            # Kill off any children
            self.kill_children()
        except:  # XXX: handle this better
            return_code = -1

        results = ToolResults(test_id=self.test_id, return_code=return_code, stdout=stdout, stderr=stderr)

        self.results_queue.put(results)

    def stop(self):
        self.stop_pipe_client.send_bytes('1')
