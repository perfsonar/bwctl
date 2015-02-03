import datetime
import time

from bwctl.utils import BwctlProcess, timedelta_seconds
from bwctl.models import Results
from bwctl.exceptions import SystemProblemException, BwctlException

class ToolRunner(BwctlProcess):
    def __init__(self, test=None, results_cb=None):
        super(ToolRunner, self).__init__()

        self.test = test
        self.results_cb = results_cb

        if test.local_client:
            self.start_time = test.scheduling_parameters.test_start_time
        else:
            self.start_time = test.scheduling_parameters.reservation_start_time

        self.end_time = test.scheduling_parameters.reservation_end_time

        print "Duration: %s" % (timedelta_seconds(self.end_time - self.start_time))

    def run(self):
        test_results = None

        try:
            if self.start_time:
                sleep_time = timedelta_seconds(self.start_time - datetime.datetime.now())
                if sleep_time < 0:
                    raise TestStartTimeFailure

                time.sleep(sleep_time)

            print "Run test: %s" % datetime.datetime.now()

            test_results = self.test.tool_obj.run_test(self.test, end_time=self.end_time)

            print "Finished run test: %s" % datetime.datetime.now()
        except BwctlException as e:
            err = e.as_bwctl_error()
            test_results = Results(status="failed", bwctl_errors=[ err.as_bwctl_error() ])
        except Exception as e:
            err = SystemProblemException(str(e))
            test_results = Results(status="failed", bwctl_errors=[ err.as_bwctl_error() ])

        self.results_cb(test_results)

        return results
