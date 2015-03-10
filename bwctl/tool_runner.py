import datetime
import time

from bwctl.utils import BwctlProcess, timedelta_seconds, get_logger
from bwctl.models import Results
from bwctl.exceptions import SystemProblemException, BwctlException, TestStartTimeFailure

class ToolRunner(BwctlProcess):
    def __init__(self, test=None, results_cb=None):
        super(ToolRunner, self).__init__()

        self.logger = get_logger()

        self.test = test
        self.results_cb = results_cb

        if test.local_client:
            self.start_time = test.scheduling_parameters.test_start_time
        else:
            self.start_time = test.scheduling_parameters.reservation_start_time

        self.end_time = test.scheduling_parameters.reservation_end_time

    def run(self):
        test_results = None

        try:
            if self.start_time:
                sleep_time = timedelta_seconds(self.start_time - datetime.datetime.utcnow())
                if sleep_time < 0:
                    raise TestStartTimeFailure

                self.logger.debug("Waiting %f seconds before running test %s" % (sleep_time, self.test.id))

                time.sleep(sleep_time)

            test_results = self.test.tool_obj.run_test(self.test, end_time=self.end_time)
        except BwctlException as e:
            self.logger.debug("Test %s failed: %s" % (self.test.id, str(e)))

            test_results = Results(status="failed", bwctl_errors=[ e.as_bwctl_error() ])
        except Exception as e:
            self.logger.debug("Test %s failed: %s" % (self.test.id, str(e)))

            err = SystemProblemException(str(e))
            test_results = Results(status="failed", bwctl_errors=[ err.as_bwctl_error() ])

        self.results_cb(test_results)

        return test_results
