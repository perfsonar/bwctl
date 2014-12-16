import datetime
from bwctl.utils import timedelta_seconds
from bwctl.tool_runner import ToolRunner

debug = True

def run_test(start_time=None, end_time=None, cmd_line=None, timeout=0, callback=None):
    tr = ToolRunner(start_time=start_time, end_time=end_time, cmd_line=cmd_line)
    tr.run()
    results = tr.get_results(timeout=0)
    if callback:
        callback(results)
    if debug:
        print "Results:"
        print " - Command: %s" % " ".join(cmd_line)
        print " - Start Time: %s" % results.start_time
        print " - End Time: %s" % results.end_time
        print " - Return Code: %d" % results.return_code
        print " - Standard Out: %s" % results.stdout
        print " - Standard Err: %s" % results.stderr

def test_succeed():
    start_time=datetime.datetime.now()
    end_time=start_time + datetime.timedelta(seconds=5)
    cmd_line=["ls", "/"]
    def results_cb(results):
        assert results.stdout != ""
        assert results.return_code == 0

    run_test(start_time=start_time, end_time=end_time, cmd_line=cmd_line, callback=results_cb)

def test_failure():
    start_time=datetime.datetime.now()
    end_time=start_time + datetime.timedelta(seconds=5)
    cmd_line=["/sbin/fdsa",]
    def results_cb(results):
        assert results.return_code != 0

    run_test(start_time=start_time, end_time=end_time, cmd_line=cmd_line, callback=results_cb)

def test_timeout():
    start_time=datetime.datetime.now()
    end_time=start_time + datetime.timedelta(seconds=5)
    cmd_line=["/bin/sleep", "30"]
    def results_cb(results):
        assert timedelta_seconds(results.end_time - results.start_time) < 6

    run_test(start_time=start_time, end_time=end_time, cmd_line=cmd_line, callback=results_cb)


test_succeed()
test_failure()
test_timeout()
