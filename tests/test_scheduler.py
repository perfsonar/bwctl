from os.path import dirname, realpath, sep, pardir
import sys
sys.path.insert(0, dirname(realpath(__file__)) + sep + pardir)

import unittest

import datetime

from bwctl.exceptions import NoAvailableTimeslotException
from bwctl.models import SchedulingParameters
from bwctl.tools  import ToolTypes
from bwctl.server.scheduler import Scheduler

import uuid

class MockScheduledTest(object):
  """A simplified test representation that has everything the scheduler uses"""
  def __init__(self, id=str(uuid.uuid4()), test_type=ToolTypes.UNKNOWN, duration=10, 
               local_client=False, fuzz=0.2, requested_time=None,
               latest_acceptable_time=None):

    self.id = id
    self.test_type = test_type
    self.duration = duration
    self.local_client = local_client
    self.fuzz = fuzz
    self.scheduling_parameters = SchedulingParameters(requested_time=requested_time,
                                                      latest_acceptable_time=latest_acceptable_time)


class SchedulerTest(unittest.TestCase):
  def test_schedule(self):
    requested_time = datetime.datetime.utcnow()
    latest_time = requested_time + datetime.timedelta(seconds=5)

    test = MockScheduledTest(test_type=ToolTypes.THROUGHPUT,
                             requested_time=requested_time,
                             latest_acceptable_time=latest_time
                            )
    scheduler = Scheduler()
    results = scheduler.add_test(test)

    self.assertTrue(results.reservation_start_time <= results.test_start_time)
    self.assertTrue(results.test_start_time < results.reservation_end_time)
    self.assertTrue(results.test_start_time < results.reservation_end_time)

    self.assertTrue(requested_time <= results.test_start_time)
    self.assertTrue(results.test_start_time <= latest_time)

  def test_remove(self):
    requested_time = datetime.datetime.utcnow()
    latest_time = requested_time + datetime.timedelta(seconds=5)

    test = MockScheduledTest(test_type=ToolTypes.THROUGHPUT,
                             requested_time=requested_time,
                             latest_acceptable_time=latest_time
                            )
    scheduler = Scheduler()
    results = scheduler.add_test(test)

    self.assertTrue(scheduler.remove_test(test))

  def test_schedule_throughput_no_overlap(self):
    requested_time = datetime.datetime.utcnow()
    latest_time = requested_time + datetime.timedelta(seconds=5)

    test1 = MockScheduledTest(test_type=ToolTypes.THROUGHPUT,
                              requested_time=requested_time,
                              latest_acceptable_time=latest_time,
                              duration=2
                             )
    test2 = MockScheduledTest(test_type=ToolTypes.THROUGHPUT,
                              requested_time=requested_time,
                              latest_acceptable_time=latest_time,
                              duration=2
                             )

    scheduler = Scheduler()
    results1 = scheduler.add_test(test1)
    results2 = scheduler.add_test(test2)

    self.assertFalse(results1.overlaps(results2))

  def test_schedule_throughput_latency_no_overlap(self):
    requested_time = datetime.datetime.utcnow()
    latest_time = requested_time + datetime.timedelta(seconds=5)

    test1 = MockScheduledTest(test_type=ToolTypes.LATENCY,
                              requested_time=requested_time,
                              latest_acceptable_time=latest_time,
                              duration=2
                             )
    test2 = MockScheduledTest(test_type=ToolTypes.THROUGHPUT,
                              requested_time=requested_time,
                              latest_acceptable_time=latest_time,
                              duration=2
                             )

    scheduler = Scheduler()
    results1 = scheduler.add_test(test1)
    results2 = scheduler.add_test(test2)

    self.assertFalse(results1.overlaps(results2))

  def test_schedule_throughput_traceroute_overlap(self):
    requested_time = datetime.datetime.utcnow()
    latest_time = requested_time + datetime.timedelta(seconds=5)

    test1 = MockScheduledTest(test_type=ToolTypes.TRACEROUTE,
                              requested_time=requested_time,
                              latest_acceptable_time=latest_time,
                              duration=10
                             )
    test2 = MockScheduledTest(test_type=ToolTypes.THROUGHPUT,
                              requested_time=requested_time,
                              latest_acceptable_time=latest_time,
                              duration=10
                             )

    scheduler = Scheduler()
    results1 = scheduler.add_test(test1)
    results2 = scheduler.add_test(test2)

    self.assertTrue(results1.overlaps(results2))

  def test_schedule_latency_traceroute_overlap(self):
    requested_time = datetime.datetime.utcnow()
    latest_time = requested_time + datetime.timedelta(seconds=5)

    test1 = MockScheduledTest(test_type=ToolTypes.TRACEROUTE,
                              requested_time=requested_time,
                              latest_acceptable_time=latest_time,
                              duration=10
                             )
    test2 = MockScheduledTest(test_type=ToolTypes.LATENCY,
                              requested_time=requested_time,
                              latest_acceptable_time=latest_time,
                              duration=10
                             )

    scheduler = Scheduler()
    results1 = scheduler.add_test(test1)
    results2 = scheduler.add_test(test2)

    self.assertTrue(results1.overlaps(results2))

  def test_schedule_no_available_timeslots(self):
    requested_time = datetime.datetime.utcnow()
    latest_time = requested_time + datetime.timedelta(seconds=5)

    test1 = MockScheduledTest(test_type=ToolTypes.THROUGHPUT,
                               requested_time=requested_time,
                               latest_acceptable_time=latest_time,
                               duration=10
                              )

    test2 = MockScheduledTest(test_type=ToolTypes.THROUGHPUT,
                               requested_time=requested_time,
                               latest_acceptable_time=latest_time,
                               duration=10
                              )
    scheduler = Scheduler()
    results1 = scheduler.add_test(test1)

    no_timeslot = False
    try:
      results2 = scheduler.add_test(test2)
    except NoAvailableTimeslotException as e:
      no_timeslot = True

    self.assertTrue(no_timeslot)

  def test_schedule_latency_overlap(self):
    requested_time = datetime.datetime.utcnow()
    latest_time = requested_time + datetime.timedelta(seconds=30)

    scheduler = Scheduler()

    prev_time_range = None

    i = 0
    while i < 10:
      test = MockScheduledTest(
                               test_type=ToolTypes.LATENCY,
                               requested_time=requested_time + datetime.timedelta(seconds=i),
                               latest_acceptable_time=latest_time,
                               duration=10
                              )

      results = scheduler.add_test(test)
      if prev_time_range:
        self.assertTrue(results.overlaps(prev_time_range))

      prev_time_range = results
      i = i + 1



if __name__ == "__main__":
  unittest.main()
