import datetime

from threading import RLock

from bwctl.tools import ToolTypes
from bwctl.exceptions import NoAvailableTimeslotException
from bwctl.utils import get_logger

class TimeSlotTypes:
    ANY           = 0
    THROUGHPUT    = 1
    LATENCY       = 2

class ReservationTime:
    def __init__(self, reservation_start_time=None, reservation_end_time=None, test_start_time=None):
        self.reservation_start_time=reservation_start_time
        self.reservation_end_time=reservation_end_time
        self.test_start_time=test_start_time

    def overlaps(self, other):
        if self.reservation_start_time > other.reservation_end_time:
            return False

        if other.reservation_start_time > self.reservation_end_time:
            return False

        return True

class TimeSlot:
    def __init__(self, start_time=0, end_time=0, num_tests=0, max_tests=30):
        self.type      = TimeSlotTypes.ANY
        self.start_time     = start_time
        self.end_time       = end_time
        self.tests     = []
        self.num_tests = num_tests
        self.max_tests = max_tests

    def add_test(self, test):
        assert test.id

        if test.test_type == ToolTypes.THROUGHPUT:
            self.type = ToolTypes.THROUGHPUT
        elif test.test_type == ToolTypes.LATENCY:
            self.type = ToolTypes.LATENCY

        self.num_tests = self.num_tests + 1
        self.tests.append(test.id)

    def remove_test(self, test):
        if self.has_test(test):
            self.num_tests = self.num_tests - 1
            self.tests.remove(test.id)

    def split(self, time):
        new_slot = TimeSlot()
        new_slot.start_time = time
        new_slot.end_time = self.end_time
        new_slot.type = self.type
        new_slot.max_tests = self.max_tests
        new_slot.num_tests = self.num_tests
        new_slot.tests = self.tests[:]

        self.end_time = new_slot.start_time - datetime.timedelta(microseconds=1)

        return new_slot

    def has_test(self, test):
        if test.id in self.tests:
            return True

        return False

    def can_handle_test(self, test):
        if test.test_type == ToolTypes.THROUGHPUT:
            if self.type == TimeSlotTypes.LATENCY or self.type == TimeSlotTypes.THROUGHPUT:
                return False
        elif test.test_type == ToolTypes.LATENCY:
            if self.type == TimeSlotTypes.THROUGHPUT:
                return False

        if self.num_tests == self.max_tests:
            return False

        return True

def locked(f):
    def inner(self, *args, **kwargs):
        with self.lock:
            return f(self, *args, **kwargs)
    return inner

class Scheduler:
    def __init__(self):
        self.lock = RLock()
        self.time_slots = []
        self.logger = get_logger()

    @locked
    def add_test(self, test):
        # Make sure that we can start the test later than the minimum start
        # time. The idea is that we'll give the client some time to do the
        # back-and-forth of coordinating the test with the other server as well
        # as this server to validate the test and whatnot. XXX: Currently, this
	# is 2 seconds out, but it might make sense to see about a lower bound.
        test_min_start_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=2)
        if test.scheduling_parameters.latest_acceptable_time < test_min_start_time:
            raise NoAvailableTimeslotException

        server_time_offset = datetime.timedelta(seconds=test.fuzz)
        if not test.local_client:
            # We want the test to start at the requested time. The client will
	    # start at the test start time, but the server will start listening
	    # a half second or so before that to account for startup time
	    # differences between the client and the server.
            server_time_offset = server_time_offset + datetime.timedelta(seconds=0.5)

        # The reservation length is slightly longer than the test duration to
        # account for the "fuzziness" of time, and a tacked on half second for
        # the tool to finish up processing.
        reservation_length = datetime.timedelta(seconds=test.fuzz + test.duration + 0.5)

        reservation_start_time = test.scheduling_parameters.requested_time - server_time_offset
        reservation_end_time = reservation_start_time + server_time_offset + reservation_length

        reservation_max_start_time = test.scheduling_parameters.latest_acceptable_time
        if reservation_max_start_time:
            reservation_max_start_time = reservation_max_start_time - server_time_offset

        added = False

        for index, ts in enumerate(self.time_slots):
            if reservation_max_start_time and reservation_max_start_time < reservation_start_time:
                raise NoAvailableTimeslotException

            if ts.end_time < reservation_start_time:
                continue

            # If this slot starts after our test ends, we just add a new
            # time slot covering this test since it doesn't overlap any
            # reservations.
            if reservation_end_time < ts.start_time and (index == 0 or reservation_start_time > self.time_slots[index - 1].start_time):
                new_ts = TimeSlot(start_time=reservation_start_time, end_time=reservation_end_time)
                new_ts.add_test(test)

                self.time_slots.insert(index, new_ts)

                added = True
                break

	    # Skip this slot if it's already full, or otherwise can't handle
	    # the test
            if not ts.can_handle_test(test):
                reservation_start_time = ts.end_time + datetime.timedelta(microseconds=1)
                reservation_end_time = reservation_start_time + server_time_offset + reservation_length
                continue

	    # Using the current slot as a starting point, check whether it's
	    # possible to run the test by going through all the slots that
	    # overlap the reservation, and make sure they're all copacetic with
	    # this test before performed as well.
	    overlap_slots = []
	    overlap_index = index
	    conflicting_slot = None

	    while overlap_index < len(self.time_slots):
	        curr_ts = self.time_slots[overlap_index]

	        if reservation_end_time < curr_ts.start_time:
	            break

	        if not curr_ts.can_handle_test(test):
	            conflicting_slot = curr_ts
	            break

	        overlap_slots.append(curr_ts)

	        overlap_index = overlap_index + 1

            # The test can't work with the current start_time time because a
	    # timeslot somewhere conflicts with it, skip ahead past the
	    # conflicting time slot.
	    if conflicting_slot:
	        reservation_start_time = conflicting_slot.end_time + datetime.timedelta(microseconds=1)
	        reservation_end_time   = reservation_start_time + server_time_offset + reservation_length
	        continue

	    # From here on out, we're overlapping the slots in overlap slots.

	    if overlap_slots[0].start_time < reservation_start_time:
	        new_slot = overlap_slots[0].split(time=reservation_start_time)

	        # Add the new slot into the overlap slots
	        overlap_slots.pop(0)
	        overlap_slots.insert(0, new_slot)

	        # Add the new slot into the time slots list
	        self.time_slots.insert(index + 1, new_slot)
	    elif overlap_slots[0].start_time > reservation_start_time:
                new_slot = TimeSlot(start_time=reservation_start_time, end_time=overlap_slots[0].start_time - datetime.timedelta(microseconds=1))

		# Add the new slot into the overlap list, and the time slots
		# list
	        overlap_slots.insert(0, new_slot)
	        self.time_slots.insert(index, new_slot)

	    if overlap_slots[len(overlap_slots) - 1].end_time > reservation_end_time:
	        new_slot = overlap_slots[len(overlap_slots) - 1].split(time=reservation_end_time + datetime.timedelta(microseconds=1))

                # Add the new slot into the overlap slots
	        overlap_slots.pop(len(overlap_slots) - 1)
	        overlap_slots.append(new_slot)

                # Add the new slot into the time slots list
                new_index = index + len(overlap_slots) - 1
	        self.time_slots.insert(new_index, new_slot)
	    elif overlap_slots[len(overlap_slots) - 1].end_time < reservation_end_time:
	        new_slot = TimeSlot(start_time=overlap_slots[len(overlap_slots) - 1].start_time + datetime.timedelta(microseconds=1), end_time=reservation_end_time)

                # Add the new slot into the overlap slots
	        overlap_slots.append(new_slot)

                # Add the new slot into the time slots list
                new_index = index + len(overlap_slots)
	        self.time_slots.insert(new_index, new_slot)

	    for overlap_ts in overlap_slots:
	        overlap_ts.add_test(test)

            added = True
	    break

        if reservation_start_time > reservation_max_start_time:
            raise NoAvailableTimeslotException

        if not added:
            new_ts = TimeSlot(start_time=reservation_start_time, end_time=reservation_end_time)
            new_ts.add_test(test)
            self.time_slots.append(new_ts)

        # XXX: check latest time
        self.display_time_slots()

        test_start_time = reservation_start_time + server_time_offset

        return ReservationTime(reservation_start_time=reservation_start_time,
                               reservation_end_time=reservation_end_time,
                               test_start_time=test_start_time)

    @locked
    def remove_test(self, test):
        # Remove the test from the list
        for ts in self.time_slots:
            ts.remove_test(test)

        # Remove empty time slots
        self.time_slots[:] = [ ts for ts in self.time_slots if ts.num_tests > 0 ]

        self.display_time_slots()

        return True

    def display_time_slots(self):
        self.logger.debug("Timeslots")
        for index, ts in enumerate(self.time_slots):
            self.logger.debug("Slot %d) %s - %s: %s" % (index, ts.start_time, ts.end_time, ",".join(ts.tests)))
