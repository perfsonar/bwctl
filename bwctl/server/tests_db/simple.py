import uuid
from bwctl.exceptions import ResourceNotFoundException

import threading

from .base import Base

def locked(f):
    def inner(self, *args, **kwargs):
        with self.lock:
            retval = f(self, *args, **kwargs)
            return retval
    return inner

class SimpleDB(Base):
    def __init__(self):
        self.lock         = threading.RLock()
        self.tests        = {}
        self.test_results = {}
        self.test_cvs     = {}
        self.locked_tests = {}

    def _copy_obj(self, obj):
        return obj.__class__(obj.to_json())

    def lock_test(self, test_id):
        if not self.test_cvs[test_id]:
            return

        with self.test_cvs[test_id]:
            while self.locked_tests[test_id] and \
                  self.locked_tests[test_id] != threading.current_thread().name:
                self.test_cvs[test_id].wait()
            self.locked_tests[test_id] = threading.current_thread().name

    def unlock_test(self, test_id):
        if not self.test_cvs[test_id]:
            return

        with self.test_cvs[test_id]:
            self.locked_tests[test_id] = None
            self.test_cvs[test_id].notify()

    @locked
    def get_test(self, test_id):
        if not test_id in self.tests.keys():
            raise ResourceNotFoundException("Test not found: '%s'" % test_id)

        return self._copy_obj(self.tests[test_id])

    @locked
    def add_test(self, test):
        test = self._copy_obj(test)

        if not test.id:
            test.id = str(uuid.uuid4())

        if test.id in self.tests.keys():
            return None

        self.tests[test.id] = test

        self.locked_tests[test.id] = False
        self.test_cvs[test.id] = threading.Condition(self.lock)

        return test.id

    @locked
    def replace_test(self, test_id, test):
        if not test_id in self.tests.keys():
            raise ResourceNotFoundException("Test not found")

        test = self._copy_obj(test)

        self.tests[test_id] = test

        return test_id

    @locked
    def add_results(self, test_id, results):
        results = self._copy_obj(results)

        if not test_id in self.tests.keys():
            return False

        if test_id in self.test_results.keys():
            return False

        self.test_results[test_id] = results

        return True

    @locked
    def get_results(self, test_id):
        if not test_id in self.test_results.keys():
            raise ResourceNotFoundException("Test results not found")

        return self._copy_obj(self.test_results[test_id])
