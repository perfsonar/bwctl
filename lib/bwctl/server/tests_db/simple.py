import uuid
from bwctl.exceptions import ResourceNotFoundException

from threading import Lock

from .base import Base

def locked(f):
    def inner(self, *args, **kwargs):
        with self.lock:
            return f(self, *args, **kwargs)
    return inner

class SimpleDB(Base):
    def __init__(self):
        self.lock         = Lock()
        self.tests        = {}
        self.test_results = {}

    def _copy_obj(self, obj):
        return obj.__class__(obj.to_json())

    @locked
    def get_test(self, test_id):
        if not test_id in self.tests.keys():
            raise ResourceNotFoundException("Test not found")

        return self._copy_obj(self.tests[test_id])

    @locked
    def add_test(self, test):
        test = self._copy_obj(test)

        if not test.id:
            test.id = str(uuid.uuid4())

        if test.id in self.tests.keys():
            return None

        self.tests[test.id] = test

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
