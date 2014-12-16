import uuid

class TestsDB:
    def __init__(self):
        self.tests        = {}
        self.test_results = {}

    def _copy_obj(self, obj):
        return obj.__class__(obj.to_json())

    def get_test(self, test_id):
        if not test_id in self.tests.keys():
            raise Exception("Test not found")

        return self._copy_obj(self.tests[test_id])

    def add_test(self, test):
        test = self._copy_obj(test)

        if not test.id:
            test.id = str(uuid.uuid4())

        if test.id in self.tests.keys():
            return None

        self.tests[test.id] = test

        return test.id

    def add_results(self, test_id, results):
        results = self._copy_obj(results)

        if not test_id in self.tests.keys():
            return False

        if test_id in self.test_results.keys():
            return False

        self.test_results[test_id] = results

        return True

    def get_results(self, test_id):
        print "Test ID(results): %s" % test_id

        if not test_id in self.test_results.keys():
            raise Exception("Test results not found")

        return self._copy_obj(self.test_results[test_id])
