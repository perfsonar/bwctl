from bwctl.models import Test, Results
from bwctl.tests_db import TestsDB

test_db = TestsDB()

test_ids = []

for i in range(1, 4):
    test = Test()

    test_id = test_db.add_test(test)
    test_ids.append(test_id)

for test_id in test_ids:
    test = test_db.get_test(test_id)

    print "Test(%s): %s" % (test_id, test.to_json())

for test_id in test_ids:
    results = Results()

    test_db.add_results(test_id, results)

for test_id in test_ids:
    results = test_db.get_results(test_id)

    print "Test(%s): %s" % (test_id, results.to_json())
