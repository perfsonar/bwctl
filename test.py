from bwctl.models import Test
import json

f = open('test.json', 'r')
test_json = json.load(f)
test = Test(test_json)
print test

