from bwctl.protocol.models import *
import uuid

test = Test()
test.id = str(uuid.uuid1())
print test.to_json()
