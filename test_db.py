import os
import sys
import time

import threading

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from tempfile import mkstemp

from bwctl.db.models import Base, Endpoint

db_str = "sqlite:///:memory:"
#db_str = "sqlite:///test.db"
engine = create_engine(db_str, echo=True)

print "DB Str: %s" % db_str

# get a handle on the metadata
metadata = Base.metadata
metadata.create_all(engine)

Session = scoped_session(sessionmaker(bind=engine))
 
class childThread (threading.Thread):
    def __init__(self, name, session_factory):
        threading.Thread.__init__(self)
        self.name = name
        self.session_factory = session_factory

    def run(self):
        self.session = self.session_factory()

        endpoint = Endpoint()
        endpoint.address = "192.168.1.100-%s" % self.name
        endpoint.test_port = 5001
        endpoint.bwctl_protocol = 2.0
        endpoint.peer_port = 4824
        endpoint.base_path = "/bwctl"
        endpoint.test_id   = "1234"

        print "%s adding a new endpoint" % self.name

        self.session.add(endpoint)
        self.session.commit()

        #time.sleep(2)

        for instance in self.session.query(Endpoint).order_by(Endpoint.id):
            print self.name, instance.address, instance.test_port

        self.session.close()

thread1 = childThread("thread-1", Session)
thread2 = childThread("thread-2", Session)
thread3 = childThread("thread-3", Session)

thread1.start()
thread2.start()
thread3.start()

time.sleep(10)
