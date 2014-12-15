from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relation, backref

class TestTypes:
    UNKNOWN       = 1
    THROUGHPUT    = 2
    LATENCY       = 3
    TRACEROUTE    = 4

Base = declarative_base()

class RequestingClient(Base):
    __tablename__ = 'clients'

    id = Column(Integer, primary_key=True)

    address = Column(String(255))
    bwctl_protocol = Column(Float)

    ntp_error      = Column(Float)
    time_offset    = Column(Float)

class Endpoint(Base):
    __tablename__ = 'endpoints'

    id = Column(Integer, primary_key=True)

    address = Column(String(255))
    test_port = Column(Integer)

    bwctl_protocol = Column(Float)
    peer_port      = Column(Integer)
    base_path      = Column(String(255))
    test_id        = Column(String(255))

    legacy_client_endpoint = Column(Boolean)
    posts_endpoint_status  = Column(Boolean)

    # Figure out if this endpoint is local to this machine
    def is_local(self):
        return False

class Test(Base):
    __tablename__ = 'tests'

    id = Column(Integer, primary_key=True)

    requesting_client_id = Column(Integer, ForeignKey('clients.id'))
    requesting_client = relation(RequestingClient, backref=backref("test", uselist=False),
                                 primaryjoin=(requesting_client_id == RequestingClient.id))

    sender_endpoint_id = Column(Integer, ForeignKey('endpoints.id'))
    sender_endpoint = relation(Endpoint, backref=backref("sender_test", uselist=False),
                                 primaryjoin=(sender_endpoint_id == Endpoint.id))

    receiver_endpoint_id = Column(Integer, ForeignKey('endpoints.id'))
    receiver_endpoint = relation(Endpoint, backref=backref("receiver_test", uselist=False),
                                 primaryjoin=(receiver_endpoint_id == Endpoint.id))

    requested_time    = Column(DateTime)
    latest_time       = Column(DateTime)
    test_duration     = Column(Integer)

    priority          = Column(Integer)

    reservation_start = Column(DateTime)
    test_start        = Column(DateTime)
    reservation_end   = Column(DateTime)

    tool              = Column(String(32))

    def fuzz(self):
        if self.sender_endpoint and self.receiver_endpoint:
            return self.sender_endpoint.client_offset + self.receiver_endpoint.client_offset
        else:
            return 2.0 # default to assuming we're not more than two seconds offset

class ToolParameter(Base):
    __tablename__ = 'tool_parameters'

    id = Column(Integer, primary_key=True)

    test_id = Column(Integer, ForeignKey('tests.id'))
    test = relation(Test, backref=backref('tool_parameters', order_by=id))

    parameter = Column(String(255))
    value     = Column(String(255))
