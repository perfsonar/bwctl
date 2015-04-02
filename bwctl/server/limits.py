import copy
import datetime
import radix
import re

from bwctl.tools import ToolTypes
from bwctl.exceptions import LimitViolatedException
from bwctl.utils import is_loopback, timedelta_seconds

# Limit Definitions
class Limit(object):
    type = ""
    default_value = None

    def __init__(self, value, default=False, override_children=False):
        self.value = value
        self.default = default
        self.override_children = override_children

    def parse_string(self, value):
        raise Exception("Can't parse string values")

    def __str__(self):
        if self.default:
            return "%s: %s*" % (self.type, self.value)
        else:
            return "%s: %s" % (self.type, self.value)

    def check(self, test):
        return True

    def merge(self, other):
        raise Exception("")

    def duplicate(self):
        return copy.copy(self)

    @classmethod
    def get_subclasses(cls):
        subclasses = cls.__subclasses__()
        for subclass in subclasses:
            subclasses.extend(subclass.get_subclasses())

        return subclasses

class NumberLimit(Limit):
    def __init__(self, value, default=False):
        value = int(value)

        super(NumberLimit, self).__init__(value, default=default)

class BooleanLimit(Limit):
    def __init__(self, value, default=False):
        # Convert the boolean from a string of 'on' or 'off' to a boolean
        # attribute
        if value == "on":
            value = True
        elif value == "off":
            value = False
        else:
            raise ValidationException("Must be one of 'on' or 'off': %s" % value)

        super(BooleanLimit, self).__init__(value, default=default)

    def merge(self, other):
        if not other.value:
            self.value = False

class MinimumLimit(NumberLimit):
    def merge(self, other):
        if other.value > self.value:
            self.value = other.value

class MaximumLimit(NumberLimit):
    def merge(self, other):
        if other.value < self.value:
            self.value = other.value

class BandwidthLimit(MaximumLimit):
    """ The maximum bandwidth a test can have
    """
    type = "bandwidth"
    default_value = "0"

    def __init__(self, value, default=False):
        m = re.match("([0-9]+)([bBmMkKgG]?)", value)
        if m:
            value  = int(m.group(0))
            unit   = m.group(1)

            if unit in [ 'k', 'K' ]:
                value = value * 1000
            elif unit in [ 'm', 'M' ]:
                value = value * 1000 * 1000
            elif unit in [ 'g', 'G' ]:
                value = value * 1000 * 1000 * 1000
        else:
            raise ValidationException("Invalid bandwidth: %s" % value)

        super(BandwidthLimit, self).__init__(value, default=default)

    def check(self, test):
       if self.value and self.value < test.bandwidth:
           raise LimitViolatedException("Bandwidth exceeds maximum: %s" % self.value)

class DurationLimit(MaximumLimit):
    """ The maximum duration a test can have
    """
    type = "duration"
    default_value = "60"

    def check(self, test):
       if self.value < test.duration:
           raise LimitViolatedException("Duration exceeds maximum: %s" % self.value)

class PacketsPerSecondLimit(MaximumLimit):
    """ The maximum number of packets per second a test may have
    """
    type = "packets_per_second"
    default_value = "200"

    def check(self, test):
       if self.value < test.packets_per_second:
           raise LimitViolatedException("Packet-per-second exceeds maximum: %s" % self.value)

class EventHorizonLimit(MaximumLimit):
    """ The maximum number of seconds into the future that a test may be
        scheduled
    """
    type = "event_horizon"
    default_value = "300"

    def check(self, test):
       if test.scheduling_parameters and test.scheduling_parameters.test_start_time:
           time_till_test = test.scheduling_parameters.test_start_time - datetime.datetime.utcnow()
           if timedelta_seconds(time_till_test) > self.value:
               raise LimitViolatedException("Test too far in the future. Maximum seconds in future: %s" % self.value)

class AllowUDPLimit(BooleanLimit):
    """ Whether or not UDP throughput tests are allowed
    """
    type = "allow_udp_throughput"
    default_value = "off"

    def check(self, test):
       if test.test_type == ToolTypes.THROUGHPUT:
           protocol = test.tool_parameters.get("protocol", "tcp")
           if protocol == "udp" and not self.value:
               raise LimitViolatedException("UDP throughput tests not allowed")

class AllowEndpointlessLimit(BooleanLimit):
    """ Allow reservations where the remote side does not have an endpoint, and
        won't post it's status. This is a potentially dangerous setting because
        bwctl will unilaterally do a test based solely on the say-so of the
        client.
    """
    type = "allow_no_endpoint"
    default_value = "off"

    def check(self, test):
       if not test.remote_endpoint.bwctl_protocol and not self.value:
           raise LimitViolatedException("Remote endpoint must be running bwctl")

class BannedLimit(BooleanLimit):
    """ Whether or not a given user or network is banned from requesting tests.
    """
    type = "banned"
    default_value = "off"

    def check(self, test):
       if self.value:
           raise LimitViolatedException("No tests allowed")

class LimitsDB(object):
    """ A database of limits """
    def __init__(self):
        self.classes  = {}
        self.users    = {}
        self.networks = radix.Radix()
        self.default_limit_class = None
        self.loopback_limit_class = None

        self.system_default_limits = LimitClass()

        # Set some sane defaults for so that people don't accidently stand up
        # UDP packet cannons. These will be the parent for any classes that
        # don't have one, as well as what a default user gets.
        for limit_class in Limit.get_subclasses():
            if not limit_class.default_value:
                continue

            limit = limit_class(limit_class.default_value, default=True)
            self.system_default_limits.add_limit(limit)

        # XXX: until we get a file reader for the limits, we'll need this so
        # that regular tests can work.
        self.create_limit_class("loopback")
        self.add_limit("loopback", AllowEndpointlessLimit("on"))
        self.set_loopback_limit_class("loopback")

    def check_test(self, test, address=None, user=None):
        limits = self.get_limits(user=user, address=address, tool=test.tool)

        for limit in limits:
            limit.check(test)

        return

    def create_limit_class(self, limit_class, parent=None):
        if limit_class in self.classes.keys():
            raise Exception("Class %s already exists" % limit_class)

        if parent and not parent in self.classes.keys():
            raise Exception("Parent class %s does not exist" % parent)

        parent_obj = None
        if parent:
            parent_obj = self.classes[parent]
        else:
            parent_obj = self.system_default_limits

        new_class = LimitClass(name=limit_class, parent=parent_obj)

        self.classes[limit_class] = new_class

        return

    def set_default_limit_class(self, limit_class):
        if not limit_class in self.classes.keys():
            raise Exception("Class %s does not exist" % limit_class)

        self.default_limit_class = self.classes[limit_class]

        return

    def set_loopback_limit_class(self, limit_class):
        if not limit_class in self.classes.keys():
            raise Exception("Class %s does not exist" % limit_class)

        limit_class = self.classes[limit_class]

        has_endpointless = False
        for limit in limit_class.get_limits():
            if limit.type == "allow_no_endpoint" and not limit.default:
                has_endpointless = True

        if not has_endpointless:
            # By default, external folks can't do endpointless tests, but loopback
            # users can. This gets around an issue where regular testing didn't
            # work by default.
            limit_class.add_limit(AllowEndpointlessLimit(value=True, default=True))

        self.loopback_limit_class = limit_class

        return

    def add_limit(self, limit_class, limit, tool=""):
        if not limit_class in self.classes.keys():
            raise Exception("Class %s does not exist" % limit_class)

        limit_class_obj = self.classes[limit_class]

        limit_class_obj.add_limit(limit, tool=tool)

        return

    def get_limit_class_by_name(self, limit_class):
        return self.classes[limit_class]

    def get_limit_class(self, user=None, address=None, tool=""):
        # If they're a loopback user, use that limit class, if it exists
        if address and self.loopback_limit_class \
           and is_loopback(address, strict=False):
            return self.loopback_limit_class

        # If they're logged in, use their limit class, if it exists
        if user and user in self.users.keys():
            return self.users[user]

        # If they match an address' limit class, use that
        if address:
            node = self.networks.search_best(address)
            if node and "limit_class" in node.data:
                return node.data['limit_class']

        # If there isn't a user, nor an address class, use the default
        if self.default_limit_class:
            return self.default_limit_class

        # If nothing else, return the overall system default limit set
        return self.system_default_limits

    def get_limits(self, user=None, address=None, tool=""):
        limit_class = self.get_limit_class(user=user, address=address)

        limits = []
        # If they're logged in, use their limit class, if it exists
        if limit_class:
            limits.extend(limit_class.get_limits(tool=tool))

        return limits

    def add_user(self, user, limit_class):
        if not limit_class in self.classes.keys():
            raise Exception("Class %s does not exist" % limit_class)

        if user in self.users.keys():
            raise Exception("User %s already exists" % limit_class)

        self.users[user] = self.classes[limit_class]

        return

    def add_network(self, network, limit_class):
        if not limit_class in self.classes.keys():
            raise Exception("Class %s does not exist" % limit_class)

        node = self.networks.add(network)
        node.data['limit_class'] = self.classes[limit_class]

        return

class LimitClass(object):
    """ A class has multiple limits associated with it """
    def __init__(self, name="", parent=None):
        if parent:
            self.limits = copy.deepcopy(parent.limits)
        else:
            self.limits = {}

        self.name   = name
        self.parent = parent
        self.children = []

        if self.parent:
            self.parent.children.append(self)

    def get_limits(self, tool=""):
        limits = []

        if self.parent:
            limits.extend(self.parent.get_limits(tool=tool))

        for tool_name in [ "", tool ]:
            if not tool_name in self.limits.keys():
                continue

            for limit in self.limits[tool_name]:
                limits = [ x for x in limits if x.type != limit.type ]
                limits.append(limit)

        return limits

    # XXX: minimize the limits set
    def add_limit(self, limit, tool=""):
        #print "Adding %s to %s" % (limit, self.name)

        # Make a copy of the limit
        limit = limit.duplicate()

        if not tool in self.limits:
            self.limits[tool] = []

        self.limits[tool].append(limit)

        return

    def __str__(self):
        return "%s: %s" % ( self.name, ", ".join([str(i) for i in self.get_limits()]) )
