import radix
import copy

class LimitsDB:
    """ A database of limits """
    def __init__(self):
        self.classes  = {}
        self.users    = {}
        self.networks = radix.Radix()
        self.default_limit = None

    def create_limit_class(self, limit_class, parent=None):
        if limit_class in self.classes.keys():
            raise Exception("Class %s already exists" % limit_class)

        if parent and not parent in self.classes.keys():
            raise Exception("Parent class %s does not exist" % parent)

        parent_obj = None
        if parent:
            parent_obj = self.classes[parent]

        new_class = LimitClass(name=limit_class, parent=parent_obj)

        self.classes[limit_class] = new_class

        return

    def set_default_limit_class(self, limit_class):
        if not limit_class in self.classes.keys():
            raise Exception("Class %s does not exist" % limit_class)

        self.default_limit = self.classes[limit_class]

        return

    def add_limit(self, limit_class, limit, tester=""):
        if not limit_class in self.classes.keys():
            raise Exception("Class %s does not exist" % limit_class)

        limit_class_obj = self.classes[limit_class]

        limit_class_obj.add_limit(limit, tester=tester)

        return

    def get_limit_class(self, user=None, address=None, tester=""):
        # If they're logged in, use their limit class, if it exists
        if user and user in self.users.keys():
            return self.users[user]

        # If they match an address' limit class, use that
        if address:
            node = self.networks.search_best(address)
            if node and "limit_class" in node.data:
                return node.data['limit_class']

        # If there isn't a user, nor an address class, use the default
        if self.default_limit:
            return self.default_limit

        return None

    def get_limits(self, user=None, address=None, tester=""):
        limit_class = self.get_limit_class(user=user, address=address)

        limits = []
        # If they're logged in, use their limit class, if it exists
        if limit_class:
            limits.extend(limit_class.get_limits(tester=tester))

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

class LimitClass:
    """ A class has multiple limits associated with it """
    def __init__(self, name="", parent=None):
        self.limits = {}
        self.name   = name
        self.parent = parent
        self.children = []

        if self.parent:
            self.parent.children.append(self)

    def get_limits(self, tester=""):
        limits = []

        if tester in self.limits.keys():
            limits.extend(self.limits[tester])

        if tester != "" and "" in self.limits.keys():
            limits.extend(self.limits[""])

        return limits

    # XXX: minimize the limits set
    def add_limit(self, limit, tester=""):
        print "Adding %s to %s" % (limit, self.name)

        # Make a copy of the limit
        limit = limit.duplicate()

        if not tester in self.limits:
            self.limits[tester] = []

        added = False
        for old_limit in self.limits[tester]:
            if old_limit.name == limit.name:
                print "Merging %s with %s" % (old_limit, limit)
                old_limit.merge(limit)
                added = True

        if not added:
            self.limits[tester].append(limit)

        for child_class in self.children:
            child_class.add_limit(limit, tester=tester)

        return

    def __str__(self):
        return "%s: %s" % ( self.name, ", ".join([str(i) for i in self.get_limits()]) )




# Limit Definitions
class Limit:
    name = ""

    def __str__(self):
        return ""

    def check(self, test):
        return True

    def merge(self, other):
        raise Exception("")

    def duplicate(self):
        return copy.copy(self)

class NumberLimit(Limit):
   def __init__(self, number):
       self.value = number

class MinimumLimit(NumberLimit):
   def merge(self, other):
       if other.value > self.value:
           self.value = other.value

class MaximumLimit(NumberLimit):
   def merge(self, other):
       if other.value < self.value:
           self.value = other.value

class BandwidthLimit(MaximumLimit):
    type = "bandwidth"

    def __str__(self):
        return "bandwidth: %d" % self.value

    def check(self, test):
       raise Exception("Bandwidth limit needs implemented")

class DurationLimit(MaximumLimit):
    name = "duation"

    def __str__(self):
        return "duration: %d" % self.value

    def check(self, test):
       raise Exception("Duration limit needs implemented")

class LimitsFile:
    def parse(file):
        limits_db = LimitsDB()

        with open(file) as fh:
            # Read the limit classes
            for line in fh.readlines():


if __name__ == "__main__":
    limits_db = LimitsDB()
    limits_db.create_limit_class("root")
    limits_db.create_limit_class("default", parent="root")
    limits_db.create_limit_class("jail", parent="root")

    bandwidth_limit = BandwidthLimit(90)
    duration_limit  = DurationLimit(60)
    no_duration_limit  = DurationLimit(1)

    limits_db.add_limit("root", duration_limit)
    limits_db.add_limit("default", bandwidth_limit)
    limits_db.add_limit("jail", no_duration_limit)

    limits_db.add_user("evil_user", "jail")
    limits_db.add_user("good_user", "root")
    limits_db.add_user("other_user", "default")

    limits_db.add_network("192.168.0.0/16", "jail")
    limits_db.add_network("10.0.0.0/8", "default")
    limits_db.add_network("10.0.0.0/16", "root")

    limits_db.add_network("::/0", "jail") # disable all IPv6 tests

    limits_db.set_default_limit_class("default")

    for user in [ "evil_user", "good_user", "other_user", "nonexistent_user" ]:
        limit_class = limits_db.get_limit_class(user=user)

        print "%s limits: %s" % ( user, limit_class )

    for address in [ "192.168.0.8", "10.0.0.1", "10.0.1.1", "10.1.1.1", "::1", "140.232.101.101" ]:
        limit_class = limits_db.get_limit_class(address=address)

        print "%s limits: %s" % ( address, limit_class )
