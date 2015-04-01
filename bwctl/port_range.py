from copy import deepcopy
from bwctl.exceptions import NoAvailablePortsException

class PortRange:
    def __init__(self, min=1025, max=65536):
        self.min = min
        self.max = max
        self.index = 0
        self.used = []

    def _next_port(self):
        self.index = (self.index + 1) % (self.max - self.min + 1)

        return self.min + self.index

    def release_port(self, port):
        self.used.remove(port)

    def get_port(self):
        if len(self.used) == self.max - self.min + 1:
            raise NoAvailablePortsException

        port = self._next_port()
        while port in self.used:
            port = self._next_port()
        self.used.append(port)

        return port

    def copy(self):
        new_range = PortRange(min=self.min, max=self.max)
        new_range.used = deepcopy(self.used)
        return new_range
