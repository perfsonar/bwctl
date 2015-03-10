from copy import deepcopy

class PortRange:
    def __init__(self, min=1025, max=65536):
        self.min = 1025
        self.max = max
        self.index = min
        self.used = []

    def _next_index(self):
        self.index = (self.index + 1) % (self.max + 1)

        return self.index

    def release_port(self, port):
        self.used.remove(port)

    def get_port(self):
        if len(self.used) == self.max - self.min:
            raise NoAvailablePortsException

        port = self._next_index()
        while port in self.used:
            port = self._next_index()
        self.used.append(port)

        return port

    def copy(self):
        new_range = PortRange(min=self.min, max=self.max)
        new_range.used = deepcopy(self.used)
        return new_range
