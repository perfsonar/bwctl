from os.path import dirname, realpath, sep, pardir
import sys
sys.path.insert(0, dirname(realpath(__file__)) + sep + pardir)

import unittest

from bwctl.port_range import PortRange

class PortRangeTest(unittest.TestCase):
  """Unit tests for the Port Range module"""

  def test_port_range(self):
    min = 1
    max = 5
    total = max - min + 1

    port_range = PortRange(min=min, max=max)

    # Try to get all the available ports
    requested = 0
    while requested < total:
        port = port_range.get_port()

        self.assertTrue(port <= max)
        self.assertTrue(port >= min)
        requested = requested + 1

    # Try to get a port after the range is full
    failed = False
    try:
        port = port_range.get_port()
    except:
        failed = True

    self.assertTrue(failed)

    # Release all the ports
    i = min
    while i <= max:
       port_range.release_port(i)
       i = i + 1

    # Request all the ports again
    requested = 0
    while requested < total:
        port = port_range.get_port()

        self.assertTrue(port <= max)
        self.assertTrue(port >= min)
        requested = requested + 1

    # Free the last port, it will be the only one open so we'll make sure that
    # we get assigned that port again since it's the only one free.
    port_range.release_port(port)

    new_port = port_range.get_port()
    self.assertEqual(new_port, port)

if __name__ == "__main__":
  unittest.main()
