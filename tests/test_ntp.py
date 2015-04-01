from os.path import dirname, realpath, sep, pardir
import sys
sys.path.insert(0, dirname(realpath(__file__)) + sep + pardir)

import unittest

from bwctl.ntp import ntp_adjtime

class NTPTest(unittest.TestCase):
  """Unit tests for the NTP utility library"""

  def setUp(self):
    self.timex = ntp_adjtime()

    self.assertNotEqual(self.timex, None)

  def test_synchronized(self):
    self.assertTrue(self.timex.synchronized)

  def test_offset_sec(self):
    self.assertNotEqual(self.timex.offset_sec, 0)

  def test_maxerror_sec(self):
    self.assertNotEqual(self.timex.maxerror_sec, 0)

if __name__ == "__main__":
  unittest.main()
