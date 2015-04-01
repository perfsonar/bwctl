from os.path import dirname, realpath, sep, pardir
import sys
sys.path.insert(0, dirname(realpath(__file__)) + sep + pardir)

import unittest
import datetime

from bwctl.utils import is_ipv6, ip_matches, get_ip
from bwctl.utils import timedelta_seconds
from bwctl.utils import urljoin

class TimeTest(unittest.TestCase):
  """Unit tests for the Time functions in the utils library"""
  def test_timedelta_seconds_no_microseconds(self):
    dt = datetime.timedelta(seconds=2)
    self.assertEqual(2.0, timedelta_seconds(dt))

  def test_timedelta_seconds_microseconds(self):
    dt = datetime.timedelta(microseconds=500000)
    self.assertEqual(0.5, timedelta_seconds(dt))

class URLTest(unittest.TestCase):
  """Unit tests for the URL functions in the utils library"""
  def test_urljoin(self):
    url = urljoin("/test", "123", "456")
    self.assertEqual(url, "/test/123/456")

class IPTest(unittest.TestCase):
  """Unit tests for the IP functions in the utils library"""

  def test_is_ipv6_ipv4_address(self):
    self.assertFalse(is_ipv6("127.0.0.1"))

  def test_is_ipv6_ipv6_address(self):
    self.assertTrue(is_ipv6("::1"))

  def test_is_ipv6_ipv6_mapped_address(self):
    self.assertTrue(is_ipv6("::ffff:192.168.1.1"))

  def test_is_ipv6_ipv6_link_local(self):
    self.assertTrue(is_ipv6("fe80::1aa9:5ff:fe1a:b913"))

  def test_is_ipv6_ipv6_public(self):
    self.assertTrue(is_ipv6("2001:48a8:68fe:ffff:1aa9:5ff:fe1a:b913"))

  def test_get_ip_require_ipv4(self):
    address = get_ip("www.google.com", require_ipv4=True)
    self.assertFalse(is_ipv6(address))

  def test_get_ip_require_ipv6(self):
    address = get_ip("www.google.com", require_ipv6=True)
    self.assertTrue(is_ipv6(address))

  def test_get_ip_prefer_ipv6(self):
    # Google has a v6 address, so this should return the v6 address
    address = get_ip("www.google.com", prefer_ipv6=True)
    self.assertTrue(is_ipv6(address))

  def test_get_ip_require_ipv4_failure(self):
    # ESnet has some addresses that can be guaranteed to resolve to v4 or v6
    address = get_ip("chic-pt1-v6.es.net", require_ipv4=True)
    self.assertEqual(address, None)

  def test_get_ip_require_ipv6_failure(self):
    address = get_ip("chic-pt1-v4.es.net", require_ipv6=True)
    self.assertEqual(address, None)

  def test_get_ip_prefer_ipv6_no_ipv6(self):
    address = get_ip("chic-pt1-v4.es.net", prefer_ipv6=True)
    self.assertNotEqual(address, None)

  def test_ip_matches_ipv4_success(self):
    self.assertTrue(ip_matches("127.0.0.1", "127.0.0.1"))

  def test_ip_matches_ipv4_failure(self):
    self.assertFalse(ip_matches("127.0.0.1", "192.168.1.1"))

  def test_ip_matches_ipv6_success(self):
    self.assertTrue(ip_matches("::1", "::1"))
  def test_ip_matches_ipv6_inexact_success(self):
    self.assertTrue(ip_matches("0000:0000::1", "::1"))

  def test_ip_matches_ipv6_failure(self):
    self.assertFalse(ip_matches("::1", "2001:48a8:68fe:ffff:1aa9:5ff:fe1a:b913"))

  def test_ip_matches_ipv6_ipv4_failure(self):
    self.assertFalse(ip_matches("::1", "127.0.0.1"))

  def test_ip_matches_ipv6_mapped_success(self):
    self.assertTrue(ip_matches("::ffff:192.168.1.1", "192.168.1.1"))


if __name__ == "__main__":
  unittest.main()
