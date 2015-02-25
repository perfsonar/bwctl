'''
Created on 23.02.2015

@author: unrz217
'''
import unittest
from nose.tools import eq_
from nose.tools import ok_

from os.path import dirname, realpath, sep, pardir
import sys
sys.path.append(dirname(realpath(__file__)) + sep + pardir + sep + "lib")

from bwctl.server import limits_parser

limits_examples_folder = "limits_exampes"
limits_big_file = "bwctld-big.limits"
limits_simple_file = "bwctld-simple.limits"
test_simple_file = limits_examples_folder + sep + limits_simple_file
test_big_file = limits_examples_folder + sep + limits_big_file

class Test(unittest.TestCase):


    def test_crator_with_simple_file(self):
        ldbc = limits_parser.LimitsDBfromFileCreator(test_simple_file)
        ldbc.create()
        print ldbc.get_limits_classes()
              


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()