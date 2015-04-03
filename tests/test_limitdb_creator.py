'''
Created on 23.02.2015

@author: unrz217
'''
import unittest
from nose.tools import eq_
from nose.tools import ok_

from os.path import dirname, realpath, sep

from bwctl.server.limits_parser import *

sep = "/"
tests_path = dirname(realpath(__file__))
limits_examples_folder = "limits_exampes"
limits_big_file = "bwctld-big.limits"
limits_simple_file = "bwctld-simple.limits"
Limits_new = "bwctl_new_limits.conf"
test_simple_file = tests_path + sep + limits_examples_folder + sep + limits_simple_file
test_big_file = tests_path + sep + limits_examples_folder + sep + limits_big_file
test_new_limits_file = tests_path + sep + limits_examples_folder + sep + Limits_new

class LimitsDBTest(unittest.TestCase):


    def test_creator_with_v1(self):
        ldbc = LimitsDBfromFileCreator(test_simple_file)
        ldbc.create()
              
    def test_with_limitsv2(self):
        lfpv2 = LimitFileParserV2(test_new_limits_file)
        lfpv2.parse()
        expected_result = 3 #Num of classes
        eq_(expected_result, lfpv2.get_limits_counter())
        
    def test_creator_with_v2(self):
        ldbc = LimitsDBfromFileCreator(test_new_limits_file)
        ldbc.create()        
        
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
