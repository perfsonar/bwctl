'''
Created on 23.02.2015

@author: unrz217
'''
import unittest

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


    
    def test_creator(self):
        ldbc = create_limitsdb(test_new_limits_file)
        
        
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
