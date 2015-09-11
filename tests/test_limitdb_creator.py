'''
Created on 23.02.2015

@author: unrz217
'''
import unittest

from os.path import dirname, realpath, sep

from bwctl.server.limits import LimitsDB
from bwctl.server.limits_parser import LimitsDBfromFileCreator


sep = "/"
tests_path = dirname(realpath(__file__))
limits_examples_folder = "limits_exampes"
limits_big_file = "bwctld-big.limits"
limits_simple_file = "bwctld-simple.limits"
Limits_new = "bwctl_new_limits.conf"
test_new_limits_file = tests_path + sep + limits_examples_folder + sep + Limits_new

#TODO: define for all limits tests
class LimitsDBTest(unittest.TestCase):

    def setUp(self):
        self.ldb = LimitsDBfromFileCreator(test_new_limits_file).get_limitsdb()
    
    def test_creator(self):
        '''
        Simple test with root_user.
        It should return some limits.
        '''
        class_name = "root_users"        
        limit_class = self.ldb.get_limit_class_by_name(class_name)
        self.assertTrue(limit_class, "Should not be empty")      
        
    def test_tool_equal_default(self):
        '''
        No iperf tool defined in root_user class.
        Therefore should return default limits
        '''
        class_name = "root_users"        
        limits = self.ldb.get_limit_class_by_name(class_name).get_limits("iperf3")
        default_limits = self.ldb.get_limit_class_by_name(class_name).get_limits()
        self.assertEqual(limits, default_limits)
        
    def test_tool_not_equal_default(self):
        '''
        class root_user hasdefined tool latency.
        Therefore not equal defaults.
        '''
        class_name = "root_users"        
        limits = self.ldb.get_limit_class_by_name(class_name).get_limits("throughput")
        default_limits = self.ldb.get_limit_class_by_name(class_name).get_limits()
        self.assertNotEqual(limits, default_limits)
        
    def test_values_set_correct(self):
        '''
        Tool: throughput
        class: root_user
        has following values:
         <limits "throughput">
            duration      30
            bandwidth     10G
            allow_udp_throughput     on
        </limits>
        '''
        class_name = "root_users"        
        limits = self.ldb.get_limit_class_by_name(class_name).get_limits("throughput")

        for limit in limits:
            if "duration".__eq__(limit.type):
                self.assertEqual(30, limit.value)
            elif "bandwidth".__eq__(limit.type):
                self.assertEqual(10000000000, limit.value)
            elif "allow_udp_throughput".__eq__(limit.type):
                self.assertTrue(limit.value)
                
    def test_allow_local_interface_limit(self):
        """
        <limits "throughput">
            duration      30
            bandwidth     10G
            allow_local_interface   11.1.0.1
            allow_local_interface   fe80::219:99ff:fea0:352c
            allow_udp_throughput     on
        </limits>
        """
        expected_local_interfaces = ["11.1.0.1", "fe80::219:99ff:fea0:352c"]
        class_name = "root_users"
        limits = self.ldb.get_limit_class_by_name(class_name).get_limits("throughput")
        for limit in limits:
            #print limit
            if "allow_local_interface".__eq__(limit.type):
                #self.assertTrue(limit.value in expected_local_interfaces, "Not defined local interface in limit file")
                self.assertEqual(limit.value, expected_local_interfaces, "Allow local interface is not correctly set in limit db")
                
    #TODO: at the moment  only int values stored            
    def test_test_frequency_limit(self):
        expected_test_frequency = 4
        class_name = "anonymous_users"
        limit_type = "test_frequency"
        limits = self.ldb.get_limit_class_by_name(class_name).get_limits("throughput")
        for limit in limits:
            if limit_type.__eq__(limit.type):
                self.assertEqual(expected_test_frequency, limit.value, "Limit: %s is not correct parsed" % limit_type)
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
