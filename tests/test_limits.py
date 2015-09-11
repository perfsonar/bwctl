'''
Created on 27.07.2015

@author: Hakan Calim
'''
#TODO: Add all limits for testing  here
import unittest

from nose.tools import eq_

from bwctl.server.limits import *


class MockTest1:
    def __init__(self):
        self.bwctl_protocol = False
    
class MockTest2(object):
    def __init__(self):
        self.tool_parameters = {'name' : 'owamp'}
        self.remote_endpoint = MockTest1()
        
    
class LimitsTest(unittest.TestCase):
     
    def testAllowEndpointlessLimit_should_raise(self):
        test =  MockTest2()        
        limit = AllowEndpointlessLimit("off")
        with self.assertRaises(LimitViolatedException):
            limit.check(test)        
    
    def testAllowEndpointlessLimit_should_not_raise(self):
        test =  MockTest2()        
        limit = AllowEndpointlessLimit("on")
        limit.check(test)
        
    def testAllowLocalInterface_should_raise(self):
        local_interface = "1.2.3.4"
        test_interface = "2.2.2.2"        
        limit = AllowLocalInterface(local_interface)
        test =  MockTest2()
        with self.assertRaises(LimitViolatedException):
            limit.check(test, test_interface)
            
    def testAllowLocalInterface_should_not_raise(self):
        local_interface1 = "1.2.3.4"
        local_interface2 = "192.168.100.1"
        local_interface3 = "10.10.10.1"
        test_interface = local_interface3        
        limit = AllowLocalInterface([local_interface1, local_interface2, local_interface3])
        test =  MockTest2()
        limit.check(test, test_interface)
        
        
        


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()