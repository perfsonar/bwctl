'''
Created on 12.02.2015

@author: Hakan Calim <Hakan.Calim@fau.de>
'''
import unittest
from nose.tools import eq_
from nose.tools import ok_

from os.path import dirname, realpath, sep

from bwctl.server import limits_parser


sep="/"

class LimitsParserV1Test(unittest.TestCase):
       
    def setUp(self): 
        self.tests_path = dirname(realpath(__file__))
        self.limits_examples_folder = "limits_exampes"
        self.limits_big_file = "bwctld-big.limits"
        self.limits_simple_file = "bwctld-simple.limits"
        self.limit_with_type_error_file = "bwctld-simple-error-01.limits"
        self.test_simple_file = self.tests_path + sep + self.limits_examples_folder + sep + self.limits_simple_file
        self.test_big_file = self.tests_path + sep + self.limits_examples_folder + sep + self.limits_big_file
        self.test_limit_type_error = self.tests_path + sep + self.limits_examples_folder + sep + self.limit_with_type_error_file
    

    def test_simple_parse(self):
        '''
        Check if limit entries parse of
        '''
        classes = parse(self.test_simple_file, "dict")
        expected_result = 3
        eq_(expected_result, len(classes))
        
    def test_check_assigns(self):
        '''
        Checks num of assigns for class
        In simple limits file class root has 2 assigns
        jail has 1
        '''
        classes = parse(self.test_simple_file, "dict")
        eq_(2, get_num_of_limit_assigns(classes,  "root"))
        eq_(1, get_num_of_limit_assigns(classes,  "jail"))
        
    def test_class_has_parent(self):
        '''
        Check the parent of a class
        root has None
        jail has root
        regular has root
        '''
        classes = parse(self.test_simple_file, "dict")
        eq_(None, get_class_parent(classes, "root"))
        eq_("root", get_class_parent(classes, "jail"))
        eq_("root", get_class_parent(classes, "regular"))
        
    
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
