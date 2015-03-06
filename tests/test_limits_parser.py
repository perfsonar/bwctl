'''
Created on 12.02.2015

@author: Hakan Calim <Hakan.Calim@fau.de>
'''
import unittest
from nose.tools import eq_
from nose.tools import ok_

from bwctl.server import limits_parser


sep="/"

class LimitsParserTest(unittest.TestCase):
       
    def setUp(self): 
        self.limits_examples_folder = "limits_exampes"
        self.limits_big_file = "bwctld-big.limits"
        self.limits_simple_file = "bwctld-simple.limits"
        self.limit_with_type_error_file = "bwctld-simple-error-01.limits"
        self.test_simple_file = self.limits_examples_folder + sep + self.limits_simple_file
        self.test_big_file = self.limits_examples_folder + sep + self.limits_big_file
        self.test_limit_type_error = self.limits_examples_folder + sep + self.limit_with_type_error_file
    

    def test_limit_parser_with_simple_file(self):
        '''
        Check if limit entries parse of
        '''
        lfp = limits_parser.LimitsFileParser(self.test_simple_file)
        lfp.parse()
        expected_result = 3
        eq_(expected_result, lfp.limits_counter)
        eq_(expected_result, lfp.get_num_of_limit_classes())

    def test_num_of_assigns_simple_file(self):
	'''
	root class has 2 net assigns in simple limits file
	'''
	lfp = limits_parser.LimitsFileParser(self.test_simple_file)
        lfp.parse()
	expected_result = 2 #root had 2 assigns in simple limit file
	eq_(expected_result, lfp.get_num_of_limit_assigns("root"))
       
    def test_limit_parser_with_big_file(self):
        '''
        Parse big limits file and count number of limit entries
        '''
        lfp = limits_parser.LimitsFileParser(self.test_big_file)
        lfp.parse()
        expected_result = 7
        eq_(expected_result, lfp.limits_counter)
        eq_(expected_result, lfp.get_num_of_limit_classes())
        
    def test_limit_class_types(self):
        lfp = limits_parser.LimitsFileParser(self.test_simple_file)
        lfp.parse()
        expected_result = 6 # root class has 6 parameters
        eq_(expected_result, lfp.get_num_of_limit_types("root"))
        
        #Check num of params for  class regular
        expected_result = 2 # regular class has 2 parameters
        eq_(expected_result, lfp.get_num_of_limit_types("regular"))
        
        #root has no parent
        expected_result = None 
        eq_(expected_result, lfp.get_class_parent("root"))
           
        #jail has root as parent
        expected_result = "root"
        eq_(expected_result, lfp.get_class_parent("jail"))
   
    def test_limit_type_error(self):
        '''
        This test should raise an error becaue limit type in file does not exist
        '''
        try:
            lfp = limits_parser.LimitsFileParser(self.test_limit_type_error)
            lfp.parse()
        except Exception:
            ok_(1)
        
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
