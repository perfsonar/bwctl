import datetime
import os

#Direction Constants
DIRECTION_SEND="send"
DIRECTION_RECV="recv"
DIRECTION_NONE="none"

#Output Level Constants
LVL_QUIET=0
LVL_NORMAL=1
LVL_VERBOSE=2

class Outputter(object):
    """Base class for all BWCTL output classes"""
    
    def __init__(self, level=LVL_NORMAL):
        self.ouput_level = level
    
    def info(self, str, level=LVL_NORMAL):
        """Prints BWCTL information (wait times, etc)"""
        pass
    
    def debug(self, str):
        """Convenience function for verbose output"""
        self.info(str, level=LVL_VERBOSE)
            
    def error(self, str, time=datetime.datetime.utcnow(), direction=DIRECTION_NONE):
        """Outputs a generic error message"""
        pass
    
    def results(self, direction, reservation_time, str):    
        """Outputs the results of a tool"""
        pass
    
    def result_errors(self, direction, reservation_time, error_list):
        """Outputs a list of errors returned by a BWCTL test """
        pass

class ScreenOutputter(Outputter):
    """Outputs BWCTL results to screen"""
    
    def info(self, str, level=LVL_NORMAL):
        if level <= self.ouput_level:
            print str
    
    def error(self, str, time=datetime.datetime.utcnow(), direction=DIRECTION_NONE):
        self.info(str)
    
    def results(self, direction, reservation_time, str):
        if direction == DIRECTION_SEND:
            print "Sender:"
        elif direction == DIRECTION_RECV:
            print "Receiver:"
        
        self.info("Results:\n%s" % str)
    
    def result_errors(self, direction, reservation_time, error_list):
        print "Errors:"
        for error in error_list:
            print "%d) %s" % (error.error_code, error.error_msg)
    

class BWFileOutputter(ScreenOutputter):
    """Outputs BWCTL results to a file and prints filename to screen"""
    
    def __init__(self, filedir=".", fname_datefmt="%Y-%m-%d_%H-%M-%S-%f", level=LVL_NORMAL):
        self.filedir = filedir
        self.fname_datefmt = fname_datefmt
        super(BWFileOutputter, self).__init__(level=level)
    
    def error(self, str, time=datetime.datetime.utcnow(), direction=DIRECTION_NONE):
        filename = "%s.%s.err" % (time.strftime(self.fname_datefmt), direction)
        filename = os.path.join(self.filedir, filename)
        with open(filename, "w") as f:
            f.write(str)
        print filename
        
    def results(self, direction, reservation_time, str):
        filename = "%s.%s.bw" % (reservation_time.strftime(self.fname_datefmt), direction)
        filename = os.path.join(self.filedir, filename)
        with open(filename, "w") as f:
            f.write(str)
        print filename
    
    def result_errors(self, direction, reservation_time, error_list):
        filename = "%s.%s.err" % (reservation_time.strftime(self.fname_datefmt), direction)
        filename = os.path.join(self.filedir, filename)
        with open(filename, "w") as f:
            for error in error_list:
                f.write("%d) %s\n" % (error.error_code, error.error_msg))
        print filename
        
    