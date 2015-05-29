import datetime
import os
import sys
import json
import traceback

#Direction Constants
DIRECTION_SEND="send"
DIRECTION_RECV="recv"
DIRECTION_NONE="none"

#Output Level Constants
LVL_QUIET=0
LVL_NORMAL=1
LVL_VERBOSE=2

#INFO EVENTs
INFO_WAITTIME='wait'
INFO_SEND_CMD='send_cmd'
INFO_RECV_CMD='recv_cmd'
INFO_SEND_ADDRESS='send_address'
INFO_RECV_ADDRESS='recv_address'
INFO_TOOL='tool'
INFO_REQUESTED_TIME='req_time'
INFO_END_TIME='end_time'
INFO_DEBUG='debug'

class Outputter(object):
    """Base class for all BWCTL output classes"""
    
    def __init__(self, level=LVL_NORMAL):
        self.output_level = level
    
    def info(self, type, val, level=LVL_NORMAL):
        """Outputs BWCTL information (wait times, etc)"""
        pass
    
    def debug(self, str):
        """Convenience function for debugging output"""
        self.info(INFO_DEBUG, str, level=LVL_VERBOSE)
            
    def error(self, str):
        """Outputs a generic error message"""
        pass
    
    def results(self, direction, str):    
        """Outputs the results of a tool"""
        pass
    
    def result_errors(self, direction, error_list):
        """Outputs a list of errors returned by a BWCTL test"""
        pass
    
    def finalize(self):
        """Tasks to be done after output is complete (flush output, close files, etc)"""
        pass

class QuietOutputter(Outputter):

    """Outputter for quiet mode"""
    def __init__(self):
        super(QuietOutputter, self).__init__(level=LVL_QUIET)

class ScreenOutputter(Outputter):
    """Outputs BWCTL results to screen"""
    
    def info(self, type, val, level=LVL_NORMAL):
        if level > self.output_level:
            return
        if type == INFO_WAITTIME:
            print "Waiting %s seconds for results" % val
        elif type == INFO_SEND_CMD:
            print "Sender Command-line: %s" % val
        elif type == INFO_RECV_CMD:
            print "Receiver Command-line: %s" % val
        elif type == INFO_SEND_ADDRESS:
            print "Sender Address: %s" % val
        elif type == INFO_RECV_ADDRESS:
            print "Receiver Address: %s" % val
        elif type == INFO_TOOL:
            print "Selected tool: %s" % val
        elif type == INFO_REQUESTED_TIME:
            print "Requested time: %s" % val.isoformat()
        elif type == INFO_END_TIME:
            print "End time: %s" % val.isoformat()
        elif type == INFO_DEBUG:
            print val
            
    def error(self, str):
        sys.stderr.write("%s\n" % str)
        if self.output_level >= LVL_VERBOSE:
            traceback.print_exc()
    
    def results(self, direction, str):
        if direction == DIRECTION_SEND:
            print "Sender Results:"
        elif direction == DIRECTION_RECV:
            print "Receiver Results:"
        
        print str
    
    def result_errors(self, direction, error_list):
        print "Errors:"
        for error in error_list:
            print "%d) %s" % (error.error_code, error.error_msg)
    
    def finalize(self):
        sys.stdout.flush()
        sys.stderr.flush()
        

class BufferedOutputter(Outputter):
    """Stores BWCTL results in object for later output"""
    
    def __init__(self, level=LVL_NORMAL):
        self.buffer = { 
            'bwctl': {
                'requested_time': None,
                'end_time': None,
                'errors': [],
                'waittime': None,
                'tool': None
            },
            DIRECTION_SEND: {
                'address': None,
                'command': None,
                'errors': [],
                'results': None
            },
            DIRECTION_RECV: {
                'address': None,
                'command': None,
                'errors': [],
                'results': None
            }
        }
        super(BufferedOutputter, self).__init__(level=level)
    
    def info(self, type, val, level=LVL_NORMAL):
        if type == INFO_WAITTIME:
            self.buffer['bwctl']['waittime'] = val
        elif type == INFO_SEND_CMD:
            self.buffer[DIRECTION_SEND]['command'] = val
        elif type == INFO_RECV_CMD:
            self.buffer[DIRECTION_RECV]['command'] = val
        elif type == INFO_SEND_ADDRESS:
            self.buffer[DIRECTION_SEND]['address'] = val
        elif type == INFO_RECV_ADDRESS:
            self.buffer[DIRECTION_RECV]['address'] = val
        elif type == INFO_TOOL:
            self.buffer['bwctl']['tool'] = val
        elif type == INFO_REQUESTED_TIME:
            self.reservation_time = val
            self.buffer['bwctl']['requested_time'] = val.isoformat()
        elif type == INFO_END_TIME:
            self.reservation_time = val
            self.buffer['bwctl']['end_time'] = val.isoformat()
            
    def error(self, str):
        self.buffer['bwctl']['errors'].append(str)
    
    def results(self, direction, str):
        self.buffer[direction]['results'] = str
    
    def result_errors(self, direction, error_list):
        for error in error_list:
            self.buffer[direction]['errors'].append({'code': error.error_code, 'msg': error.error_msg})

class JSONOutputter(BufferedOutputter):
    """Stores BWCTL results in object for later output as JSON"""
    
    def results(self, direction, str):
        try:
            self.buffer[direction]['results'] = json.loads(str)
        except:
            self.buffer[direction]['results'] = str
        
class JSONScreenOutputter(JSONOutputter):
    """Outputs BWCTL results as JSON to screen"""
    
    def finalize(self):
        print json.dumps(self.buffer)
        sys.stdout.flush()

class JSONFileOutputter(JSONOutputter):
    """Outputs BWCTL results as JSON to file"""
    
    def __init__(self, filedir=".", fname_datefmt="%Y-%m-%d_%H-%M-%S-%f", level=LVL_NORMAL):
        self.filedir = filedir
        self.fname_datefmt = fname_datefmt
        super(JSONFileOutputter, self).__init__(level=level)
        
    def finalize(self):
        filename = "%s.bw" % self.reservation_time.strftime(self.fname_datefmt)
        filename = os.path.join(self.filedir, filename)
        with open(filename, "w") as f:
            f.write(json.dumps(self.buffer))
        print filename
        sys.stdout.flush()