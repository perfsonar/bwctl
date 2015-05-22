import datetime
import random

NUM_TESTS_INFINITE = -1

class Scheduler(object):
    """Base class for all BWCTL client schedulers"""
    def __init__(self, max_num_tests=NUM_TESTS_INFINITE):
        self.tests_remaining = max_num_tests
        self.max_num_tests = max_num_tests
        self.last_runtime = None
    
    def reset_test_count(self):
        self.tests_remaining = self.max_num_tests
        
    def get_next_wait_time(self): pass
    
    def has_next_test(self):
        return self.tests_remaining != 0
    
    def mark_test_run(self):
        self.last_runtime = datetime.datetime.utcnow()
        if(self.tests_remaining > 0):
            self.tests_remaining -= 1
    
    def cancel(self):
        self.tests_remaining = 0
        
class IntervalScheduler(Scheduler):
    
    def __init__(self, interval=0, rand_start=0, max_num_tests=NUM_TESTS_INFINITE):
        self.interval = interval
        self.rand_start = rand_start
        super(IntervalScheduler, self).__init__(max_num_tests=max_num_tests)
    
    @property
    def rand_start(self):
        return self._rand_start
    
    @rand_start.setter
    def rand_start(self, r):
        if(r < 0):
            raise Exception("Random start percentage cannot be a negative number")
        elif(r > 50):
           raise Exception("Random start percentage cannot exceed 50")
        
        self._rand_start = r
            
        
    def get_next_wait_time(self):
        alpha = self.interval * (self.rand_start/100.0)
        r = random.random()
        
        wait_time = 0.0
        if(self.last_runtime is None):
            wait_time = alpha * r
        else:
            wait_time = self.interval - alpha + (2.0 * r * alpha) 

        return wait_time

class StreamingScheduler(Scheduler):
    
    def get_next_wait_time(self): 
        return 0.0

class SingleTestScheduler(StreamingScheduler):

    def __init__(self):
        super(SingleTestScheduler, self).__init__(max_num_tests=1)
