from ctypes import *
from ctypes.util import find_library

"""
int ntp_adjtime(struct timex *);

#define STA_UNSYNC      0x0040  /* clock unsynchronized (rw) */

#define STA_NANO        0x2000  /* resolution (0 = us, 1 = ns) (ro) */

struct timex {
    int  modes;      /* Mode selector */
    long offset;     /* Time offset; nanoseconds, if STA_NANO
                        status flag is set, otherwise microseconds */
    long freq;       /* Frequency offset, in units of 2^-16 ppm
                        (parts per million, see NOTES below) */
    long maxerror;   /* Maximum error (microseconds) */
    long esterror;   /* Estimated error (microseconds) */
    int  status;     /* Clock command/status */
    long constant;   /* PLL (phase-locked loop) time constant */
    long precision;  /* Clock precision (microseconds, read-only) */
    long tolerance;  /* Clock frequency tolerance (ppm, read-only) */
    struct timeval time;
                     /* Current time (read-only, except for
                        ADJ_SETOFFSET); upon return, time.tv_usec
                        contains nanoseconds, if STA_NANO status
                        flag is set, otherwise microseconds */
    long tick;       /* Microseconds between clock ticks */
    long ppsfreq;    /* PPS (pulse per second) frequency (in units
                        of 2^-16 ppm--see NOTES, read-only) */
    long jitter;     /* PPS jitter (read-only); nanoseconds, if
                        STA_NANO status flag is set, otherwise
                        microseconds */
    int  shift;      /* PPS interval duration (seconds, read-only) */
    long stabil;     /* PPS stability (2^-16 ppm--see NOTES,
                        read-only) */
    long jitcnt;     /* PPS jitter limit exceeded (read-only) */
    long calcnt;     /* PPS calibration intervals (read-only) */
    long errcnt;     /* PPS calibration errors (read-only) */
    long stbcnt;     /* PPS stability limit exceeded (read-only) */
    int tai;         /* TAI offset, as set by previous ADJ_TAI
                        operation (seconds, read-only,
                        since Linux 2.6.26) */
    /* Further padding bytes to allow for future expansion */
};

struct timeval {
    time_t      tv_sec;     /* seconds */
    suseconds_t tv_usec;    /* microseconds */
};
"""

STA_NANO=0x2000
STA_UNSYNC=0x0040

class TimevalStruct(Structure):
    _fields_ = [
        ("tv_sec", c_long),
        ("tv_usec", c_long),
    ]

class TimexStruct(Structure):
    _fields_ = [
        ("modes", c_int),
        ("offset", c_long),
        ("freq", c_long),
        ("maxerror", c_long),
        ("esterror", c_long),
        ("status", c_int),
        ("constant", c_long),
        ("precision", c_long),
        ("tolerance", c_long),
        ("time", TimevalStruct),
        ("tick", c_long),
        ("ppsfreq", c_long),
        ("jitter", c_long),
        ("shift", c_int),
        ("stabil", c_long),
        ("jitcnt", c_long),
        ("calcnt", c_long),
        ("errcnt", c_long),
        ("stbcnt", c_long),
        ("tai", c_int),
    ]

    @property
    def resolution(self):
        if self.status & STA_NANO:
            return 10**9
        else:
            return 10**6

    @property
    def synchronized(self):
        return (self.status & STA_UNSYNC) == 0

    @property
    def offset_sec(self):
        return self.offset / float(self.resolution)

    @property
    def maxerror_sec(self): # max error is always in microseconds
        return self.maxerror / float(10**6)

def ntp_adjtime():
    retval = None
    try:
        libc = cdll.LoadLibrary(find_library("c"))
        timex = TimexStruct()
        p_timex = pointer(timex)

        libc.ntp_adjtime(p_timex)

        retval = p_timex.contents
    except Exception as e:
        #print "Error: %s" % e
        pass

    return retval

if __name__ == "__main__":
    timex = ntp_adjtime()

    print "Synchronized: %d" % timex.synchronized

    print "STA_NANO: %s" % (timex.status & STA_NANO)
    print "STA_UNSYNC: %s" % (timex.status & STA_UNSYNC)
    print "Offset: %s" % timex.offset
    print "Offset(sec): %s" % timex.offset_sec
    print "Max Error: %s" % timex.maxerror
    print "Max Error(sec): %s" % timex.maxerror_sec
