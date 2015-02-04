import logging
import logging.handlers

import multiprocessing
import psutil
from IPy import IP
import socket

def timedelta_seconds(td):
    """ Returns the time difference, in floating-point seconds, of a datetime timedelta object. This is needed for Python 2.6 support."""
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10.0**6


class BwctlProcess(multiprocessing.Process):
    #def kill(self):
    #    self.kill_children()
    #
    #    return super(BwctlProcess, self).kill()

    def kill_children(self):
        if not self.pid:
            return

	# Find all the processes spawned off by this process, and kill them
        parent = psutil.Process(self.pid)
        for child in parent.get_children(recursive=True):
            child.kill()

def urljoin(*args):
    """
    Joins given arguments into a url. Trailing but not leading slashes are
    stripped for each argument.
    """

    return "/".join(map(lambda x: str(x).rstrip('/'), args))

def is_ipv6(addr):
    ip = IP(addr)
    return ip.version() == 6

def get_ip(host, prefer_ipv6=True, require_ipv6=False, require_ipv4=False):
    """
    This method returns the first IP address string
    that responds as the given domain name
    """
    try:
        addresses = socket.getaddrinfo(host, 0, 0, 0, socket.IPPROTO_TCP)

        if prefer_ipv6 or require_ipv6:
            for (family, socktype, proto, canonname, sockaddr) in addresses:
                if family == socket.AF_INET6:
                    return sockaddr[0]

        if not require_ipv6:
            for (family, socktype, proto, canonname, sockaddr) in addresses:
                if family == socket.AF_INET:
                    return sockaddr[0]
    except Exception:
        pass

    return None

logging_name = ""

def init_logging(name, screen=True, syslog_facility=None, debug=False,
        format="%(name)s [%(process)d] %(message)s"):

    logging_name = name

    level = logging.WARNING
    if debug:
        print "Debug mode"
        level = logging.DEBUG

    log = logging.getLogger()
    log.setLevel(level)

    if syslog_facility:
        syslog = logging.handlers.SysLogHandler("/dev/log", facility=syslog_facility)
        syslog.setFormatter(logging.Formatter(format))
        log.addHandler(syslog)

    if screen:
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(format))
        log.addHandler(console)

def get_logger():
    return logging.getLogger(logging_name)
