import logging
from logging.handlers import TimedRotatingFileHandler, SysLogHandler

import multiprocessing
import netifaces
import os
import psutil
import socket
import sys

from bwctl.dependencies.IPy import IP

def timedelta_seconds(td):
    """ Returns the time difference, in floating-point seconds, of a datetime timedelta object. This is needed for Python 2.6 support."""
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10.0**6


class BwctlProcess(multiprocessing.Process):
    def terminate(self):
        self.kill_children()
    
        return super(BwctlProcess, self).terminate()

    def kill_children(self):
        if not self.pid:
            return

	# Find all the processes spawned off by this process, and kill them
        try:
            parent = psutil.Process(self.pid)
            for child in parent.get_children(recursive=True):
                child.kill()
        except:
            pass

def urljoin(*args):
    """
    Joins given arguments into a url. Trailing but not leading slashes are
    stripped for each argument.
    """

    return "/".join(map(lambda x: str(x).rstrip('/'), args))

def is_ipv6(addr):
    ip = IP(addr)
    return ip.version() == 6

def is_loopback(addr, strict=True):
    ip_obj = IP(addr)
    if ip_obj.iptype() == "LOOPBACK":
        return True

    # Look for addresses that are on the host itself
    if not strict:
        for iface in netifaces.interfaces():
            iface_addrs = netifaces.ifaddresses(iface)
            for addr_type in [ netifaces.AF_INET, netifaces.AF_INET6 ]:
                if not addr_type in iface_addrs:
                    continue
 
                for iface_addr in iface_addrs[addr_type]:
                    try:
                        addr_components = iface_addr['addr'].split('%', 1)
                        if ip_matches(addr, addr_components[0]):
                            return True
                    except:
                        pass

    return False

def ip_matches(ip1, ip2, resolve_v46_map=True):
    if ip1 == ip2:
        return True

    ip1_obj = IP(ip1)
    ip2_obj = IP(ip2)

    return _ip_matches(ip1_obj, ip2_obj)

def _ip_matches(ip1_obj, ip2_obj, resolve_v46_map=True):
    if ip1_obj.strCompressed() == ip2_obj.strCompressed():
        return True

    if ip1_obj.version() == ip2_obj.version():
        return False

    if resolve_v46_map:
        if ip1_obj.version() == 6:
            try:
                return _ip_matches(ip1_obj.v46map(), ip2_obj)
            except:
                pass
        elif ip2_obj.version() == 6:
            try:
                return _ip_matches(ip1_obj, ip2_obj.v46map())
            except:
                pass

    return False


def get_ip(host, prefer_ipv6=True, require_ipv6=False, require_ipv4=False, protocol=socket.IPPROTO_TCP):
    """
    This method returns the first IP address string
    that responds as the given domain name
    """
    try:
        addresses = socket.getaddrinfo(host, 0, 0, 0, protocol)

        if require_ipv6:
            for (family, socktype, proto, canonname, sockaddr) in addresses:
                if family == socket.AF_INET6:
                    return sockaddr[0]
        elif require_ipv4:
            for (family, socktype, proto, canonname, sockaddr) in addresses:
                if family == socket.AF_INET:
                    return sockaddr[0]
        elif prefer_ipv6:
            for (family, socktype, proto, canonname, sockaddr) in addresses:
                if family == socket.AF_INET6:
                    return sockaddr[0]

            for (family, socktype, proto, canonname, sockaddr) in addresses:
                if family == socket.AF_INET:
                    return sockaddr[0]
        else:
            for (family, socktype, proto, canonname, sockaddr) in addresses:
                if family in [ socket.AF_INET, socket.AF_INET6 ]:
                    return sockaddr[0]
    except Exception:
        pass

    return None

def discover_source_address(addr, interface=None):
    source_addr = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.connect((addr, 9)) # use UDP discard port
        source_addr = sock.getsockname()[0]
    except socket.error:
        source_addr = None
    finally:
        del sock

    return source_addr

logging_name = ""

def init_logging(name, screen=True, syslog_facility=None, debug=False,
        log_file=None, format="%(name)s [%(process)d] %(asctime)s %(message)s"):

    global logging_name

    logging_name = name

    level = logging.WARNING
    if debug:
        level = logging.DEBUG

    log = logging.getLogger()
    log.setLevel(level)

    if syslog_facility:
        syslog = SysLogHandler("/dev/log", facility=syslog_facility)
        syslog.setFormatter(logging.Formatter(format))
        log.addHandler(syslog)

    if log_file:
        log_handler = TimedRotatingFileHandler(filename=log_file,
                                               when='D',
                                               backupCount=7)
        log_handler.setFormatter(logging.Formatter(format))
        log.addHandler(log_handler)

    if screen:
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(format))
        log.addHandler(console)

def get_logger():
    global logging_name

    return logging.getLogger(logging_name)

class LoggerIO(object):
    """file like class which logs writes to syslog module
    
    This is intended to catch errant output to stdout or stderr inside daemon
    processes and log it to syslog rather than crashing the program."""

    def __init__(self):
        self.logger = get_logger()

    def write(self, buf):
        self.logger.debug("Captured Output: " + buf)

    def flush(self):
        for handler in self.logger.handlers:
            handler.flush()

def daemonize(pidfile=None):
    '''Forks the current process into a daemon.
        derived from the esmond
    '''

    if pidfile:
        # Resolve the path to an absolute
        pidfile = os.path.abspath(pidfile)

        # Create the directory path if it doesn't exist
        piddir = os.path.dirname(pidfile)

        if not os.path.exists(piddir):
            try:
                os.makedirs(piddir)
            except:
                raise Exception("PID file directory does not exist %s.  aborting." % pidfile) 
        if not os.access(piddir, os.W_OK):
            raise Exception("PID file directory %s is not writable.  aborting." % pidfile) 

    if os.path.exists(pidfile):
        f = open(pidfile)
        pid = f.readline()
        f.close()
        pid = int(pid.strip())
        try:
            os.kill(pid, 0)
        except:
            pass
        else:
            raise Exception("Process still running as pid %d.  aborting." % pid) 

    # Do first fork.
    try: 
        pid = os.fork() 
        if pid > 0: sys.exit(0) # Exit first parent.
    except OSError, e: 
        sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)
        
    # Decouple from parent environment.
    os.chdir("/") 
    os.umask(0) 
    os.setsid() 
    
    # Do second fork.
    try: 
        pid = os.fork() 
        if pid > 0: sys.exit(0) # Exit second parent.
    except OSError, e: 
        sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)
    
    pid = str(os.getpid())

    if pidfile:
        f = file(pidfile,'w')
        f.write("%s\n" % pid)
        f.close()
  
    # close stdin, stdout, stderr
    # XXX might not be 100% portable.
    for fd in range(3):
        os.close(fd)

    sys.stdout = sys.stderr = LoggerIO()

    return
