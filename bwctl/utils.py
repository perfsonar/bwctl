import logging
import logging.handlers

import multiprocessing
import psutil
from bwctl.dependencies.IPy import IP
import socket

def timedelta_seconds(td):
    """ Returns the time difference, in floating-point seconds, of a datetime timedelta object. This is needed for Python 2.6 support."""
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10.0**6


class BwctlProcess(multiprocessing.Process):
    def kill(self):
        self.kill_children()
    
        return super(BwctlProcess, self).kill()

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
        format="%(name)s [%(process)d] %(message)s"):

    global logging_name

    logging_name = name

    level = logging.WARNING
    if debug:
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
    global logging_name

    return logging.getLogger(logging_name)
