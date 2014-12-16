import multiprocessing
import psutil

def timedelta_seconds(td):
    """ Returns the time difference, in floating-point seconds, of a datetime timedelta object. This is needed for Python 2.6 support."""
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10.0**6


class BwctlProcess(multiprocessing.Process):
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
