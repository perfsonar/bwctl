def timedelta_seconds(td):
    """ Returns the time difference, in floating-point seconds, of a datetime timedelta object. This is needed for Python 2.6 support."""
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10.0**6
