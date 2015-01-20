import traceback

class BwctlException(Exception):
    """Base class for BWCTL exceptions, as well as the default "unknown" exception type."""
    error_code  = 100
    http_error  = 500
    default_msg = "Unknown error"

    def __init__(self, msg=""):
        self._msg = msg
        self._tb = traceback.format_exc()

    def __str__(self):
        return "%s: %s: %s" % (self.error_code, self.msg, self._tb)

    @property
    def msg(self):
        msg = self._msg
        if not msg:
            msg = self.default_msg
        msg = msg + "\n" + str(self._tb)
        return msg

    def as_bwctl_error(self):
        # Import here to avoid circular import errors
        from bwctl.models import BWCTLError

        return BWCTLError(error_code=self.error_code, error_msg=self.msg)

    def raise_if_error(self):
        raise self

    @classmethod
    def from_bwctl_error(cls, err):
        # XXX: special case due to JSON...
        if not err.error_code:
            return Success()

        classes = [ cls, ]
        exception_cls = None

        while len(classes) > 0:
            curr_cls = classes.pop()
            if curr_cls.error_code == err.error_code:
                exception_cls = curr_cls
                break
            classes.extend(curr_cls.__subclasses__())

        if not exception_cls:
            exception_cls = BwctlException

        return exception_cls(err.error_msg)

class Success(BwctlException):
    error_code  = 0
    default_msg = ""
    http_error  = 200

    def raise_if_error(self):
        pass

class ResourceNotFoundException(BwctlException):
    error_code  = 102
    http_error  = 404
    default_msg = "Test not found"

class ValidationException(BwctlException):
    error_code  = 202
    http_error  = 400
    default_msg = "Invalid resource"

class InvalidToolException(BwctlException):
    error_code  = 205
    http_error  = 400
    default_msg = "Invalid tool specified"

class NoAvailableTimeslotException(BwctlException):
    error_code  = 206
    http_error  = 400
    default_msg = "No available timeslots"

class TestAlreadyFinishedException(BwctlException):
    error_code  = 212
    http_error  = 409
    default_msg = "Test is already finished"

class TestInvalidActionException(BwctlException):
    error_code  = 222
    http_error  = 400
    default_msg = "Can't perform requested action on test"

class LimitViolatedException(BwctlException):
    error_code  = 302
    http_error  = 403
    default_msg = "Limit violation"

class SystemProblemException(BwctlException):
    error_code  = 402
    http_error  = 500
    default_msg = "System Error"

class TestStartTimeFailure(BwctlException):
    error_code  = 502
    http_error  = 500
    default_msg = "Test didn't start at expected time"

