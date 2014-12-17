from bwctl.exceptions import *
from bwctl.models import BWCTLError


not_found = ResourceNotFoundException()
limit_vio = LimitViolatedException()

for err in [ not_found, limit_vio ]:
    bwctl_error = err.as_bwctl_error()
    new_err = BwctlException.from_bwctl_error(bwctl_error)

    print "Err: %s" % err
    print "New Err: %s" % err
