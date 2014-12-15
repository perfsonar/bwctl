from urlparse import urljoin
from httplib2 import Http
import simplejson

from bwctl.protocol.models import ServerStatus
 
class SimpleClient:
    def __init__(self, base_url):
        self.base_url = base_url

    def get_status(self):
        try:
            url = urljoin(self.base_url, "?format=json")
            #url = urljoin(self.base_url, "status")
            resp, content = Http().request(url,"GET")
            parsed_json = simplejson.loads(content)
            return ServerStatus(parsed_json)
        except Exception as e:
            print "Error: %s" % e
            pass

        return None

    def accept_test(self, id):
        try:
            url = urljoin(self.base_url, "tests", id, "accept")
            resp, content = Http().request(
                        uri=url,
                        method='POST',
                        headers={'Content-Type': 'application/json'},
                        body="{}",
            )
            return simplejson.loads(resp)
        except Exception as e:
            print "Error: %s" % e
            pass

        return None

#    def cancel_test(self, id):
#        return True
#
#    def get_test(self, id):
#        return self.tests[id]
