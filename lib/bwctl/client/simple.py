# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from urlparse import urljoin, urlsplit, urlunsplit
import requests
import simplejson

from bwctl.server.rest_api_server import ServerStatus
from bwctl.models import Test, Results
from bwctl.utils import urljoin
 
class SimpleClient:
    def __init__(self, base_url):
        self.base_url = base_url

        self.session = requests.Session()

    def get_status(self):
        url = urljoin(self.base_url, "status")
        r = self.session.get(url)
        r.raise_for_status()
        return ServerStatus(r.json())

    def get_test(self, id):
        url = urljoin(self.base_url, "tests", id)
        r = self.session.get(url)
        r.raise_for_status()

        return Test(r.json())

    def get_test_results(self, id):
        url = urljoin(self.base_url, "tests", id, "results")
        r = self.session.get(url)
        r.raise_for_status()

        return Results(r.json())

    def request_test(self, test):
        url = urljoin(self.base_url, "tests")
        r = self.session.post(url, data=simplejson.dumps(test.to_json()), headers={'Content-Type': 'application/json'})
        r.raise_for_status()
        return Test(r.json())

    def update_test(self, id, test):
        url = urljoin(self.base_url, "tests", id)
        r = self.session.put(url, data=simplejson.dumps(test.to_json()), headers={'Content-Type': 'application/json'})
        r.raise_for_status()
        return Test(r.json())

    def accept_test(self, id):
        url = urljoin(self.base_url, "tests", id, "accept")
        r = self.session.post(url, data="{}", headers={'Content-Type': 'application/json'})
        r.raise_for_status()
        return True

    def remote_accept_test(self, id):
        url = urljoin(self.base_url, "tests", id, "remote_accept")
        r = self.session.post(url, data="{}", headers={'Content-Type': 'application/json'})
        r.raise_for_status()
        return True

    def cancel_test(self, id):
        url = urljoin(self.base_url, "tests", id, "cancel")
        r = self.session.post(url, data="{}", headers={'Content-Type': 'application/json'})
        r.raise_for_status()
        return True

# XXX: Python 2.6 does not support setting the source address, which we use to
#      do some basic authorization with...
#class BindableHTTPConnection(httplib.HTTPConnection):
#    def connect(self):
#        """Connect to the host and port specified in __init__."""
#        self.sock = socket.socket()
#        self.sock.bind((self.source_ip, 0))
#        if isinstance(self.timeout, float):
#            self.sock.settimeout(self.timeout)
#        self.sock.connect((self.host,self.port))
#
#def BindableHTTPConnectionFactory(source_ip):
#    def _get(host, port=None, strict=None, timeout=0):
#        bhc=BindableHTTPConnection(host, port=port, strict=strict, timeout=timeout)
#        bhc.source_ip=source_ip
#        return bhc
#    return _get
#
#class BindableHTTPHandler(urllib2.HTTPHandler):
#    def http_open(self, req):
#        return self.do_open(BindableHTTPConnectionFactory('127.0.0.1'), req)
#
#opener = urllib2.build_opener(BindableHTTPHandler)
