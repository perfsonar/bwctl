# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from urlparse import urljoin, urlsplit, urlunsplit

from bwctl.dependencies import requests
from bwctl.dependencies.requests.auth import HTTPDigestAuth
from bwctl.dependencies.requests.adapters import HTTPAdapter
from bwctl.dependencies.requests.packages.urllib3.poolmanager import PoolManager

import simplejson

from bwctl.protocol.v2.models import ServerStatus, Test, Results
from bwctl.utils import urljoin
 
class Client:
    def __init__(self, base_url, source_address=None, username=None, password=None):
        self.base_url = urljoin(base_url, "v2")
        self.username = username
        self.password = password
        self.auth     = HTTPDigestAuth(username, password)

        self.session = requests.Session()
        if source_address:
            self.session.mount('http://', SourceAddressAdapter((source_address, 0)))

    def get_status(self):
        url = urljoin(self.base_url, "status")
        r = self.session.get(url, auth=self.auth)
        r.raise_for_status()
        return ServerStatus(r.json())

    def get_test(self, id):
        url = urljoin(self.base_url, "tests", id)
        r = self.session.get(url, auth=self.auth)
        r.raise_for_status()

        return Test(r.json())

    def get_test_results(self, id):
        url = urljoin(self.base_url, "tests", id, "results")
        r = self.session.get(url, auth=self.auth)
        r.raise_for_status()

        return Results(r.json())

    def request_test(self, test):
        url = urljoin(self.base_url, "tests")
        r = self.session.post(url, data=simplejson.dumps(test.to_json()), headers={'Content-Type': 'application/json'}, auth=self.auth)
        print r.text
        r.raise_for_status()
        return Test(r.json())

    def update_test(self, id, test):
        url = urljoin(self.base_url, "tests", id)
        r = self.session.put(url, data=simplejson.dumps(test.to_json()), headers={'Content-Type': 'application/json'}, auth=self.auth)
        print "JSON: %s" % r.json()
        r.raise_for_status()
        return Test(r.json())

    def accept_test(self, id):
        url = urljoin(self.base_url, "tests", id, "accept")
        r = self.session.post(url, data="{}", headers={'Content-Type': 'application/json'}, auth=self.auth)
        r.raise_for_status()
        return True

    def remote_accept_test(self, id, test):
        url = urljoin(self.base_url, "tests", id, "remote_accept")
        r = self.session.post(url, data=simplejson.dumps(test.to_json()), headers={'Content-Type': 'application/json'}, auth=self.auth)
        print "R: %s" % r.json()
        r.raise_for_status()
        return True

    def cancel_test(self, id):
        url = urljoin(self.base_url, "tests", id, "cancel")
        r = self.session.post(url, data="{}", headers={'Content-Type': 'application/json'}, auth=self.auth)
        r.raise_for_status()
        return True

class SourceAddressAdapter(HTTPAdapter):
    def __init__(self, source_address, **kwargs):
        self.source_address = source_address
        super(SourceAddressAdapter, self).__init__(**kwargs)
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       source_address=self.source_address,
                                       )
