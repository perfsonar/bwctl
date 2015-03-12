# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from urlparse import urljoin, urlsplit, urlunsplit

from bwctl.dependencies import requests
from bwctl.dependencies.requests.auth import HTTPDigestAuth
from bwctl.dependencies.requests.adapters import HTTPAdapter
from bwctl.dependencies.requests.packages.urllib3.poolmanager import PoolManager

import simplejson

from bwctl.protocol.coordinator.models import Test, Results
from bwctl.utils import urljoin
 
class Client:
    def __init__(self, server_address="127.0.0.1", server_port=5678, api_key=''):
        base_url = "http://[%s]:%d/bwctl" % (server_address, server_port)
        self.base_url = urljoin(base_url, "coordinator")
        self.auth     = HTTPDigestAuth("api_key", api_key)

    def get_test(self, test_id=None, requesting_address=None, user=None):
        headers = { 'Bwctl-User': user, 'Bwctl-Requesting-Address': requesting_address }

        url = urljoin(self.base_url, "tests", test_id)
        r = requests.get(url, auth=self.auth, headers=headers)
        r.raise_for_status()

        return Test(r.json())

    def get_test_results(self, test_id=None, requesting_address=None, user=None):
        headers = { 'Bwctl-User': user, 'Bwctl-Requesting-Address': requesting_address }

        url = urljoin(self.base_url, "tests", test_id, "results")
        r = requests.get(url, auth=self.auth, headers=headers)
        r.raise_for_status()

        return Results(r.json())

    def request_test(self, test=None, requesting_address=None, user=None):
        headers = { 'Bwctl-User': user, 'Bwctl-Requesting-Address': requesting_address, 'Content-Type': 'application/json' }
        url = urljoin(self.base_url, "tests")
        r = requests.post(url, data=simplejson.dumps(test.to_json()), headers=headers, auth=self.auth)
        r.raise_for_status()
        return Test(r.json())

    def update_test(self, test_id=None, test=None, requesting_address=None, user=None):
        headers = { 'Bwctl-User': user, 'Bwctl-Requesting-Address': requesting_address, 'Content-Type': 'application/json' }
        url = urljoin(self.base_url, "tests", test_id)
        r = requests.put(url, data=simplejson.dumps(test.to_json()), headers=headers, auth=self.auth)
        r.raise_for_status()
        return Test(r.json())

    def client_confirm_test(self, test_id=None, requesting_address=None, user=None):
        headers = { 'Bwctl-User': user, 'Bwctl-Requesting-Address': requesting_address, 'Content-Type': 'application/json' }
        url = urljoin(self.base_url, "tests", test_id, "accept")
        r = requests.post(url, data="{}", headers=headers, auth=self.auth)
        r.raise_for_status()
        return True

    def remote_confirm_test(self, test_id=None, test=None, requesting_address=None, user=None):
        headers = { 'Bwctl-User': user, 'Bwctl-Requesting-Address': requesting_address, 'Content-Type': 'application/json' }
        url = urljoin(self.base_url, "tests", test_id, "remote_accept")
        r = requests.post(url, data=simplejson.dumps(test.to_json()), headers=headers, auth=self.auth)
        r.raise_for_status()
        return True

    def server_confirm_test(self, test_id=None, requesting_address=None, user=None):
        headers = { 'Bwctl-User': user, 'Bwctl-Requesting-Address': requesting_address, 'Content-Type': 'application/json' }
        url = urljoin(self.base_url, "tests", test_id, "server_accept")
        r = requests.post(url, data="{}", headers=headers, auth=self.auth)
        r.raise_for_status()
        return True

    def cancel_test(self, test_id=None, requesting_address=None, user=None):
        headers = { 'Bwctl-User': user, 'Bwctl-Requesting-Address': requesting_address, 'Content-Type': 'application/json' }
        url = urljoin(self.base_url, "tests", test_id, "cancel")
        r = requests.post(url, data="{}", headers=headers, auth=self.auth)
        r.raise_for_status()
        return True

    def finish_test(self, test_id=None, results=None, requesting_address=None, user=None):
        headers = { 'Bwctl-User': user, 'Bwctl-Requesting-Address': requesting_address, 'Content-Type': 'application/json' }
        url = urljoin(self.base_url, "tests", test_id, "finish")
        r = requests.post(url, data=simplejson.dumps(results.to_json()), headers=headers, auth=self.auth)
        r.raise_for_status()
        return Test(r.json())
