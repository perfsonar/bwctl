import cherrypy

import datetime
import multiprocessing
import traceback
import uuid

from bwctl import jsonobject
from bwctl.utils import BwctlProcess
from bwctl import server
from bwctl.tools import get_available_tools
from bwctl.exceptions import BwctlException, SystemProblemException, ValidationException

from bwctl.protocol.coordinator.models import *

class CoordinatorServer(BwctlProcess):
    def __init__(self, coordinator=None, server_address='127.0.0.1', server_port=5678, api_key=""):
        self.coordinator = coordinator
        self.server_address = server_address
        self.server_port = server_port
        self.api_key = api_key

        super(CoordinatorServer, self).__init__()

    def run(self):
        dispatcher = cherrypy.dispatch.RoutesDispatcher()

        coordinator_protocol_controller = CoordinatorProtocolController(coordinator=self.coordinator)
        coordinator_protocol_controller.add_urls(dispatcher)

        apikey_dict = {
            'api_key': self.api_key
        }

        get_ha1 = cherrypy.lib.auth_digest.get_ha1_dict_plain(apikey_dict)

        if self.server_address:
            cherrypy.config.update({'server.bind_addr': ( self.server_address, self.server_port )})
        else:
            # Default to "ipv6 any" which should encompass ipv4 addresses to.
            # If not, we'll need to rethink how this gets done.
            cherrypy.config.update({'server.bind_addr': ( "::", self.server_port ) })

        cherrypy.config.update({'engine.autoreload_on':False})

        cherrypy.config.update({'log.screen': False})

        cherrypy.tree.mount(root=None, config={
            '/': {
                'request.dispatch': dispatcher,
                'tools.json_in.on': True,
                'tools.json_out.on': True,

                'tools.encode.encoding': 'utf-8',

                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': 'wonderland',
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': str(uuid.uuid4()),
            }
        })

        cherrypy.engine.start()
        cherrypy.engine.block()

def resolve_user_requesting_address(function):
    def decorated_func(*args, **kwargs):
        result = None

        try:
           user = cherrypy.request.headers.get("Bwctl-User", None)
           requesting_address = cherrypy.request.headers.get("Bwctl-Requesting-Address", None)

           result = function(*args, user=user, requesting_address=requesting_address, **kwargs)
        except BwctlException as e:
            result = e.as_bwctl_error().to_json()
            cherrypy.response.status = e.http_error
        except Exception as e:
            err = SystemProblemException(str(e))
            result = err.as_bwctl_error().to_json()
            cherrypy.response.status = err.http_error

        return result

    return decorated_func


def handle_bwctl_exceptions(function):
    def decorated_func(*args, **kwargs):
        result = None

        try:
           result = function(*args, **kwargs)
        except BwctlException as e:
            result = e.as_bwctl_error().to_json()
            cherrypy.response.status = e.http_error
        except Exception as e:
            err = SystemProblemException(str(e))
            result = err.as_bwctl_error().to_json()
            cherrypy.response.status = err.http_error

        return result

    return decorated_func

class CoordinatorProtocolController(object):
  def __init__(self, coordinator=None):
      self.coordinator = coordinator
      super(CoordinatorProtocolController, self).__init__()

  def add_urls(self, dispatcher):
      dispatcher.connect('new_test',    '/bwctl/coordinator/tests', controller=self, action='new_test', conditions=dict(method=['POST']))
      dispatcher.connect('get_test'   , '/bwctl/coordinator/tests/:id',   controller=self, action='get_test', conditions=dict(method=['GET']))
      dispatcher.connect('update_test', '/bwctl/coordinator/tests/:id',   controller=self, action='update_test', conditions=dict(method=['PUT']))
      dispatcher.connect('cancel_test', '/bwctl/coordinator/tests/:id/cancel',   controller=self, action='cancel_test', conditions=dict(method=['POST']))
      dispatcher.connect('finish_test', '/bwctl/coordinator/tests/:id/accept',   controller=self, action='accept_test', conditions=dict(method=['POST']))
      dispatcher.connect('accept_test', '/bwctl/coordinator/tests/:id/finish',   controller=self, action='finish_test', conditions=dict(method=['POST']))
      dispatcher.connect('remote_accept_test', '/bwctl/coordinator/tests/:id/remote_accept',   controller=self, action='remote_accept_test', conditions=dict(method=['POST']))
      dispatcher.connect('server_accept_test', '/bwctl/coordinator/tests/:id/server_accept',   controller=self, action='server_accept_test', conditions=dict(method=['POST']))
      dispatcher.connect('get_results', '/bwctl/coordinator/tests/:id/results',   controller=self, action='get_results', conditions=dict(method=['GET']))

  @cherrypy.expose
  @handle_bwctl_exceptions
  @resolve_user_requesting_address
  def new_test(self, user=None, requesting_address=None):
    added_test = None

    # XXX: validate this somehow

    test = None
    try:
        test = Test(cherrypy.request.json)
    except Exception as e:
       raise ValidationException("Problem parsing test definition: %s" % e)

    added_test = self.coordinator.request_test(test=test, requesting_address=requesting_address, user=user)

    return added_test.to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  @resolve_user_requesting_address
  def get_test(self, id, user=None, requesting_address=None):
    test = self.coordinator.get_test(test_id=id, requesting_address=requesting_address, user=user)

    return test.to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  @resolve_user_requesting_address
  def get_results(self, id, user=None, requesting_address=None):
    results = self.coordinator.get_test_results(test_id=id, requesting_address=requesting_address, user=user)

    return results.to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  @resolve_user_requesting_address
  def update_test(self, id, user=None, requesting_address=None):
    test = None
    try:
        test = Test(cherrypy.request.json)
    except Exception as e:
       raise ValidationException("Problem parsing test definition")

    updated_test = self.coordinator.update_test(test=test, test_id=id, requesting_address=requesting_address, user=user)

    return updated_test.to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  @resolve_user_requesting_address
  def cancel_test(self, id, user=None, requesting_address=None):
    self.coordinator.cancel_test(test_id=id, requesting_address=requesting_address, user=user)

    return {}

  @cherrypy.expose
  @handle_bwctl_exceptions
  @resolve_user_requesting_address
  def finish_test(self, id, user=None, requesting_address=None):
    results = None
    try:
        results = Results(cherrypy.request.json)
    except Exception as e:
       raise ValidationException("Problem parsing results definition")

    self.coordinator.finish_test(test_id=id, results=results, requesting_address=requesting_address, user=user)

    return {}

  @cherrypy.expose
  @handle_bwctl_exceptions
  @resolve_user_requesting_address
  def accept_test(self, id, user=None, requesting_address=None):
    self.coordinator.client_confirm_test(test_id=id, requesting_address=requesting_address, user=user)

    return {}

  @cherrypy.expose
  @handle_bwctl_exceptions
  @resolve_user_requesting_address
  def remote_accept_test(self, id, user=None, requesting_address=None):
    test = None
    try:
        test = Test(cherrypy.request.json)
    except Exception as e:
       raise ValidationException("Problem parsing test definition")

    self.coordinator.remote_confirm_test(test_id=id, test=test, requesting_address=requesting_address, user=user)

    return {}

  @cherrypy.expose
  @handle_bwctl_exceptions
  @resolve_user_requesting_address
  def server_accept_test(self, id, user=None, requesting_address=None):
    self.coordinator.server_confirm_test(test_id=id, requesting_address=requesting_address, user=user)

    return {}
