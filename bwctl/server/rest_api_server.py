import cherrypy

import datetime
import multiprocessing
import traceback

from bwctl import jsonobject
from bwctl.utils import BwctlProcess
from bwctl import server
from bwctl.tools import get_available_tools
from bwctl.exceptions import BwctlException, SystemProblemException, ValidationException

from bwctl.protocol.v2.models import *

class RestApiServer(BwctlProcess):
    def __init__(self, coordinator=None, server_address='', server_port=4824, legacy_endpoint_port=None):
        self.coordinator = coordinator
        self.server_address = server_address
        self.server_port = server_port
        self.legacy_endpoint_port = legacy_endpoint_port

        super(RestApiServer, self).__init__()

    def run(self):
        dispatcher = cherrypy.dispatch.RoutesDispatcher()

        v2_protocol_controller = V2ProtocolController(coordinator=self.coordinator, legacy_endpoint_port=self.legacy_endpoint_port)
        v2_protocol_controller.add_urls(dispatcher)

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
            }
        })

        cherrypy.engine.start()
        cherrypy.engine.block()

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

class V2ProtocolController(object):
  def __init__(self, coordinator=None, legacy_endpoint_port=None):
      self.coordinator = coordinator
      self.legacy_endpoint_port = legacy_endpoint_port
      super(V2ProtocolController, self).__init__()

  def add_urls(self, dispatcher):
      dispatcher.connect('status', '/bwctl/v2/status', controller=self, action='status')
      dispatcher.connect('new_test',    '/bwctl/v2/tests', controller=self, action='new_test', conditions=dict(method=['POST']))
      dispatcher.connect('get_test'   , '/bwctl/v2/tests/:id',   controller=self, action='get_test', conditions=dict(method=['GET']))
      dispatcher.connect('update_test', '/bwctl/v2/tests/:id',   controller=self, action='update_test', conditions=dict(method=['PUT']))
      dispatcher.connect('cancel_test', '/bwctl/v2/tests/:id/cancel',   controller=self, action='cancel_test', conditions=dict(method=['POST']))
      dispatcher.connect('accept_test', '/bwctl/v2/tests/:id/accept',   controller=self, action='accept_test', conditions=dict(method=['POST']))
      dispatcher.connect('remote_accept_test', '/bwctl/v2/tests/:id/remote_accept',   controller=self, action='remote_accept_test', conditions=dict(method=['POST']))
      dispatcher.connect('get_results', '/bwctl/v2/tests/:id/results',   controller=self, action='get_results', conditions=dict(method=['GET']))

  @cherrypy.expose
  @handle_bwctl_exceptions
  def status(self):
    status = ServerStatus()
    status.protocol = 2.0
    status.time = datetime.datetime.utcnow()
    status.ntp_error = 0.0
    status.available_tools = get_available_tools()
    status.version = server.__version__
    status.legacy_endpoint_port = self.legacy_endpoint_port

    return status.to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  def new_test(self):
    added_test = None

    # XXX: validate this somehow

    test = None
    try:
        test = Test(cherrypy.request.json).to_internal()
    except Exception as e:
       raise ValidationException("Problem parsing test definition: %s" % e)

    added_test = self.coordinator.request_test(test=test, requesting_address=cherrypy.request.remote.ip)

    return Test.from_internal(added_test).to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  def get_test(self, id):
    test = self.coordinator.get_test(test_id=id, requesting_address=cherrypy.request.remote.ip)

    return Test.from_internal(test).to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  def get_results(self, id):
    results = self.coordinator.get_test_results(test_id=id, requesting_address=cherrypy.request.remote.ip)

    return Results.from_internal(results).to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  def update_test(self, id):
    test = None
    try:
        test = Test(cherrypy.request.json).to_internal()
    except Exception as e:
       raise ValidationException("Problem parsing test definition")

    updated_test = self.coordinator.update_test(test=test, test_id=id, requesting_address=cherrypy.request.remote.ip)

    return Test.from_internal(updated_test).to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  def cancel_test(self, id):
    self.coordinator.cancel_test(test_id=id, requesting_address=cherrypy.request.remote.ip)

    return {}

  @cherrypy.expose
  @handle_bwctl_exceptions
  def accept_test(self, id):
    self.coordinator.client_confirm_test(test_id=id, requesting_address=cherrypy.request.remote.ip)

    return {}

  @cherrypy.expose
  @handle_bwctl_exceptions
  def remote_accept_test(self, id):
    test = None
    try:
        test = Test(cherrypy.request.json).to_internal()
    except Exception as e:
       raise ValidationException("Problem parsing test definition")

    self.coordinator.remote_confirm_test(test_id=id, test=test, requesting_address=cherrypy.request.remote.ip)

    return {}
