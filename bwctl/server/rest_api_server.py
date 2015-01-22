import cherrypy

import datetime
import multiprocessing
import traceback

from bwctl.models import Test
from bwctl import jsonobject
from bwctl.utils import BwctlProcess
from bwctl import server
from bwctl.exceptions import BwctlException, SystemProblemException, ValidationException

class RestApiServer(BwctlProcess):
    def __init__(self, coordinator_client=None):
        status_controller = StatusController()
        tests_controller = TestsController()

        dispatcher = cherrypy.dispatch.RoutesDispatcher()

        # Status URL
        dispatcher.connect('status', '/bwctl/status', controller=status_controller, action='status')

        # Test URLs
        dispatcher.connect('new_test',    '/bwctl/tests', controller=tests_controller, action='new_test', conditions=dict(method=['POST']))
        dispatcher.connect('get_test'   , '/bwctl/tests/:id',   controller=tests_controller, action='get_test', conditions=dict(method=['GET']))
        dispatcher.connect('update_test', '/bwctl/tests/:id',   controller=tests_controller, action='update_test', conditions=dict(method=['PUT']))
        dispatcher.connect('cancel_test', '/bwctl/tests/:id/cancel',   controller=tests_controller, action='cancel_test', conditions=dict(method=['POST']))
        dispatcher.connect('accept_test', '/bwctl/tests/:id/accept',   controller=tests_controller, action='accept_test', conditions=dict(method=['POST']))
        dispatcher.connect('remote_accept_test', '/bwctl/tests/:id/remote_accept',   controller=tests_controller, action='remote_accept_test', conditions=dict(method=['POST']))
        dispatcher.connect('get_results', '/bwctl/tests/:id/results',   controller=tests_controller, action='get_results', conditions=dict(method=['GET']))

        cherrypy.tree.mount(root=None, config={
            '/': {
                'request.dispatch': dispatcher,
                'tools.json_in.on': True,
                'tools.json_out.on': True,

                'tools.encode.encoding': 'utf-8',

                'coordinator_client': coordinator_client
            }
        })

        super(RestApiServer, self).__init__()

    def run(self):
        cherrypy.engine.start()
        cherrypy.engine.block()

def get_coord_client():
    return cherrypy.request.app.config['/']['coordinator_client']

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

class ServerStatus(jsonobject.JsonObject):
    protocol = jsonobject.FloatProperty(exclude_if_none=True)
    time = jsonobject.DateTimeProperty(exact=True, exclude_if_none=True)
    ntp_error = jsonobject.FloatProperty(exclude_if_none=True)
    available_tools = jsonobject.ListProperty(unicode, exclude_if_none=True)
    version = jsonobject.StringProperty(exclude_if_none=True)

class StatusController:
  @cherrypy.expose
  @handle_bwctl_exceptions
  def status(self):
    status = ServerStatus()
    status.protocol = 2.0
    status.time = datetime.datetime.now()
    status.ntp_error = 0.0
    #status.available_tools = server.get_available_tools()
    status.available_tools = []
    status.version = server.__version__

    return status.to_json()

class TestsController:
  @cherrypy.expose
  @handle_bwctl_exceptions
  def new_test(self):
    added_test = None

    # XXX: validate this somehow

    test = None
    try:
        test = Test(cherrypy.request.json)
    except Exception as e:
       raise ValidationException("Problem parsing test definition: %s" % e)

    added_test = get_coord_client().request_test(test=test, requesting_address=cherrypy.request.remote.ip)

    return added_test.to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  def get_test(self, id):
    test = get_coord_client().get_test(test_id=id, requesting_address=cherrypy.request.remote.ip)

    return test.to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  def get_results(self, id):
    results = get_coord_client().get_test_results(test_id=id, requesting_address=cherrypy.request.remote.ip)

    return results.to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  def update_test(self, id):
    test = None
    try:
        test = Test(cherrypy.request.json)
    except Exception as e:
       raise ValidationException("Problem parsing test definition")

    updated_test = get_coord_client().update_test(test=test, test_id=id, requesting_address=cherrypy.request.remote.ip)

    return updated_test.to_json()

  @cherrypy.expose
  @handle_bwctl_exceptions
  def cancel_test(self, id):
    get_coord_client().cancel_test(test_id=id, requesting_address=cherrypy.request.remote.ip)

    return {}

  @cherrypy.expose
  @handle_bwctl_exceptions
  def accept_test(self, id):
    get_coord_client().client_confirm_test(test_id=id, requesting_address=cherrypy.request.remote.ip)

    return {}

  @cherrypy.expose
  @handle_bwctl_exceptions
  def remote_accept_test(self, id):
    get_coord_client().remote_confirm_test(test_id=id, requesting_address=cherrypy.request.remote.ip)

    return {}
