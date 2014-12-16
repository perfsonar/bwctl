import cherrypy

import datetime
import multiprocessing
import traceback

from bwctl.models import Test
from bwctl import jsonobject
from bwctl.utils import BwctlProcess
from bwctl import server

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

class ServerStatus(jsonobject.JsonObject):
    protocol = jsonobject.FloatProperty(exclude_if_none=True)
    time = jsonobject.DateTimeProperty(exact=True, exclude_if_none=True)
    ntp_error = jsonobject.FloatProperty(exclude_if_none=True)
    available_tools = jsonobject.ListProperty(unicode, exclude_if_none=True)
    version = jsonobject.StringProperty(exclude_if_none=True)

class StatusController:
  @cherrypy.expose
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
  def new_test(self):
    status = None
    value  = None

    # XXX: validate this somehow

    try:
        input_json = cherrypy.request.json
        test = Test(input_json)

        status, value = get_coord_client().request_test(test, requesting_address=cherrypy.request.remote.ip)
    except Exception as e:
        print "Exception when adding test: %s" % e
        print traceback.format_exc()

    return value.to_json()

  @cherrypy.expose
  def get_test(self, id):
    status = None
    value  = None

    try:
        status, value = get_coord_client().get_test(id, requesting_address=cherrypy.request.remote.ip)
    except Exception as e:
        print "Exception when getting test: %s" % e
        print traceback.format_exc()

    return value.to_json()

  @cherrypy.expose
  def get_results(self, id):
    status = None
    value  = None

    try:
        status, value = get_coord_client().get_test_results(id, requesting_address=cherrypy.request.remote.ip)
    except:
        print "Exception when getting results: %s" % e
        print traceback.format_exc()

    # XXX: properly respond to 404, etc.

    return value.to_json()

  @cherrypy.expose
  def update_test(self, id):
    try:
        input_json = cherrypy.request.json
        test = Test(input_json)

        test.id = id

        status, value = get_coord_client().request_test(test, requesting_address=cherrypy.request.remote.ip)
    except Exception as e:
        print "Exception when adding test: %s" % e
        print traceback.format_exc()

    return value

  @cherrypy.expose
  def cancel_test(self, id):
    # Send a "cancel" message to the server
    status = None
    value  = None

    try:
        status, value = get_coord_client().cancel_test(id, requesting_address=cherrypy.request.remote.ip)
    except:
        print "Exception when cancelling test: %s" % e
        print traceback.format_exc()

    return {}

  @cherrypy.expose
  def accept_test(self, id):
    # Send an "accept" message to the server
    status = None
    value  = None

    try:
        status, value = get_coord_client().client_confirm_test(id, requesting_address=cherrypy.request.remote.ip)
    except:
        print "Exception when accepting test: %s" % e
        print traceback.format_exc()

    return {}
