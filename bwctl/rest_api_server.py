import cherrypy
from cherrypy.process import wspbus, plugins
from sqlalchemy.orm import scoped_session, sessionmaker

import datetime

from protocol.models import ServerStatus

import bwctl.server

class RestApiServer():
    def __init__(self, coordinator_client=None):
        status_controller = StatusController()
        tests_controller = TestsController()

        dispatcher = cherrypy.dispatch.RoutesDispatcher()

        # Status URL
        dispatcher.connect('status', '/bwctl/status', controller=status_controller, action='status')

        # Test URLs
        dispatcher.connect('new_test',    '/bwctl/tests', controller=tests_controller, action='status')
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
            }
        })

        self.coordinator_client = coordinator_client

    def run(self):
        cherrypy.engine.start()

    def stop(self):
        cherrypy.engine.exit()

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
    pass

  @cherrypy.expose
  def get_test(self, id):
    return { "test": test }

  @cherrypy.expose
  def update_test(self, id):
    cherrypy.request.remote.ip

    pass

  @cherrypy.expose
  def cancel_test(self, id):
    # Send a "cancel" message to the server
    pass

  @cherrypy.expose
  def accept_test(self, id):
    # Send an "accept" message to the server
    pass

  @cherrypy.expose
  def get_results(self, id):
    pass
