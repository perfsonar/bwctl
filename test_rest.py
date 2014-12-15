import time
from bwctl.rest_api_server import RestApiServer

rest_api_server = RestApiServer()
rest_api_server.run()
try:
    time.sleep(60)
except:
    pass
rest_api_server.stop()
