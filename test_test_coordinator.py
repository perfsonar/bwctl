from bwctl.server.test_coordinator import TestCoordinator
from bwctl.server.coordinator import CoordinatorClient, CoordinatorServer
from bwctl.server.rest_api_server import RestApiServer
from bwctl.server.tests_db import TestsDB

server_address = "127.0.0.1"
server_port = 1234

coord_client = CoordinatorClient(server_address=server_address, server_port=server_port)

tests_db = TestsDB()

rest_api_server = RestApiServer(coordinator_client=coord_client)
test_coordinator = TestCoordinator(server_address=server_address, server_port=server_port, tests_db=tests_db)

try:
    test_coordinator.start()
    rest_api_server.start()

    test_coordinator.join()
finally:
    print "Killing children of rest api server"
    rest_api_server.kill_children()
    rest_api_server.terminate()
