from bwctl.coordinator import CoordinatorClient, CoordinatorServer
from multiprocessing import Process
import time
from bwctl.models import BWCTLError

auth_key = "12345"

def client1():
    client = CoordinatorClient(auth_key=auth_key)
    client.connect()
    status, value = client.cancel_test("1234567890")
    print "Client 1: Status: %d Msg: %s" % (status.error_code, status.error_msg)
    return

def client2():
    time.sleep(1)
    client = CoordinatorClient(auth_key=auth_key)
    client.connect()
    status, value = client.cancel_test("0987654321")
    print "Client 2: Status: %d Msg: %s" % (status.error_code, status.error_msg)
    return

def server():
    def finish_test_cb(requesting_address=None, test_id=None, value=None):
        print "Test %s finished" % test_id
        return BWCTLError(error_code=1, error_msg=""), None

    server = CoordinatorServer(auth_key=auth_key)
    server.set_callbacks(finish_test_cb=finish_test_cb)
    server.setup_listener()
    server.run()

if __name__ == '__main__':
    clients = []
    clients.append(Process(target=client1, args=()))
    clients.append(Process(target=client1, args=()))
    clients.append(Process(target=client1, args=()))
    clients.append(Process(target=client1, args=()))
    clients.append(Process(target=client1, args=()))
    clients.append(Process(target=client1, args=()))
    clients.append(Process(target=client1, args=()))
    clients.append(Process(target=client2, args=()))
    server = Process(target=server)

    server.start()
    time.sleep(1)
    for client in clients:
        client.start()

    for client in clients:
        client.join()

    server.terminate()
