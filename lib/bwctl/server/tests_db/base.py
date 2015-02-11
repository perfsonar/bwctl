import uuid
from bwctl.exceptions import ResourceNotFoundException

class Base:
    def get_test(self, test_id):
        raise Exception("get_test must be overridden")

    def add_test(self, test):
        raise Exception("add_test must be overridden")

    def replace_test(self, test_id, test):
        raise Exception("replace_test must be overridden")

    def add_results(self, test_id, results):
        raise Exception("add_results must be overridden")

    def get_results(self, test_id):
        raise Exception("get_results must be overridden")
