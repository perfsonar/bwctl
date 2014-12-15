class Base:
    name = ""
    known_parameters = []

    def check_parameters(self, parameters):
        for parameter in parameters.keys():
            if not parameter in self.known_parameters:
                return False

        return True

    def check_config(self, cfg):
        pass

    def validate_test(self, test):
        return True

    def build_command_line(self, test):
        raise Exception("build_command_line must be overwritten")

    def get_results(self, exit_status=0, stdout="", stderr=""):
        return {
            'tool_results': stderr + stdout,
        }
