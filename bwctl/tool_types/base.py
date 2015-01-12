from bwctl.tools import ToolTypes

class Base:
    name = ""
    type = ToolTypes.UNKNOWN
    known_parameters = []

    def check_parameters(self, parameters):
        for parameter in parameters.keys():
            if not parameter in self.known_parameters:
                return False

        return True

    def receiver_is_client(self, test):
        if "receiver_connects" in self.known_parameters and "receiver_connects" in test.tool_parameters:
            return test.tool_parameters["receiver_connects"]

        return False

    def check_config(self, cfg):
        pass

    def validate_test(self, test):
        return True

    def build_command_line(self, test):
        raise Exception("build_command_line must be overwritten")

    def get_results(self, exit_status=0, stdout="", stderr=""):
        from bwctl.models import Results

        return Results(status="finished", results={ 'output': stderr+stdout })

    def duration(self, test):
        """ Returns the test length, a required paramter. If 'duration' isn't an
            available parameter for this tool, this function needs overwritten  """

        if 'duration' in test.tool_parameters:
            return test.tool_parameters['duration']
        else:
            raise Exception("Unknown test duration")

    def bandwidth(self, test):
        """ Returns the network bandwidth this test uses. If 'bandwidth' isn't an
            available parameter for this tool.  """

        if 'bandwidth' in test.tool_parameters:
            return test.tool_parameters['bandwidth']
        else:
            return 0
