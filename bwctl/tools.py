from bwctl.exceptions import InvalidToolException, ValidationException
from validate import Validator

tool_classes = [
    "bwctl.tool_types.iperf.Iperf",
    "bwctl.tool_types.iperf3.Iperf3",
    "bwctl.tool_types.owamp.Owamp",
    "bwctl.tool_types.ping.Ping",
    "bwctl.tool_types.traceroute.Traceroute",
    "bwctl.tool_types.tracepath.Tracepath",
]

tools = {}
tool_modules_initialized = False

available_tools = []
available_tools_initialized = False

class ToolTypes:
    UNKNOWN    = 0
    THROUGHPUT = 1
    LATENCY    = 2
    TRACEROUTE = 3

class ToolResults:
    def __init__(self, start_time=None, end_time=None, return_code=0, stdout="", stderr=""):
        self.start_time = start_time
        self.end_time   = end_time
        self.return_code = return_code
        self.stdout     = stdout
        self.stderr     = stderr

class ToolParameter:
    def __init__(self, name="", type=""):
        self.name = name
        self.type = type
        self.validator = Validator()

    def check(self, value):
        retval = None
        try:
            retval = self.validator.check(self.type, str(value))
        except:
            raise ValidationException("Invalid parameter: %s" % self.name)
        return retval

def init_tool_modules():
    for tool_class_name in tool_classes:
        (module_name, class_name) = tool_class_name.rsplit('.', 1)

        module = __import__(module_name, fromlist=[class_name])
        tool_class = getattr(module, class_name)
        tool_name = tool_class.name
        # Create a "tool" object out of the imported class
        tools[tool_name] = tool_class()

def get_available_tools():
    global available_tools_initialized
    global available_tools

    if not available_tools_initialized:
        for tool in get_tools():
            if tool.check_available():
                available_tools.append(tool.name)

        available_tools_initialized = True

    return available_tools
 
def configure_tools(config):
    for tool in get_tools():
        tool.configure(config)

def get_tool_types():
    return tools.keys()

def get_tools():
    return tools.values()

def get_tool(name):
    if name in tools.keys():
        return tools[name]
    raise InvalidToolException

# Load the various tool modules
if not tool_modules_initialized:
    init_tool_modules()
    tools_initialized = True
