from bwctl.exceptions import InvalidToolException

tool_classes = [
    "bwctl.tool_types.iperf.Iperf",
    "bwctl.tool_types.owamp.Owamp",
    "bwctl.tool_types.ping.Ping",
    "bwctl.tool_types.traceroute.Traceroute",
]

tools = {}
tool_modules_initialized = False

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

def init_tool_modules():
    for tool_class_name in tool_classes:
        (module_name, class_name) = tool_class_name.rsplit('.', 1)

        module = __import__(module_name, fromlist=[class_name])
        tool_class = getattr(module, class_name)
        tool_name = tool_class.name
        # Create a "tool" object out of the imported class
        tools[tool_name] = tool_class()

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
