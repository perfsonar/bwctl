tool_classes = [
    "bwctl.tool_types.iperf.Iperf",
    "bwctl.tool_types.owamp.Owamp",
]

tools = {}
tools_initialized = False

class ToolTypes:
    UNKNOWN    = 0
    THROUGHPUT = 1
    LATENCY    = 2
    TRACEROUTE = 3

def init_tools():
    for tool_class_name in tool_classes:
        (module_name, class_name) = tool_class_name.rsplit('.', 1)

        module = __import__(module_name, fromlist=[class_name])
        tool_class = getattr(module, class_name)
        tool_name = tool_class.name
        # Create a "tool" object out of the imported class
        tools[tool_name] = tool_class()

def get_tool_types():
    return tools.keys()

def get_tool(name):
    if name in tools.keys():
        return tools[name]
    return None

# Load the various tool modules
if not tools_initialized:
    init_tools()
    tools_initialized = True
