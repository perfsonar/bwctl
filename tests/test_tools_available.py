from bwctl.config import get_config
from bwctl.tools import get_tools

config = get_config()

for tool in get_tools():
    tool.configure(config)
    available = tool.check_available()
    if available:
        print "%s is available" % tool.name
    else:
        print "%s is not available" % tool.name
