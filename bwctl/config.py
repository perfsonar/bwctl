from configobj import ConfigObj, flatten_errors
from validate import Validator, ValidateError
import re

from bwctl.tools import get_tools
from bwctl.port_range import PortRange
from bwctl.exceptions import ValidationException

port_range_re = re.compile('(\d+)-(\d+)')
def port_range_check(value):
    if not value:
        return None

    if isinstance(value, list):
        raise ValidateError('A list was passed when a port range was expected')

    m = port_range_re.match(value)
    if not m:
        raise ValidateError('"%s" is not a port range' % value)

    min = int(m.group(1))
    max = int(m.group(2))

    if max <= min:
        raise ValidateError('"%s" is an invalid port range' % value)

    return PortRange(min=min, max=max)


def get_config_from_file(command_config_options={}, include_tool_options=True, config_file=None):
    config_lines = []
    if config_file:
        config_lines = [line.strip() for line in open(config_file)]

    return get_config(command_config_options=command_config_options,
                      include_tool_options=include_tool_options,
                      config_lines=config_lines)

def get_config(command_config_options={}, include_tool_options=True, config_lines=[]):
    full_config_options = {}

    for key, value in command_config_options.iteritems():
        full_config_options[key] = value

    # Initialize the configuration spec
    if include_tool_options:
        for tool in get_tools():
            for key, value in tool.config_options().iteritems():
                if key in full_config_options and \
                    value != full_config_options[key]:
                    raise ValidationException("Two tools use the config option '%s' but with different types" % key)

                full_config_options[key] = value 

    config_spec = []
    for option, type in full_config_options.iteritems():
        config_spec.append("%s = %s" % (option, type))

    validator = Validator({ 'port_range': port_range_check })

    config = ConfigObj(config_lines, configspec=config_spec)
    results = config.validate(validator)

    if results != True:
        for (section_list, key, _) in flatten_errors(config, results):
            if key is not None:
                raise ValidationException('The "%s" key in the section failed validation' % key)

    return config
