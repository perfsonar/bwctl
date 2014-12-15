import os

current_config = None

def get_config(config_file):
    if current_config == None:
        raise Exception("No configuration defined")

    return current_config

def init_config(config_file, override={}):
    if not os.path.exists(config_file):
        raise ConfigError("Configuration file not found: %s" % config_file)

    try:
        conf = BwctlConfig(config_file, opts)
    except ConfigParser.Error, e:
        raise ConfigError("Unable to parse configuration file: %s" % e)

    current_config = conf

    return

class BwctlConfig(object):
    def __init__(self, file, override={}):
        self.file = file

        # XXX: Define parameters here

        self.read_config(opts)
        self.convert_types()
        self.validate_config()

    def read_config(self):
        """ Read in the configuration from an INI-style file"""
        cfg = ConfigParser.SafeConfigParser()
        cfg.read(self.file)

        # Read in server parameters

        # Read in tool-specific parameters

    def convert_configuration(self):
        """convert_types -- convert input from config file format to appropriate internal format"""

    def validate_config(self):
        """validate_config -- make sure that the configuration makes sense"""

