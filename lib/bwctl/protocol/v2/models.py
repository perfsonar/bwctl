from bwctl import models
from bwctl import jsonobject

class ServerStatus(jsonobject.JsonObject):
    protocol = jsonobject.FloatProperty(exclude_if_none=True)
    time = jsonobject.DateTimeProperty(exact=True, exclude_if_none=True)
    ntp_error = jsonobject.FloatProperty(exclude_if_none=True)
    available_tools = jsonobject.ListProperty(unicode, exclude_if_none=True)
    version = jsonobject.StringProperty(exclude_if_none=True)

class BWCTLError(models.BWCTLError):
    def to_internal(self):
        return models.BWCTLError(self.to_json())

    @classmethod
    def from_internal(cls, object):
        return cls(object.to_json())

class Results(models.Results):
    def to_internal(self):
        return models.Results(self.to_json())

    @classmethod
    def from_internal(cls, object):
        return cls(object.to_json())

class ClientSettings(models.ClientSettings):
    def to_internal(self):
        return models.ClientSettings(self.to_json())

    @classmethod
    def from_internal(cls, object):
        return cls(object.to_json())

class SchedulingParameters(models.SchedulingParameters):
    def to_internal(self):
        return models.SchedulingParameters(self.to_json())

    @classmethod
    def from_internal(cls, object):
        return cls(object.to_json())

class Endpoint(models.Endpoint):
    def to_internal(self):
        return models.Endpoint(self.to_json())

    @classmethod
    def from_internal(cls, object):
        return cls(object.to_json())

class Test(models.Test):
    def to_internal(self):
        return models.Test(self.to_json())

    @classmethod
    def from_internal(cls, object):
        return cls(object.to_json())
