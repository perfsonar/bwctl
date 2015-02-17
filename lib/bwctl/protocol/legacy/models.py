from struct import pack, unpack
import datetime
from calendar import timegm
import socket


#########
# Utility classes covering complex data types used by multiple messages
#########
class Timestamp:
    def __init__(self, time=datetime.datetime(1970,1,1,0,0,0)):
        self.time = time

    @staticmethod
    def parse(data):
        (seconds, nanoseconds) = unpack("! L L", data)

        scale = 2**32
        combined = (seconds << 32) | nanoseconds
        nanoseconds = combined % scale
        seconds = combined / scale

        # The resolution of nanoseconds can be greater than 1 second for some reason
        while nanoseconds > 1000000000:
            seconds = seconds + 1
            nanoseconds = nanoseconds - 1000000000

        # convert the seconds into seconds since 1970. It defaults to seconds since 1900.
        seconds = seconds - 0x83aa7e80

        # Truncate to microseconds since the datetime module only supports that level of granularity
        microseconds = int(nanoseconds / 1000)

        print "Seconds: %d" % seconds
        print "Nanoseconds: %d" % nanoseconds

        dt = datetime.datetime.utcfromtimestamp(seconds)
        dt = dt.replace(microsecond=microseconds)

        return Timestamp(time=dt)

    def unparse(self):
        seconds = timegm(self.time.utctimetuple())
        nanoseconds = self.time.microsecond * 1000

        # convert the seconds into seconds since 1900
        seconds = seconds + 0x83aa7e80

        return pack("! L L", seconds, nanoseconds)


class ErrorEstimate:
    def __init__(self, synchronized=False, error=0.001):
        self.synchronized = synchronized
        self.error = error

    @staticmethod
    def parse(data):
        (scale_synchronized, multiplier) = unpack("! B B", data)

        synchronized = False
        if scale_synchronized & 0x80:
            synchronized = True

        scale = scale_synchronized & 0x7F

        error = multiplier*(2**-32)*2**scale

        return ErrorEstimate(synchronized=synchronized, error=error)

    def unparse(self):
        scale = 0;
        error = self.error * 2**32
        while error >= 0xFF:
            error = error / 2
            scale = scale + 1

        multiplier = int(error) & 0xFF

        scale_synchronized = scale
        if self.synchronized:
            scale_synchronized = scale_synchronized | 0x80

        print "Error: %f Multiplier: %d Scale: %d" % (self.error, multiplier, scale)

        return pack("! B B", scale_synchronized, multiplier)

class Modes:
    OPEN = 1
    AUTHENTICATED = 2
    ENCRYPTED = 4

class AcceptType:
    INVALID = -1
    ACCEPT  = 0
    REJECT  = 1
    FAILURE = 2
    UNSUPPORTED = 4

class Tools:
    UNDEFINED        = 0
    IPERF            = 0x01
    NUTTCP           = 0x02
    THRULAY          = 0x04
    IPERF3           = 0x08
    PING             = 0x10
    TRACEROUTE       = 0x20
    TRACEPATH        = 0x40
    OWAMP            = 0x80
    PARIS_TRACEROUTE = 0x100

class MessageTypes:
    TestRequest  = 1
    StartSession = 2
    StopSession  = 3
    TimeRequest  = 4

class ServerGreeting:
    def __init__(self, modes=[ Modes.OPEN ], protocol_version=5, challenge=''):
        self.modes = modes
        self.protocol_version = protocol_version
        self.challenge = challenge

    @staticmethod
    def parse(data):
        (protocol_modes, challenge) = unpack("! 12x L 16s", data)
        protocol = (protocol_modes & 0xFF000000) >> 24

        modes = []
        mode = protocol_modes & 0x00FFFFFF
        if mode & Modes.OPEN:
            modes.append(Modes.OPEN)
        if mode & Modes.AUTHENTICATED:
            modes.append(Modes.AUTHENTICATED)
        if mode & Modes.ENCRYPTED:
            modes.append(Modes.ENCRYPTED)

        return ServerGreeting(modes=modes, protocol_version=protocol, challenge=challenge)

    def unparse(self):
        modes = 0
        for mode in self.modes:
            modes = modes | mode

        protocol_modes = (self.protocol_version << 24)|(modes)

        return pack("! 12x L 16s", protocol_modes, self.challenge)

class ClientGreeting:
    def __init__(self, protocol_version=5, mode=Modes.OPEN, username='', token='', client_iv=''):
        self.protocol_version = protocol_version
        self.mode = mode
        self.username = username
        self.token = token
        self.client_iv = client_iv

    @staticmethod
    def parse(data):
        (protocol_modes, username, token, client_iv) = unpack("! L 16s 32s 16s", data)

        protocol = (protocol_modes & 0xFF000000) >> 24
        mode = protocol_modes & 0x00FFFFFF

        return ClientGreeting(protocol_version=protocol, mode=mode, username=username, token=token, client_iv=client_iv)

    def unparse(self):
        protocol_mode = (self.protocol_version << 24)|(self.mode)

        return pack("! L 16s 32s 16s", protocol_mode, self.username, self.token, self.client_iv)

class ServerOK:
    def __init__(self, tools=[], server_iv='', uptime=0.0, accept_type=AcceptType.ACCEPT):
        self.tools = tools
        self.server_iv = server_iv
        self.uptime = uptime
        self.accept_type = accept_type

    @staticmethod
    def parse(data):
        (tools_str, accept_type, server_iv, uptime, zero_padding) = unpack("! L 11x b 16s Q Q", data)

        tools = []
        if tools_str & Tools.IPERF:
            tools.append(Tools.IPERF)
        if tools_str & Tools.NUTTCP:
            tools.append(Tools.NUTTCP)
        if tools_str & Tools.THRULAY:
            tools.append(Tools.THRULAY)
        if tools_str & Tools.IPERF3:
            tools.append(Tools.IPERF3)
        if tools_str & Tools.PING:
            tools.append(Tools.PING)
        if tools_str & Tools.TRACEROUTE:
            tools.append(Tools.TRACEROUTE)
        if tools_str & Tools.TRACEPATH:
            tools.append(Tools.TRACEPATH)
        if tools_str & Tools.PARIS_TRACEROUTE:
            tools.append(Tools.PARIS_TRACEROUTE)

        return ServerOK(tools=tools, accept_type=accept_type, server_iv=server_iv, uptime=uptime)

    def unparse(self):
        tools = 0
        for tool in self.tools:
            tools = tools | tool

        return pack("! L 11x b 16s Q Q", tools, self.accept_type, self.server_iv, self.uptime, 0)

class MessageType:
    def __init__(self, message_type=1):
        self.message_type = message_type

    @staticmethod
    def parse(data):
        (msg_type,) = unpack("! B", data)

        return MessageType(message_type=msg_type)

    def unparse(self, include_msg_hdr=True):
        return pack("! B", self.message_type)

class TimeRequest:
    @staticmethod
    def parse(data, has_msg_hdr=True):
        if has_msg_hdr:
            (msg_type, zero_padding_1, zero_padding_2) = unpack("! B 15x 2Q", data)
        else:
            msg_type = MessageTypes.TimeRequest
            (zero_padding_1, zero_padding_2) = unpack("! 15x 2Q", data)

        if msg_type != MessageTypes.TimeRequest:
            raise Exception("Message type isn't a TimeRequest")

        return TimeRequest()

    def unparse(self, include_msg_hdr=True):
        if include_msg_hdr:
            return pack("! B 15x 2Q", MessageTypes.TimeRequest, 0, 0)
        else:
            return pack("! 15x 2Q", 0, 0)

class TimeResponse:
    def __init__(self, timestamp=0, error_estimate=0):
        self.timestamp      = timestamp
        self.error_estimate = error_estimate

    @staticmethod
    def parse(data):
        (timestamp_str, error_estimate_str, zero_padding_1, zero_padding_2) = unpack("! 8s 2s 6x 2Q", data)

        timestamp = Timestamp.parse(timestamp_str)
        error_estimate = ErrorEstimate.parse(error_estimate_str)

        return TimeResponse(timestamp=timestamp, error_estimate=error_estimate)

    def unparse(self):
        timestamp_str = self.timestamp.unparse()
        error_estimate_str = self.error_estimate.unparse()

        return pack("! 8s 2s 6x 2Q", timestamp_str, error_estimate_str, 0, 0)

class TestAccept:
    def __init__(self, accept_type=AcceptType.ACCEPT, port=0, sid='', reservation_time=0):
        self.accept_type = accept_type
        self.port = port
        self.sid = sid
        self.reservation_time = reservation_time

    @staticmethod
    def parse(data):
        (accept_type, port, sid, reservation_time_str) = unpack("! B x H 16s 8s 4x", data)

        reservation_time = Timestamp.parse(reservation_time_str)

        return TestAccept(accept_type=accept_type, port=port, sid=sid, reservation_time=reservation_time)

    def unparse(self):
        reservation_time_str = self.reservation_time.unparse()
        return pack("! B x H 16s 8s 4x", self.accept_type, self.port, self.sid, reservation_time_str, 0)

class StartAck:
    def __init__(self, accept_type=AcceptType.ACCEPT, peer_port=0):
        self.accept_type = accept_type
        self.peer_port = peer_port

    @staticmethod
    def parse(data):
        (accept_type, peer_port, zero_padding_1, zero_padding_2) = unpack("! B x H 12x 2Q", data)

        return StartAck(accept_type=accept_type, peer_port=peer_port)

    def unparse(self):
        return pack("! B x H 12x 2Q", self.accept_type, self.peer_port, 0, 0)

class StopSession:
    def __init__(self, result_status=AcceptType.ACCEPT, result_length=0):
        self.result_status = result_status
        self.result_length = result_length

    @staticmethod
    def parse(data, has_msg_hdr=True):
        if has_msg_hdr:
            (msg_type, accept_type, result_length, zero_padding_1, zero_padding_2) = unpack("! B B 6x L 4x 2Q", data)
        else:
            msg_type = MessageTypes.StopSession
            (accept_type, result_length, zero_padding_1, zero_padding_2) = unpack("! B B 6x L 4x 2Q", data)

        if msg_type != MessageTypes.StopSession:
            raise Exception("Message type isn't a StopSession")

        return StopSession(result_status=accept_type, result_length=result_length)

    def unparse(self, include_msg_hdr=True):
        if include_msg_hdr:
            return pack("! B B 6x L 4x 2Q", MessageTypes.StopSession, self.result_status, self.result_length, 0, 0)
        else:
            return pack("! B 6x L 4x 2Q", self.result_status, self.result_length, 0, 0)


class StartSession:
    def __init__(self, peer_port=0):
        self.peer_port = peer_port

    @staticmethod
    def parse(data, has_msg_hdr=True):
        if has_msg_hdr:
            (msg_type, peer_port, zero_padding_1, zero_padding_2) = unpack("! B x H 12x 2Q", data)
        else:
            msg_type = MessageTypes.StopSession
            (peer_port, zero_padding_1, zero_padding_2) = unpack("! B x H 12x 2Q", data)

        if msg_type != MessageTypes.StartSession:
            raise Exception("Message type isn't a StartSession")

        return StartSession(peer_port=peer_port)

    def unparse(self, include_msg_hdr=True):
        if include_msg_hdr:
            return pack("! B x H 12x 2Q", MessageTypes.StartSession, self.peer_port, 0, 0)
        else:
            return pack("! x H 12x 2Q", self.peer_port, 0, 0)

class TestRequest:
    def __init__(self, protocol_version=5, ip_version=4, is_client=True, requested_time=Timestamp(),
                 latest_time=Timestamp(), error_estimate=ErrorEstimate(), client_address="0.0.0.0", server_address="0.0.0.0",
                 recv_port=0,sid="", tool=Tools.UNDEFINED, verbose=False, reverse=False, no_endpoint=False,
                 # Shared test parameters
                 duration=0, packet_size=0,
                 # Bandwidth test-specific parameters
                 output_format="", bandwidth=0, omit_time=0, units="",
                 tos_bits=0, parallel_streams=0, buffer_length=0, window_size=0, report_interval=0,
                 is_udp=False, dynamic_window=False,
                 # Ping test-specific parameters
                 packet_count=0, inter_packet_delay=0, packet_ttl=0,
                 # Traceroute test-specific parameters
                 first_ttl=0, last_ttl=0):

        self.protocol_version=protocol_version
        self.ip_version=ip_version
        self.is_client=is_client
        self.requested_time=requested_time
        self.latest_time=latest_time
        self.error_estimate=error_estimate
        self.client_address=client_address
        self.server_address=server_address
        self.recv_port=recv_port
        self.sid=sid
        self.tool=tool
        self.verbose=verbose
        self.reverse=reverse
        self.no_endpoint=no_endpoint

        # Shared test parameters
        self.duration=duration
        self.packet_size=packet_size

        # Bandwidth test-specific parameters
        self.output_format=output_format
        self.bandwidth=bandwidth
        self.omit_time=omit_time
        self.units=units
        self.tos_bits=tos_bits
        self.parallel_streams=parallel_streams
        self.buffer_length=buffer_length
        self.window_size=window_size
        self.report_interval=report_interval
        self.is_udp=is_udp
        self.dynamic_window=dynamic_window

        # Ping test-specific parameters
        self.packet_count=packet_count
        self.inter_packet_delay=inter_packet_delay
        self.packet_ttl=packet_ttl

        # Traceroute test-specific parameters
        self.first_ttl=first_ttl
        self.last_ttl=last_ttl

    @staticmethod
    def parse(data, has_msg_hdr=True, protocol_version=5):
        if has_msg_hdr:
            (msg_type, data) = unpack("! B 127s", data)
        else:
            msg_type = MessageTypes.TestRequest

        if msg_type != MessageTypes.TestRequest:
            raise Exception("Message type isn't a TestRequest")

        test_request = TestRequest()

        # Grab client/server information
        (udp_ip_version, conf_client, conf_server) = unpack("! B B B 124x", data)
        ip_version = udp_ip_version & 0x0F

        if conf_client == 0 and conf_server != 0:
            test_request.is_client = False
        elif conf_client != 0 and conf_server == 0:
            test_request.is_client = True
        else:
            raise Exception("Invalid client/server settings: %d/%d" % (conf_client, conf_server))

        if ip_version == 4:
            (client_ip, server_ip) = unpack("! 27x 4s 12x 4s 80x", data)
            address_family = socket.AF_INET
        elif ip_version == 6:
            (client_ip, server_ip) = unpack("! 27x 16s 16s 80x", data)
            address_family = socket.AF_INET6
        else:
            raise Exception("Unknown IP type: %d" % ip_version)

        test_request.client_address = inet_ntop(address_family, client_ip)
        test_request.server_address = inet_ntop(address_family, server_ip)

        # Grab time information
        (requested_time_str, latest_time_str, error_estimate_str) = unpack("! 7x 8s 8s 2s 102x", data)
        test_request.requested_time = Timestamp.parse(requested_time_str)
        test_request.latest_time = Timestamp.parse(latest_time_str)
        test_request.error_estimate = ErrorEstimate.parse(error_estimate_str)

       # Grab misc. other common test parameters
        (recv_port, sid, tool, verbose, reverse, no_endpoint) = unpack("! 25x H 32x 16s 20x L B B B 25x", data)

        test_request.recv_port = recv_port
        test_request.sid = sid
        test_request.tool = tool

        if verbose != 0:
            test_request.verbose = True
        else:
            test_request.verbose = False

        if reverse != 0:
            test_request.reverse = True
        else:
            test_request.reverse = False

        if no_endpoint != 0:
            test_request.no_endpoint = True
        else:
            test_request.no_endpoint = False

        if tool == Tools.IPERF or tool == Tools.IPERF3 or tool == Tools.NUTTCP:
            udp = udp_ip_version & 0xF0
            if udp == 0:
                test_request.is_udp = False
            else:
                test_request.is_udp = True

            results = unpack("! 3x L 68x L L L L B B B 13x 1s B B 1s 16x", data)

            test_request.duration = results[0]
            test_request.bandwidth = results[1]
            test_request.buffer_length = results[2]
            test_request.window_size = results[3]
            test_request.report_interval = results[4]
            if results[5] != 0:
                test_request.dynamic_window = True
            else:
                test_request.dynamic_window = False
            test_request.tos_bits = results[6]
            test_request.parallel_streams = results[7]
            test_request.output_format = results[8]
            if results[9] != 0:
                test_request.bandwidth = test_request.bandwidth * 2**results[9]
            test_request.omit_time = results[10]
            test_request.units = results[11]
        elif tool == Tools.PING or tool == Tools.OWAMP:
            (packet_count, packet_size, inter_packet_delay, packet_ttl) = unpack("! 75x H H H B 45x", data)
            test_request.packet_count = packet_count
            test_request.packet_size = packet_size 
            test_request.inter_packet_delay = inter_packet_delay
            test_request.packet_ttl = packet_ttl
        elif tool == Tools.TRACEPATH or tool == Tools.TRACEROUTE or tool == Tools.PARIS_TRACEROUTE:
            (first_ttl, last_ttl, packet_size) = unpack("! 75x B B H 48x", data)
            test_request.packet_count = packet_count
            test_request.packet_size = packet_size 
            test_request.inter_packet_delay = inter_packet_delay
            test_request.packet_ttl = packet_ttl
        else:
            raise Exception("Unknown tool type: %d" % tool)

        return test_request

    def unparse(self, include_msg_hdr=True):
        data = ""

        addr_type = None
        for curr_addr_type in [ socket.AF_INET, socket.AF_INET6 ]:
            try:
                client_ip = socket.inet_pton(curr_addr_type, self.client_address)
                server_ip = socket.inet_pton(curr_addr_type, self.server_address)
                addr_type = curr_addr_type
            except Exception as e:
                print "Exception: %s" % e
                pass

        if not addr_type:
            raise Exception("IP type mismatch")

        if self.is_client:
            conf_client = 1
            conf_server = 0
        else:
            conf_client = 0
            conf_server = 1

        udp_ip_version = 4
        if addr_type == socket.AF_INET6:
            udp_ip_version = 6

        if self.tool == Tools.IPERF or self.tool == Tools.IPERF3 or self.tool == Tools.NUTTCP:
            if self.is_udp:
                udp_ip_version = udp_ip_version | 0x10

        data = data + pack("! B B B", udp_ip_version, conf_client, conf_server)

        # Add in time information, and the receive port
        requested_time_str = self.requested_time.unparse()
        latest_time_str = self.latest_time.unparse()
        error_estimate_str = self.error_estimate.unparse()

        data = data + pack("! L 8s 8s 2s H", self.duration, requested_time_str, latest_time_str, error_estimate_str, self.recv_port)

        import binascii
        print "  Post Time: %d %s" % (len(data), binascii.hexlify(data))

        # Add in the address information
        if len(client_ip) == 4:
            ip_info = pack("! 4s 12x 4s 12x", client_ip, server_ip)
        else:
            ip_info = pack("! 16s 16s", client_ip, server_ip)

        data = data + ip_info

        print "  Post IP: %d %s" % (len(data), binascii.hexlify(data))

        # Add in the SID
        data = data + pack("! 16s", self.sid)

        print "  Post SID: %d %s" % (len(data), binascii.hexlify(data))

        if self.tool == Tools.IPERF or self.tool == Tools.IPERF3 or self.tool == Tools.NUTTCP:
            bandwidth = self.bandwidth
            scale = 0
            while bandwidth > 2**32:
                bandwidth = bandwidth / 2
                scale = scale + 1

            dynamic = 0
            if self.dynamic_window:
                dynamic = 1
            data = data + pack("! L L L L B B B x", bandwidth, self.buffer_length, self.window_size, self.report_interval, dynamic, self.tos_bits, self.parallel_streams)
        elif self.tool == Tools.PING or self.tool == Tools.OWAMP:
            data = data + pack("! H H H B 13x", self.packet_count, self.packet_size, self.inter_packet_delay, self.packet_ttl)
        elif self.tool == Tools.TRACEROUTE or self.tool == Tools.TRACEPATH or self.tool == Tools.PARIS_TRACEROUTE:
            data = data + pack("! B B H 16x", self.first_ttl, self.last_ttl, self.packet_size)

        print "  Post Tools: %d %s" % (len(data), binascii.hexlify(data))

        verbose = 0
        if self.verbose:
            verbose = 1

        reverse = 0
        if self.reverse:
            reverse = 1

        no_endpoint = 0
        if self.no_endpoint:
            no_endpoint = 1

        data = data + pack("! L B B B x", self.tool, verbose, reverse, no_endpoint)

        print "  Post Verbose, et al: %d %s" % (len(data), binascii.hexlify(data))

        if self.tool == Tools.IPERF or self.tool == Tools.IPERF3 or self.tool == Tools.NUTTCP:
            data = data + pack("! 4x 1s B B 1s", self.output_format, scale, self.omit_time, self.units)
        else:
            data = data + pack("! 8x") 

        print "  Post Tools, et al: %d %s" % (len(data), binascii.hexlify(data))

        data = data + pack("! 16x") 

        print "  Post Whitespace: %d %s" % (len(data), binascii.hexlify(data))

        if include_msg_hdr:
            data = pack("! B 127s", MessageTypes.TestRequest, data)

        return data

