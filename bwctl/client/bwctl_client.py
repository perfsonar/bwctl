import datetime
import math
import optparse
import re
import socket
import sys
import time
import inspect

from multiprocessing import Queue

from bwctl import __version__
from bwctl.dependencies.requests.exceptions import HTTPError

#-B|--local_address <address>     Use this as a local address for control connection and tests
#-E|--no_endpoint                 Allow tests to occur when the receiver isn't running bwctl (Default: False)
#-o|--flip                        Have the receiver connect to the sender (Default: False)
#
#Test Arguments
#--tester_port <port>             For an endpoint-less test, use this port as the server port (Default: tool specific)
#
#Output Arguments
#-e|--facility <facility>         Syslog facility to log to
#-r|--syslog_to_stderr            Send syslog to stderr (Default: False)
#-x|--both                        Output both sender and receiver results

from bwctl.protocol.v2.client import Client

from bwctl.protocol.legacy.client import Client as LegacyClient
from bwctl.protocol.legacy.utils import tool_name_by_id
from bwctl.protocol.legacy.models import AcceptType, Tools, TestRequest, Timestamp, ErrorEstimate

from bwctl.client.outputter import *
from bwctl.client.scheduler import IntervalScheduler, StreamingScheduler, SingleTestScheduler
from bwctl.tools import get_tools, get_tool, ToolTypes, configure_tools, get_available_tools
from bwctl.tool_runner import ToolRunner
from bwctl.models import Test, Endpoint, SchedulingParameters, ClientSettings, Results
from bwctl.utils import get_ip, is_ipv6, timedelta_seconds, discover_source_address
from bwctl.config import get_config
from bwctl.utils import init_logging

from urlparse import urlparse

class EndpointAddress(object):
    def __init__(self, scheme="", address="", port=None, path=""):
        self.scheme = scheme
        self.address = address
        self.port = None
        if port:
            self.port = int(port)
        self.path = path

    def resolve(self, require_ipv6=False, require_ipv4=False):
        ip = get_ip(self.address, require_ipv6=require_ipv6, require_ipv4=require_ipv4)
        if not ip:
            raise Exception("Could not find a suitable address for %s" % self.address)

        return EndpointAddress(
                     scheme  = self.scheme,
                     address = ip,
                     port    = self.port,
                     path    = self.path,
               )


    @classmethod
    def parse(cls, endpoint):
        m = re.match("^[(.*)]:(\d+)$", endpoint)
        if m:
            return EndpointAddress(
                         address = m.group(1),
                         port    = m.group(2)
                   )


        m = re.match("^[(.*)]$", endpoint)
        if m:
            return EndpointAddress(
                         address = m.group(1),
                   )

        try:
            if is_ipv6(endpoint):
                return EndpointAddress(
                         address = endpoint,
                       )
        except:
            pass

        m = re.match("^(.*):(\d+)$", endpoint)
        if m:
            return EndpointAddress(
                         address = m.group(1),
                         port    = m.group(2)
                   )

        url = urlparse(endpoint)
        if url.scheme:
            return EndpointAddress(
                         scheme  = url.scheme,
                         address = url.hostname,
                         port    = url.port,
                         path    = url.path,
                   )

        return EndpointAddress(
                 address = endpoint,
               )

def initialize_endpoint(local_address=None, remote_address=None, tool_type=None,
                        is_sender=False, is_server=False, out=None):

    local_endpoint_fallback = False

    if not local_address:
       local_ip = discover_source_address(remote_address.address)
       if not local_ip:
           raise Exception("Error: couldn't figure out which address to use to connect to %s" % remote_address.address)

       local_endpoint_fallback = True
       local_address = EndpointAddress(address=local_ip)

    if local_address.scheme:
        ep_types = [ "current" ]
    elif local_address.port and local_address.port == 4823:
        ep_types = [ "legacy", "current" ]
    else:
        ep_types = [ "current", "legacy" ]

    ret_endpoint = None
    for ep_type in ep_types:
        if ep_type == "current":
            endpoint = ClientEndpoint(
                            address=local_address.address,
                            port=local_address.port,
                            path=local_address.path,
                            is_sender=is_sender,
                            is_server=is_server
                      )
        elif ep_type == "legacy":
            endpoint = LegacyClientEndpoint(
                            address=local_address.address,
                            port=local_address.port,
                            is_sender=is_sender,
                            is_server=is_server
                       )

        try:
            endpoint.initialize()
            ret_endpoint = endpoint
        except Exception as e:
            out.debug("Couldn't connect to server with %s protocol: %s: %s" % (ep_type, local_address.address, e))
            pass

        if ret_endpoint:
            break

    if not ret_endpoint and local_endpoint_fallback:
       endpoint = LocalEndpoint(address=local_ip, is_sender=is_sender, tool_type=tool_type)
       endpoint.initialize()
       return endpoint

    if not ret_endpoint:
       raise Exception("Error: couldn't connect to %s" % local_address.address)

    return ret_endpoint

def add_traceroute_test_options(oparse):
    oparse.add_option("-F", "--first_ttl", dest="first_ttl", default=0, type="int",
                      help="minimum TTL for traceroute"
                     )
    oparse.add_option("-M", "--max_ttl", dest="max_ttl", default=0, type="int",
                      help="maximum TTL for traceroute"
                     )
    oparse.add_option("-l", "--packet_size", dest="packet_size", default=0, type="int",
                      help="Size of packets (bytes)"
                     )
    oparse.add_option("-t", "--test_duration", dest="test_duration", default=10, type="int",
                      help="Maximum time to wait for traceroute to finish (seconds) (Default: 10)"
                     )
    oparse.add_option("-S", "--tos", dest="tos", type="int",
                      help="Type-Of-Service for outgoing packets"
                     )

def fill_traceroute_tool_parameters(opts, tool_parameters):
    if opts.first_ttl:
        tool_parameters["first_ttl"] = opts.first_ttl

    if opts.max_ttl:
        tool_parameters["last_ttl"] = opts.max_ttl

    if opts.packet_size:
        tool_parameters["packet_size"] = opts.packet_size

    if opts.test_duration:
        tool_parameters["maximum_duration"] = opts.test_duration
    
    if opts.tos:
        tool_parameters["tos_bits"] = opts.tos

def fill_selected_traceroute_tool_parameters(opts, tool_parameters, tool):
    pass

def add_latency_test_options(oparse):
    oparse.add_option("-i", "--packet_interval", dest="packet_interval", default=1.0, type="float",
                      help="Delay between packets (seconds) (Default: 1.0)"
                     )
    oparse.add_option("-l", "--packet_size", dest="packet_size", default=0, type="int",
                      help="Size of packets (bytes)"
                     )
    oparse.add_option("-N", "--num_packets", dest="num_packets", default=10, type="int",
                      help="Number of packets to send (Default: 10)"
                     )
    oparse.add_option("-t", "--ttl", dest="ttl", default=0, type="int",
                      help="TTL for packets"
                     )
    oparse.add_option("-S", "--tos", dest="tos", type="int",
                      help="Type-Of-Service for outgoing packets"
                     )
    oparse.add_option("-f", "--units", dest="units", type="string",
                      help="Type of measurement units to return (Default: tool specific)"
                     )

def fill_latency_tool_parameters(opts, tool_parameters):
    if opts.num_packets:
        tool_parameters["packet_count"] = opts.num_packets

    if opts.packet_interval:
        tool_parameters["inter_packet_time"] = opts.packet_interval

    if opts.packet_size:
        tool_parameters["packet_size"] = opts.packet_size

    if opts.ttl:
        tool_parameters["packet_ttl"] = opts.ttl
    
    if opts.tos:
        tool_parameters["tos_bits"] = opts.tos
    
    if opts.units:
        tool_parameters["units"] = opts.units

def fill_selected_latency_tool_parameters(opts, tool_parameters, tool):
    duration = opts.packet_interval * opts.num_packets
    finishing_time = 3 # OWAMP takes longer to finish
    if tool == "ping": # give a second or so for the ping response to be received.
        finishing_time = 1
    tool_parameters["maximum_duration"] = duration + finishing_time

def add_throughput_test_options(oparse):
    oparse.add_option("-t", "--test_duration", dest="test_duration", default=10, type="int",
                      help="Duration for test (seconds) (Default: 10)"
                     )
    oparse.add_option("-b", "--bandwidth", dest="bandwidth", default=0, type="int",
                      help="Bandwidth to use for tests (Mbits/sec) (Default: 1Mb for UDP tests, unlimited for TCP tests)"
                     )
    oparse.add_option("-i", "--report_interval", dest="report_interval", default=2, type="float",
                      help="Reporting interval (seconds) (Default: 2.0 seconds)"
                     )
    oparse.add_option("-l", "--buffer_size", dest="buffer_size", default=0, type="int",
                      help="Size of read/write buffers (Kb)"
                     )
    oparse.add_option("-O", "--omit", dest="omit", default=0, type="int",
                      help="Omit time. Currently only for iperf3 (seconds)"
                     )
    oparse.add_option("-P", "--parallel", dest="parallel", default=1, type="int",
                      help="Number of concurrent connections"
                     )
    oparse.add_option("-w", "--window_size", dest="window_size", default=0, type="int",
                      help="TCP window size (Kb) (Default: system default)"
                     )
    oparse.add_option("-u", "--udp", dest="udp", action="store_true", default=False,
                      help="Perform a UDP test"
                     )
    oparse.add_option("-S", "--tos", dest="tos", type="int",
                      help="Type-Of-Service for outgoing packets"
                     )
    oparse.add_option("-f", "--units", dest="units", type="string",
                      help="Type of measurement units to return (Default: tool specific)"
                     )

def fill_throughput_tool_parameters(opts, tool_parameters):
    if opts.test_duration:
        tool_parameters["duration"] = opts.test_duration

    if opts.bandwidth:
        tool_parameters["bandwidth"] = opts.bandwidth

    if opts.report_interval:
        tool_parameters["report_interval"] = opts.report_interval

    if opts.buffer_size:
        tool_parameters["buffer_size"] = opts.buffer_size

    if opts.omit:
        tool_parameters["omit_seconds"] = opts.omit

    if opts.parallel:
        tool_parameters["parallel_streams"] = opts.parallel

    if opts.window_size:
        tool_parameters["window_size"] = opts.window_size

    if opts.udp:
        tool_parameters["protocol"] = "udp"

    if opts.tos:
        tool_parameters["tos_bits"] = opts.tos
    
    if opts.units:
        tool_parameters["units"] = opts.units
    
    if opts.format:
        tool_parameters["output_format"] = opts.format

def fill_selected_throughput_tool_parameters(opts, tool_parameters, tool):
    #Set iperf3 output to JSON if parsable. All other tools use default output
    if tool == "iperf3":
        if opts.parsable:
            tool_parameters["output_format"] = "J"

def valid_tool(tool_name, tool_type=None, tool_parameters={}):
    try:
        tool_obj = get_tool(tool_name)
        if tool_type and tool_obj.type != tool_type:
            raise Exception

        tool_obj.validate_parameters(tool_parameters)

        return True
    except:
        pass

    return False

def select_tool(client_tools=[], server_tools=[], requested_tools=[], tool_type=None, tool_parameters={}):
    common_tools = []
    for tool in server_tools:
        if valid_tool(tool, tool_type=tool_type, tool_parameters=tool_parameters) and \
           tool in client_tools:
                common_tools.append(tool)

    for tool in client_tools:
        if valid_tool(tool, tool_type=tool_type, tool_parameters=tool_parameters) and \
           tool in server_tools and \
           not tool in common_tools:
            common_tools.append(tool)

    for tool in requested_tools:
        if valid_tool(tool, tool_type=tool_type, tool_parameters=tool_parameters) and \
           tool in client_tools and \
           tool in server_tools:
            return tool, common_tools

    return None, common_tools

def add_tool_options(oparse, tool_type=ToolTypes.UNKNOWN):
    available_tools = []
    for tool in get_tools():
        if tool.type == tool_type:
            available_tools.append(tool.name)

    default_str = ""
    if tool_type == ToolTypes.THROUGHPUT:
        default_str="iperf3,nuttcp,iperf"
    elif tool_type == ToolTypes.LATENCY:
        default_str="ping,owamp"
    elif tool_type == ToolTypes.TRACEROUTE:
        default_str="traceroute,tracepath,paris-traceroute"

    available_tools_str = ", ".join(available_tools)

    oparse.add_option("-T", "--tools", dest="tools", default=default_str,
                      help="The tool to use for the test. Available: %s" % available_tools_str
                     )

def init_scheduler(opts):
    #determine number of tests
    kwargs = {}
    if opts.num_tests: 
        kwargs['max_num_tests']=opts.num_tests
    
    if opts.test_interval:
        kwargs['interval'] = opts.test_interval
        if opts.rand_start:
            kwargs['rand_start'] = opts.rand_start
        scheduler=IntervalScheduler(**kwargs)
        return scheduler
    elif opts.streaming:
        return StreamingScheduler(**kwargs)
    elif opts.schedule:
        raise Exception("--schedule not yet implemented")
        
    return SingleTestScheduler()

def init_outputter(opts):
    
    #determine output level
    output_level=LVL_NORMAL
    if opts.quiet:
        return QuietOutputter()
    elif opts.verbose:
        output_level=LVL_VERBOSE
    
    #build outputter
    outputter = None
    if opts.print_fname:
        if opts.output_dir:
            outputter = JSONFileOutputter(filedir=opts.output_dir, level=output_level)
        else:
            outputter = JSONFileOutputter(level=output_level)
    elif opts.parsable:
        outputter = JSONScreenOutputter(level=output_level)
    else:
        outputter = ScreenOutputter(level=output_level)
    
    return outputter

def initialize_endpoints(tool_type, opts, out):
    receiver_address = None
    receiver_ip = None
    if opts.receiver:
        receiver_address = EndpointAddress.parse(opts.receiver)
        receiver_ip = receiver_address.resolve(require_ipv4=opts.require_ipv4,
                                               require_ipv6=opts.require_ipv6)

    sender_address = None
    sender_ip = None
    if opts.sender:
        sender_address = EndpointAddress.parse(opts.sender)
        sender_ip = sender_address.resolve(require_ipv4=opts.require_ipv4,
                                           require_ipv6=opts.require_ipv6)

    # Setup the endpoint handlers
    sender_endpoint   = initialize_endpoint(local_address=sender_ip,
                                            remote_address=receiver_ip,
                                            tool_type=tool_type,
                                            is_sender=True,
                                            is_server=False,
                                            out=out)

    receiver_endpoint = initialize_endpoint(local_address=receiver_ip,
                                            remote_address=sender_ip,
                                            tool_type=tool_type,
                                            is_sender=False,
                                            is_server=True,
                                            out=out)

    sender_endpoint.remote_endpoint = receiver_endpoint
    receiver_endpoint.remote_endpoint = sender_endpoint

    # We need multiple representations depending on what we're doing. 
    server_endpoint = receiver_endpoint
    client_endpoint = sender_endpoint

    if (server_endpoint.is_legacy and not client_endpoint.is_remote) or \
       (client_endpoint.is_legacy and not server_endpoint.is_remote):
       raise Exception("BWCTL cannot be used against a legacy server without running a local bwctld instance")

    if client_endpoint.is_legacy and not server_endpoint.is_legacy and \
       not server_endpoint.legacy_endpoint_port:
       raise Exception("%s is a legacy server, but %s does not support legacy protocol" % (client_endpoint.address, server_endpoint.address))
    
    return (server_endpoint, client_endpoint)

def cancel_endpoint_tests(endpoints):
    for ep in endpoints:
        try:
            ep.cancel_test()
        except Exception as e:
            #Ignore exceptions since we want to exit regardless
            pass

def bwctl_client():
    """Entry point for bwctl client"""
    
    # Determine the type of test we're running
    script_name = inspect.stack()[-1][1]
    if "bwtraceroute" in script_name:
        tool_type = ToolTypes.TRACEROUTE
    elif "bwping" in script_name:
        tool_type = ToolTypes.LATENCY
    elif "bwctl" in script_name:
        tool_type = ToolTypes.THROUGHPUT

    argv = sys.argv
    # Test parameters
    oparse = optparse.OptionParser(version="%prog " + __version__)
    oparse.add_option("-4", "--ipv4", action="store_true", dest="require_ipv4", default=False,
                      help="Use IPv4 only")
    oparse.add_option("-6", "--ipv6", action="store_true", dest="require_ipv6", default=False,
                      help="Use IPv6 only")
    oparse.add_option("-L", "--latest_time", dest="latest_time", default=300, type="int",
                      help="Latest time into an interval to allow a test to run (seconds) (Default: 300)")
    oparse.add_option("-c", "--receiver", dest="receiver", type="string",
                      help="The host that will act as the receiving side for a test")
    oparse.add_option("-s", "--sender", dest="sender", type="string",
                      help="The host that will act as the sending side for a test")
    # Scheduling options
    oparse.add_option("-n", "--num_tests", dest="num_tests", type="int",
                      help="Number of times to run a test. Only valid with -I, --streaming, and --schedule. Defaults to infinite number of times. If no scheduling option provided then test only run once.")
    oparse.add_option("-I", "--test_interval", dest="test_interval", type="int",
                      help="Time between repeated bwctl tests in seconds")
    oparse.add_option("-R", "--randomize", dest="rand_start", type="int", default=10,
                      help=" Randomize the start time within this percentage of the test's interval. Specified as integer between 0 and 50 (inclusive).(Default: 10%)")
    oparse.add_option("--streaming", action="store_true", dest="streaming", default=False,
                      help="Request the next test as soon as the current test finishes")
    oparse.add_option("--schedule", dest="schedule", type="string",
                      help="Specify the specific times when a test should be run (e.g. --schedule 11:00,13:00,15:00)")
    # Output parameters
    oparse.add_option("--parsable", action="store_true", dest="parsable", default=False,
                      help="Set the BWCTL output format to JSON and the tool output to the most machine parsable option.")
    oparse.add_option("-y", "--format", dest="format", type="string",
                      help="Output format to use for the tool. Does not affect BWCTL output format such as wait time, etc. (Default: tool specific)")
    oparse.add_option("-d", "--output_dir", dest="output_dir", type="string",
                      help="Directory to save session files to (only if -p)")
    oparse.add_option("-p", "--print", dest="print_fname", action="store_true", default=False,
                      help="Print results filenames to stdout (Default: False")

    # Tool specific parameters
    add_tool_options(oparse, tool_type=tool_type)

    if tool_type == ToolTypes.TRACEROUTE:
        add_traceroute_test_options(oparse)
    elif tool_type == ToolTypes.LATENCY:
        add_latency_test_options(oparse)
    elif tool_type == ToolTypes.THROUGHPUT:
        add_throughput_test_options(oparse)

    oparse.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Display verbose output")
    oparse.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Silent mode (Default: False)")
    
    (opts, args) = oparse.parse_args(args=argv)
    
    #Initialize outputter
    out = init_outputter(opts)
    
    # Initialize the logger
    init_logging(script_name, debug=opts.verbose)

    # Initialize the configuration
    config = get_config() # config_file=config_file)
    
    # Initialize the scheduler
    scheduler =  init_scheduler(opts)
    
    # Setup the tool configuration
    configure_tools(config)
    
    # Make sure we have at least a sender or receiver before proceeding
    if not opts.receiver and not opts.sender:
        out.error("Error: a sender or a receiver must be specified")
        oparse.print_help()
        sys.exit(1)
    
    #run the test
    while(scheduler.has_next_test()):
        endpoints = ()
        try:
            # Sleep until next test if necessary
            time.sleep(scheduler.get_next_wait_time())
            # Initialize the endpoints
            endpoints = initialize_endpoints(tool_type, opts, out) 
            # Try to run the test
            run_bwctl_test(tool_type, opts, endpoints, out)
        except KeyboardInterrupt:
            cancel_endpoint_tests(endpoints)
            sys.exit(0)
        except Exception as e:
            out.error(str(e))
        finally:
            out.finalize()
        
        scheduler.mark_test_run()
        
def run_bwctl_test(tool_type, opts, endpoints, out):
    
    server_endpoint = endpoints[0]
    client_endpoint = endpoints[1]
    
    tool_parameters = {}
    
    #fill specified tool parameters prior to knowing tool
    if tool_type == ToolTypes.THROUGHPUT:
        fill_throughput_tool_parameters(opts, tool_parameters)
    elif tool_type == ToolTypes.LATENCY:
        fill_latency_tool_parameters(opts, tool_parameters)
    elif tool_type == ToolTypes.TRACEROUTE:
        fill_traceroute_tool_parameters(opts, tool_parameters)

    requested_tools = opts.tools.split(",")

    selected_tool, common_tools = select_tool(requested_tools=requested_tools,
                                              server_tools=server_endpoint.available_tools,
                                              client_tools=client_endpoint.available_tools,
                                              tool_type=tool_type,
                                              tool_parameters=tool_parameters)

    if not selected_tool:
        error_msg = "Requested tools not available by both servers. "
        error_msg += "Available tools that support the requested options: %s" % ",".join(common_tools)
        raise Exception(error_msg)
    out.info(INFO_TOOL, selected_tool, level=LVL_VERBOSE)
    
    #fill-in any tool specific parameters
    if tool_type == ToolTypes.THROUGHPUT:
        fill_selected_throughput_tool_parameters(opts, tool_parameters, selected_tool)
    elif tool_type == ToolTypes.LATENCY:
        fill_selected_latency_tool_parameters(opts, tool_parameters, selected_tool)
    elif tool_type == ToolTypes.TRACEROUTE:
        fill_selected_traceroute_tool_parameters(opts, tool_parameters, selected_tool)

    requested_time=datetime.datetime.utcnow()+datetime.timedelta(seconds=3)
    latest_time=requested_time+datetime.timedelta(seconds=opts.latest_time)

    reservation_time = requested_time
    reservation_end_time = None
    reservation_completed = False

    # Make sure that we request from the server side first since it needs to
    # allocate a test port to connect to.
    out.info(INFO_REQUESTED_TIME, requested_time, level=LVL_VERBOSE)
    while not reservation_completed:
        for endpoint in [ server_endpoint, client_endpoint ]:
            reservation_time, reservation_end_time = endpoint.request_test(tool=selected_tool,
                                                                           tool_parameters=tool_parameters, 
                                                                           requested_time=reservation_time,
                                                                           latest_time=latest_time)

            if reservation_time == endpoint.remote_endpoint.test_start_time:
               reservation_completed = True
               break
    out.info(INFO_END_TIME, reservation_end_time, level=LVL_VERBOSE)
    
    # At this point, the tests are in agreement in time and tool parameters. Do
    # a final pass to ensure that the endpoint information is up to date.
    for endpoint in [ server_endpoint, client_endpoint ]:
        endpoint.finalize_test()

    # We need to accept the remote endpoints first, and then the local one (if
    # applicable) so that the local one can post its' acceptance to the server.
    for endpoint in [ server_endpoint, client_endpoint ]:
        endpoint.accept_test()

    for endpoint in [ server_endpoint, client_endpoint ]:
        endpoint.remote_accept_test()

    # Wait for the servers to accept the test
    reservation_confirmed = False
    reservation_failed    = False
    while not reservation_confirmed and not reservation_failed:
        time.sleep(.5)

        reservation_confirmed = True

        for endpoint in [ server_endpoint, client_endpoint ]:
            if not endpoint.is_pending:
                reservation_confirmed = False

            if endpoint.is_finished:
                reservation_failed = True
                break

    if reservation_confirmed:
        for endpoint in [ server_endpoint, client_endpoint ]:
            if not endpoint.is_remote:
                endpoint.spawn_tool_runner()

        # Wait until the just after the end of the test for the results to be available
        sleep_time = timedelta_seconds(reservation_end_time - datetime.datetime.utcnow() + datetime.timedelta(seconds=1))

        out.info(INFO_WAITTIME, sleep_time)

        time.sleep(sleep_time)

    client_results = client_endpoint.get_test_results()
    server_results = server_endpoint.get_test_results()

    if client_endpoint.is_sender:
        sender_results = client_results
        receiver_results = server_results
    else:
        sender_results = server_results
        receiver_results = client_results

    if not sender_results:
        out.error("No test results found for sender")
    else:
        if sender_results.results:
            if "command_line" in sender_results.results:
                out.info(INFO_SEND_CMD, sender_results.results['command_line'])
            out.results(DIRECTION_SEND, sender_results.results['output'])

        if len(sender_results.bwctl_errors) > 0:
            out.result_errors(DIRECTION_SEND,sender_results.bwctl_errors)

    if not receiver_results:
        out.error("No test results found for receiver")
    else:
        if receiver_results.results:
            if "command_line" in receiver_results.results:
                out.info(INFO_RECV_CMD, receiver_results.results['command_line'])
            out.results(DIRECTION_RECV,receiver_results.results['output'])

        if len(receiver_results.bwctl_errors) > 0:
            out.result_errors(DIRECTION_RECV,receiver_results.bwctl_errors)

class ClientEndpoint:
   def __init__(self, address="", port=None, path=None, is_sender=True, is_server=True):
       self.is_remote = True
       self.is_legacy = False

       self.remote_endpoint = None

       self.is_sender = is_sender
       self.is_server = is_server

       self.address = address
       self.test_port = 0

       if port:
           self.port = int(port)
       else:
           self.port = 4824

       self.path    = path or "/bwctl"
       self.test_id = ""

       self.time_offset      = 0   # difference between the local clock and the far clock
       self.server_ntp_error = 0
       self.server_version   = 2.0
       self.available_tools  = []

       self.server_test_description = None

       self.sent_accept = False

       self.test_start_time = None
       self.test_end_time = None
       client_url = "http://[%s]:%d%s" % (self.address, self.port, self.path)
       self.client = Client(client_url)

   def initialize(self):
       # XXX: handle failure condition
       status = self.client.get_status()
       current_time = datetime.datetime.utcnow()

       # XXX: we should probably try to account for the network delay
       self.time_offset = timedelta_seconds(current_time - status.time)

       self.protocol = status.protocol
       self.server_ntp_error = status.ntp_error
       self.server_version   = status.version
       self.available_tools = status.available_tools
       self.legacy_endpoint_port = status.legacy_endpoint_port

   def time_c2s(self, time):
       return time - datetime.timedelta(seconds=self.time_offset)

   def time_s2c(self, time):
       return time + datetime.timedelta(seconds=self.time_offset)

   def preconfigure(self):
       return

   def finalize_test(self):
       # Just call request test with no parameters. It'll just update the endpoints.
       return self.request_test()

   def request_test(self, requested_time=None, latest_time=None, tool="", tool_parameters={}):
       # Convert our time to the time that the server expects
       if requested_time:
           requested_time = self.time_c2s(requested_time)

       if latest_time:
           latest_time    = self.time_c2s(latest_time)

       test = self.server_test_description
       if test == None:
           if self.is_sender:
               receiver_endpoint = self.remote_endpoint.endpoint_obj(local=False)
               sender_endpoint = self.endpoint_obj(local=True)
           else:
               sender_endpoint = self.remote_endpoint.endpoint_obj(local=False)
               receiver_endpoint = self.endpoint_obj(local=True)

           test = Test(
                        client=ClientSettings(time=datetime.datetime.utcnow()),
                        sender_endpoint=sender_endpoint,
                        receiver_endpoint=receiver_endpoint,
                        tool=tool,
                        tool_parameters=tool_parameters,
                        scheduling_parameters=SchedulingParameters(requested_time=requested_time, latest_acceptable_time=latest_time)
                      )

       if tool:
           test.tool = tool

       if tool_parameters:
           test.tool_parameters = tool_parameters

       if requested_time:
           test.scheduling_parameters.requested_time = requested_time

       if latest_time:
           test.scheduling_parameters.latest_acceptable_time = latest_time

       if self.is_sender:
           test.receiver_endpoint = self.remote_endpoint.endpoint_obj(local=False)
           test.sender_endpoint   = self.endpoint_obj(local=True)
       else:
           test.sender_endpoint = self.remote_endpoint.endpoint_obj(local=False)
           test.receiver_endpoint   = self.endpoint_obj(local=True)

       # XXX: handle failure
       if self.test_id:
           ret_test = self.client.update_test(self.test_id, test)
       else:
           ret_test = self.client.request_test(test)

       # Save the test id since we use it for creating the Endpoint, and a few
       # other things.
       self.test_id = ret_test.id

       # Save the test port since we use it for creating our Endpoint
       # representation
       if self.is_server:
           self.test_port = ret_test.local_endpoint.test_port

       self.test_start_time = self.time_s2c(ret_test.scheduling_parameters.test_start_time)
       self.test_end_time = self.time_s2c(ret_test.scheduling_parameters.reservation_end_time)

       self.server_test_description = ret_test

       return self.test_start_time, self.test_end_time

   def get_test(self):
       # XXX: handle failure
       return self.client.get_test(self.test_id)

   def get_test_results(self):
       # XXX: handle failure
       retval = None
       try:
           retval = self.client.get_test_results(self.test_id)
       except HTTPError:
           retval = None

       return retval

   @property
   def is_pending(self):
       test = self.get_test()

       return test.status == "pending"

   @property
   def is_finished(self):
       test = self.get_test()

       return test.finished

   def accept_test(self):
       # XXX: handle failure
       if self.sent_accept:
           return

       self.sent_accept = True

       return self.client.accept_test(self.test_id)

   def remote_accept_test(self):
       return

   def cancel_test(self):
       # XXX: handle failure

       return self.client.cancel_test(self.test_id)

   def endpoint_obj(self, local=False):
    return Endpoint(
                    address=self.address,
                    test_port=self.test_port,

                    bwctl_protocol=2.0,
                    peer_port=self.port,
                    base_path=self.path,
                    test_id=self.test_id,

                    local=local,

                    ntp_error=self.server_ntp_error,
                    client_time_offset=self.time_offset,

                    legacy_client_endpoint=False,
                    posts_endpoint_status=False
                    )

class LocalEndpoint:
   def __init__(self, address="", tool_type=None, is_sender=True):
       self.address = address

       self.is_remote = False
       self.is_legacy = False

       self.is_server = False

       self.test_start_time = None
       self.test_end_time = None

       self.tool_type = tool_type
       self.is_sender = is_sender
       self.tool_runner_proc = None

       self.test_port = None

       self.legacy_endpoint_port = 6001 # XXX: this should be configurable

       self.tool = ""
       self.tool_parameters = {}

       self.available_tools = []

       self.remote_endpoint = None

       self.results_queue = Queue()

       self.results = None

   def initialize(self):
       self.available_tools = get_available_tools()

   # If the far side is a legacy 'client', we need an endpoint handler for them
   # to connect to.
   def prepare_handlers(self):
       if remote_endpoint.is_legacy and self.is_server:
           self.endpoint_handler_proc = LegacyEndpointHandler(server_port=self.legacy_endpoint_port)
           self.endpoint_handler_proc.start()

       return

   def finalize_test(self):
       # No need to finalize the test here
       return

   def request_test(self, requested_time=None, latest_time=None, tool="", tool_parameters={}):
       if not self.test_port:
           self.test_port = get_tool(tool).get_port()

       if self.is_sender:
           receiver_endpoint = self.remote_endpoint.endpoint_obj(local=False)
           sender_endpoint = self.endpoint_obj(local=True)
       else:
           sender_endpoint = self.remote_endpoint.endpoint_obj(local=False)
           receiver_endpoint = self.endpoint_obj(local=True)

       self.test = Test(
                        id="local test",
                        client=ClientSettings(time=datetime.datetime.utcnow()),
                        sender_endpoint=sender_endpoint,
                        receiver_endpoint=receiver_endpoint,
                        tool=tool,
                        tool_parameters=tool_parameters,
                        scheduling_parameters=SchedulingParameters(
                            requested_time=requested_time,
                            latest_acceptable_time=latest_time,
                        )
                      )

       # Just grab the other time's reservation end time if it's already been
       # scheduled.
       if self.remote_endpoint and \
           requested_time == self.remote_endpoint.test_start_time:
           end_time = self.remote_endpoint.test_end_time
       else:
           end_time = requested_time + datetime.timedelta(seconds=self.test.duration + 1)

       self.tool = tool
       self.tool_parameters = tool_parameters

       self.test_start_time = requested_time
       self.test_end_time = end_time

       # Fill-in the scheduling parameters
       self.test.scheduling_parameters.reservation_start_time = requested_time - datetime.timedelta(seconds=0.5) # Makes sure the server starts slightly early
       self.test.scheduling_parameters.test_start_time = requested_time
       self.test.scheduling_parameters.reservation_end_time = end_time

       return requested_time, end_time

   def get_test_results(self):
       if not self.results:
           try:
               self.results = self.results_queue.get_nowait()
           except:
               pass

       return self.results

   @property
   def is_pending(self):
       return True

   @property
   def is_finished(self):
       return not self.results

   def accept_test(self):
       return

   def remote_accept_test(self):
       client_url = "http://[%s]:%d%s" % (self.remote_endpoint.address, self.remote_endpoint.port, self.remote_endpoint.path)
       self.client = Client(client_url)

       return self.client.remote_accept_test(self.remote_endpoint.test_id, self.test)

   def cancel_test(self):
       if self.tool_runner_proc:
            self.tool_runner_proc.kill_children()
            self.tool_runner_proc.terminate()

       return

   def spawn_legacy_endpoint_client_handler(self):
       pass

   def spawn_legacy_endpoint_handler(self):
       pass

   def spawn_tool_runner(self):
       def handle_results_cb(results):
           self.results_queue.put(results)

       self.tool_runner_proc = ToolRunner(test=self.test, results_cb=handle_results_cb)
       self.tool_runner_proc.start()

   def endpoint_obj(self, local=False):
    return Endpoint(
                    address=self.address,
                    test_port=self.test_port,

                    local=local,

                    ntp_error=0, # XXX; figure this out

                    client_time_offset=0,

                    legacy_client_endpoint=False,
                    posts_endpoint_status=True
                    )

class LegacyClientEndpoint:
   def __init__(self, address="", port=4823, is_sender=True, is_server=True):
       self.is_remote = True
       self.is_legacy = True

       self.remote_endpoint = None

       self.is_sender = is_sender
       self.is_server = is_server

       self.address = address
       self.peer_port = 0
       self.test_port = 0

       if port:
           self.port = int(port)
       else:
           self.port = 4823

       self.time_offset      = 0   # difference between the local clock and the far clock
       self.server_ntp_error = 0
       self.server_version   = 1.0
       self.available_tools  = []

       self.sent_accept = False
       self.session_failed = False

       self.test_start_time = None
       self.test_end_time = None
       self.test_sid = ""

       self.results = None

       self.client = LegacyClient(server_address=self.address, server_port=self.port)

   def initialize(self):
       try:
           self.client.connect()
       except Exception as e:
           raise e

       server_greeting = self.client.get_server_greeting()

       server_ok = self.client.send_client_greeting()

       available_tools = []

       for tool_id in server_ok.tools:
           tool_name = tool_name_by_id(tool_id)
           if tool_name:
               available_tools.append(tool_name)

       self.available_tools = available_tools

       # XXX: we should probably try to account for the network delay
       current_time = datetime.datetime.utcnow()
       time_response = self.client.send_time_request()

       self.time_offset = timedelta_seconds(current_time - time_response.timestamp.time)
       self.server_ntp_error = time_response.error_estimate.error

   def request_test(self, requested_time=None, latest_time=None, tool="", tool_parameters={}):
       if self.is_sender:
           receiver_endpoint = self.remote_endpoint.endpoint_obj(local=False)
           sender_endpoint = self.endpoint_obj(local=True)
       else:
           sender_endpoint = self.remote_endpoint.endpoint_obj(local=False)
           receiver_endpoint = self.endpoint_obj(local=True)

       # Build the Test using the internal models
       test = Test(
                   client=ClientSettings(time=datetime.datetime.utcnow()),
                   sender_endpoint=sender_endpoint,
                   receiver_endpoint=receiver_endpoint,
                   tool=tool,
                   tool_parameters=tool_parameters,
                   scheduling_parameters=SchedulingParameters(
                       requested_time=requested_time,
                       latest_acceptable_time=latest_time,
                   )
                 )


       # Convert the test to the TestRequest format used in the legacy protocol
       test_request = TestRequest.from_internal(test)
       test_request.sid = self.test_sid
       test_request.verbose = True # XXX: handle this better

       # Set the time information, converting it to the server-side "time"
       # perspective.
       if requested_time:
           test_request.requested_time = Timestamp(time=self.time_c2s(requested_time))

       if latest_time:
           test_request.latest_time = Timestamp(time=self.time_c2s(latest_time))

       if self.remote_endpoint.server_ntp_error:
           test_request.error_estimate = ErrorEstimate(error=self.remote_endpoint.server_ntp_error)

       test_accept = self.client.send_test_request(test_request)

       if test_accept.accept_type == AcceptType.REJECT:
           raise Exception("TestRequest denied from %s" % self.address)
       if test_accept.accept_type != AcceptType.ACCEPT:
           raise Exception("TestRequest failed from %s" % self.address)

       self.test_port = test_accept.data_port
       self.test_sid  = test_accept.sid
       self.test_start_time = self.time_s2c(test_accept.reservation_time.time)
       self.test_end_time   = self.test_start_time + datetime.timedelta(seconds=test_request.duration + 1) # Make up an end time since the server doesn't give us one

       return self.test_start_time, self.test_end_time

   def finalize_test(self):
       # We call StartSessions here so that we have our corresponding peer_port.
       peer_port = 0
       if self.remote_endpoint.is_legacy:
           peer_port = self.remote_endpoint.peer_port
       elif self.remote_endpoint.legacy_endpoint_port:
           peer_port = self.remote_endpoint.legacy_endpoint_port

       start_ack = self.client.send_start_session(peer_port=peer_port)

       if start_ack.accept_type != AcceptType.ACCEPT:
           raise Exception("StartSession failed")

       self.peer_port = start_ack.peer_port

       self.session_started = True

       return

   def get_test_results(self):
       # Check if we've cached results
       if self.results != None:
           return self.results

       # We're at the "test should be finished" state, so send a StopSession
       # message and wait for the results.
       self.client.send_stop_session()

       stop_session_msg, results = self.client.get_stop_session()

       self.client.close()

       # XXX: Do a better conversion of the "legacy" results into the new style
       # results.
       self.results = Results(status="finished", results={ 'output': results })

       return self.results

   def time_c2s(self, time):
       return time - datetime.timedelta(seconds=self.time_offset)

   def time_s2c(self, time):
       return time + datetime.timedelta(seconds=self.time_offset)

   @property
   def is_pending(self):
       # We're in a pending state after the start session gets sent in the
       # finalize_test call.
       return self.session_started

   @property
   def is_finished(self):
       # We have no way of getting this...
       return self.session_failed

   def accept_test(self):
       # The test was "accepted" in the finalize_test call because we need to
       # get the peer_port before we can finalize the other side.
       return

   def remote_accept_test(self):
       return

   def cancel_test(self):
       # Do a session request with a timestamp of 0 if we've not done a
       # 'StartSession'. If we have, do a StopSession.
       if self.session_started:
           # We need to send a StopSession message
           pass
       elif self.test_sid:
           # We need to send a TestRequest with an requested_time of 0
           pass

       raise Exception("cancel_test needs filled out")

   def endpoint_obj(self, local=False):
    return Endpoint(
                    address=self.address,
                    test_port=self.test_port,

                    bwctl_protocol=1.0,
                    peer_port=self.peer_port,

                    local=local,

                    ntp_error=self.server_ntp_error,
                    client_time_offset=self.time_offset,

                    legacy_client_endpoint=not self.is_server,
                    posts_endpoint_status=False
                    )
