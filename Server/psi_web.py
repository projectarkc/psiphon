#!/usr/bin/python
#
# Copyright (c) 2011, Psiphon Inc.
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

'''

Example input:
https://192.168.0.1:80/handshake?propagation_channel_id=0987654321&sponsor_id=1234554321&client_version=1&server_secret=1234567890

'''

import string
import threading
import time
import os
import syslog
import ssl
import tempfile
import netifaces
import socket
import json
import re
from cherrypy import wsgiserver, HTTPError
from cherrypy.wsgiserver import ssl_pyopenssl
from cherrypy.lib import cpstats
from webob import Request
import psi_psk
import psi_config
import psi_geoip
import sys
import traceback
import platform
import redis
from datetime import datetime
from functools import wraps
import psi_web_patch

# ===== PSINET database ===================================================

sys.path.insert(0, os.path.abspath(os.path.join('..', 'Automation')))
import psi_ops
import psi_ops_discovery

psinet = psi_ops.PsiphonNetwork.load_from_file(psi_config.DATA_FILE_NAME)


# ===== Helpers =====

# see: http://codahale.com/a-lesson-in-timing-attacks/
def constant_time_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


def consists_of(str, characters):
    return 0 == len(filter(lambda x : x not in characters, str))


def is_valid_ip_address(str):
    try:
        socket.inet_aton(str)
        return True
    except:
        return False


EMPTY_VALUE = '(NONE)'


def is_valid_relay_protocol(str):
    return str in ['VPN', 'SSH', 'OSSH', 'FRONTED-MEEK-OSSH', 'UNFRONTED-MEEK-OSSH', EMPTY_VALUE]


is_valid_iso8601_date_regex = re.compile(r'(?P<year>[0-9]{4})-(?P<month>[0-9]{1,2})-(?P<day>[0-9]{1,2})T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})\.(?P<fraction>[0-9]+)(?P<timezone>Z|(([-+])([0-9]{2}):([0-9]{2})))')
def is_valid_iso8601_date(str):
    return is_valid_iso8601_date_regex.match(str) != None

def is_valid_boolean_str(str):
    return str in ['0', '1']

# see: http://code.activestate.com/recipes/496784-split-string-into-n-size-pieces/
def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]


def safe_int(input):
    return_value = 0
    try:
        return_value = int(input)
    except:
        pass
    return return_value


def exception_logger(function):
    @wraps(function)
    def wrapper(*args, **kwds):
        try:
            return function(*args, **kwds)
        except:
            for line in traceback.format_exc().split('\n'):
                syslog.syslog(syslog.LOG_ERR, line)
            raise
    return wrapper


# ===== Psiphon Web Server =====

class ServerInstance(object):

    def __init__(self, ip_address, server_secret, capabilities, host_id):
        self.session_redis = redis.StrictRedis(
            host=psi_config.SESSION_DB_HOST,
            port=psi_config.SESSION_DB_PORT,
            db=psi_config.SESSION_DB_INDEX)
        self.discovery_redis = redis.StrictRedis(
            host=psi_config.DISCOVERY_DB_HOST,
            port=psi_config.DISCOVERY_DB_PORT,
            db=psi_config.DISCOVERY_DB_INDEX)
        self.server_ip_address = ip_address
        self.server_secret = server_secret
        self.capabilities = capabilities
        self.host_id = host_id
        self.COMMON_INPUTS = [
            ('server_secret', lambda x: constant_time_compare(x, self.server_secret)),
            ('propagation_channel_id', lambda x: consists_of(x, string.hexdigits) or x == EMPTY_VALUE),
            ('sponsor_id', lambda x: consists_of(x, string.hexdigits) or x == EMPTY_VALUE),
            ('client_version', lambda x: consists_of(x, string.digits) or x == EMPTY_VALUE),
            ('client_platform', lambda x: consists_of(x, string.letters + string.digits + '-._()')),
            ('relay_protocol', is_valid_relay_protocol),
            ('tunnel_whole_device', is_valid_boolean_str)]

    def _is_request_tunnelled(self, client_ip_address):
        return client_ip_address in ['localhost', '127.0.0.1', self.server_ip_address]

    def _get_inputs(self, request, request_name, additional_inputs=None):
        if additional_inputs is None:
            additional_inputs = []

        input_values = []

        # Add server IP address for logging
        input_values.append(('server_ip_address', self.server_ip_address))

        # Log client region/city/ISP (but not IP address)
        # If the peer is localhost, the web request is coming through the
        # tunnel. In this case, check if the client provided a client_session_id
        # and check if there's a corresponding region in the tunnel session
        # database
        # Update: now we also cache GeoIP lookups done outside the tunnel
        client_ip_address = request.remote_addr
        #geoip = psi_geoip.get_unknown()
        # Use a distinct "Unknown" value to distinguish the case where the request is
        # tunneled and the session redis has expired,
        # from the case where the session has been logged with an unknown ('None') region
        geoip = {'region': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}
        if request.params.has_key('client_session_id'):
            client_session_id = request.params['client_session_id']
            if not consists_of(client_session_id, string.hexdigits):
                syslog.syslog(
                    syslog.LOG_ERR,
                    'Invalid client_session_id in %s [%s]' % (request_name, str(request.params)))
                return False
            record = self.session_redis.get(client_session_id)
            if record:
                # Extend the expiry for this record for subsequent requests
                self.session_redis.expire(client_session_id, psi_config.SESSION_EXPIRE_SECONDS)
                try:
                    geoip = json.loads(record)
                except ValueError:
                    # Backwards compatibility case
                    geoip = psi_geoip.get_region_only(record)
            elif not self._is_request_tunnelled(client_ip_address):
                geoip = psi_geoip.get_geoip(client_ip_address)
                # Cache the result for subsequent requests with the same client_session_id
                if len(client_session_id) > 0:
                    self.session_redis.set(client_session_id, json.dumps(geoip))
                    self.session_redis.expire(client_session_id, psi_config.SESSION_EXPIRE_SECONDS)
            # else: is-tunnelled and no cache, so GeoIP is unknown
        elif not self._is_request_tunnelled(client_ip_address):
            # Can't use cache without a client_session_id
            geoip = psi_geoip.get_geoip(client_ip_address)

        # Hack: log parsing is space delimited, so remove spaces from
        # GeoIP string (ISP names in particular)

        input_values.append(('client_region', geoip['region'].replace(' ', '_')))
        input_values.append(('client_city', geoip['city'].replace(' ', '_')))
        input_values.append(('client_isp', geoip['isp'].replace(' ', '_')))

        # Check for each expected input
        for (input_name, validator) in self.COMMON_INPUTS + additional_inputs:
            try:
                value = request.params[input_name]
            except KeyError as e:
                # Backwards compatibility patches
                # - Older clients don't specifiy relay_protocol, default to VPN
                # - Older clients specify vpn_client_ip_address for session ID
                # - Older clients specify client_id for propagation_channel_id
                # - Older clients don't specify client_platform
                # - Older clients don't specify last session date
                # - Older clients (and Windows clients) don't specify tunnel_whole_device
                if input_name == 'relay_protocol':
                    value = 'VPN'
                elif input_name == 'session_id' and request.params.has_key('vpn_client_ip_address'):
                    value = request.params['vpn_client_ip_address']
                elif input_name == 'propagation_channel_id' and request.params.has_key('client_id'):
                    value = request.params['client_id']
                elif input_name == 'client_platform':
                    value = 'Windows'
                elif input_name == 'last_connected':
                    value = 'Unknown'
                elif input_name == 'tunnel_whole_device':
                    value = '0'
                else:
                    syslog.syslog(
                        syslog.LOG_ERR,
                        'Missing %s in %s [%s]' % (input_name, request_name, str(request.params)))
                    return False
            if len(value) == 0:
                value = EMPTY_VALUE
            if not validator(value):
                syslog.syslog(
                    syslog.LOG_ERR,
                    'Invalid %s in %s [%s]' % (input_name, request_name, str(request.params)))
                return False
            # Special case: omit server_secret from logging
            if input_name != 'server_secret':
                input_values.append((input_name, value))

        # Caller gets a list of name/value input tuples, used for logging etc.
        return input_values

    def _log_event(self, event_name, log_values):
        syslog.syslog(
            syslog.LOG_INFO,
            ' '.join([event_name] + [str(value.encode('utf8') if type(value) == unicode else value) for (_, value) in log_values]))
        if event_name not in ['status', 'speed', 'routes', 'download']:
            json_log = {'event_name': event_name, 'timestamp': datetime.utcnow().isoformat() + 'Z', 'host_id': self.host_id}
            for key, value in log_values:
                # convert a number in a string to a long
                if (type(value) == str or type(value) == unicode) and value.isdigit():
                    json_log[key] = long(value)
                # encode unicode to utf8
                elif type(value) == unicode:
                    json_log[key] = str(value.encode('utf8'))
                else:
                    json_log[key] = value
            syslog.syslog(
                syslog.LOG_INFO | syslog.LOG_LOCAL0,
                json.dumps(json_log))

    @exception_logger
    def handshake(self, environ, start_response):
        request = Request(environ)
        inputs = self._get_inputs(request, 'handshake')
        if not inputs:
            start_response('404 Not Found', [])
            return []
        # Client submits a list of known servers which is used to
        # flag "new" discoveries in the stats logging
        # NOTE: not validating that server IP addresses are part of the network
        #       (if we do add this, be careful to not introduce a timing based
        #        attack that could be used to enumerate valid server IPs)
        if hasattr(request, 'str_params'):
            known_servers = request.str_params.getall('known_server')
        else:
            known_servers = request.params.getall('known_server')
        for known_server in known_servers:
            if not is_valid_ip_address(known_server):
                syslog.syslog(
                    syslog.LOG_ERR,
                    'Invalid known server in handshake [%s]' % (str(request.params),))
                start_response('404 Not Found', [])
                return []
        #
        # NOTE: Change PSK *last*
        # There's a race condition between setting it and the client connecting:
        # another client may request /handshake and change the PSK before the
        # first client authenticates to the VPN.  We accept the risk and the
        # client is designed to retry.  Still, best to minimize the time
        # between the PSK change on the server side and the submit by the
        # client.  See the design notes for why we aren't using multiple PSKs
        # and why we're using PSKs instead of VPN PKI: basically, lowest
        # common denominator compatibility.
        #
        self._log_event('handshake', inputs)
        client_ip_address = request.remote_addr

        client_session_id = None
        if request.params.has_key('client_session_id'):
            client_session_id = request.params['client_session_id']

        # If the request is tunnelled, we should find a pre-computed
        # ip_address_strategy_value stored in redis by psi_auth.

        client_ip_address_strategy_value = None
        if self._is_request_tunnelled(client_ip_address):
            client_ip_address = None
            if client_session_id != None:
                record = self.discovery_redis.get(client_session_id)
                if record:
                    self.discovery_redis.delete(client_session_id)
                    discovery_info = json.loads(record)
                    client_ip_address_strategy_value = discovery_info['client_ip_address_strategy_value']
        else:
            client_ip_address_strategy_value = psi_ops_discovery.calculate_ip_address_strategy_value(client_ip_address)
            if client_session_id != None:
                if self.discovery_redis.get(client_session_id) == None:
                    self.discovery_redis.set(client_session_id, json.dumps({'client_ip_address_strategy_value' : client_ip_address_strategy_value}))
                    self.discovery_redis.expire(client_session_id, psi_config.DISCOVERY_EXPIRE_SECONDS)

        # logger callback will add log entry for each server IP address discovered
        def discovery_logger(server_ip_address):
            unknown = '0' if server_ip_address in known_servers else '1'
            self._log_event('discovery',
                             inputs + [('server_ip_address', server_ip_address),
                                       ('unknown', unknown)])

        inputs_lookup = dict(inputs)
        client_region = inputs_lookup['client_region']

        config = psinet.handshake(
                    self.server_ip_address,
                    client_ip_address_strategy_value,
                    client_region,
                    inputs_lookup['propagation_channel_id'],
                    inputs_lookup['sponsor_id'],
                    inputs_lookup['client_platform'],
                    inputs_lookup['client_version'],
                    event_logger=discovery_logger)

        # Report back client region in case client needs to fetch routes file
        # for his region off a 3rd party
        config['client_region'] = client_region

        config['preemptive_reconnect_lifetime_milliseconds'] = \
            psi_config.PREEMPTIVE_RECONNECT_LIFETIME_MILLISECONDS if \
            client_region in psi_config.PREEMPTIVE_RECONNECT_REGIONS else 0

        output = []

        # Legacy handshake output is a series of Name:Value lines returned to
        # the client. That format will continue to be supported (old client
        # versions expect it), but the new format of a JSON-ified object will
        # also be output.

        for homepage_url in config['homepages']:
            output.append('Homepage: %s' % (homepage_url,))

        if config['upgrade_client_version']:
            output.append('Upgrade: %s' % (config['upgrade_client_version'],))

        for encoded_server_entry in config['encoded_server_list']:
            output.append('Server: %s' % (encoded_server_entry,))

        if config['ssh_host_key']:
            output.append('SSHUsername: %s' % (config['ssh_username'],))
            output.append('SSHPassword: %s' % (config['ssh_password'],))
            output.append('SSHHostKey: %s' % (config['ssh_host_key'],))
            output.append('SSHSessionID: %s' % (config['ssh_session_id'],))
            if config.has_key('ssh_port'):
                output.append('SSHPort: %s' % (config['ssh_port'],))
            if config.has_key('ssh_obfuscated_port'):
                output.append('SSHObfuscatedPort: %s' % (config['ssh_obfuscated_port'],))
                output.append('SSHObfuscatedKey: %s' % (config['ssh_obfuscated_key'],))

        # We assume VPN for backwards compatibility, but if a different relay_protocol
        # is specified, then we won't need a PSK.
        if inputs_lookup['relay_protocol'] == 'VPN' and (
                self.capabilities.has_key('VPN') and self.capabilities['VPN']):
            psk = psi_psk.set_psk(self.server_ip_address)
            config['l2tp_ipsec_psk'] = psk
            output.append('PSK: %s' % (psk,))


        config["server_timestamp"] = datetime.utcnow().isoformat() + 'Z'

        # The entire config is JSON encoded and included as well.

        output.append('Config: ' + json.dumps(config))

        response_headers = [('Content-type', 'text/plain')]
        start_response('200 OK', response_headers)
        return ['\n'.join(output)]

    @exception_logger
    def download(self, environ, start_response):
        # NOTE: currently we ignore client_version and just download whatever
        # version is currently in place for the propagation channel ID and sponsor ID.
        inputs = self._get_inputs(Request(environ), 'download')
        if not inputs:
            start_response('404 Not Found', [])
            return []
        self._log_event('download', inputs)
        # e.g., /root/PsiphonV/download/psiphon-<propagation_channel_id>-<sponsor_id>.exe
        inputs_lookup = dict(inputs)
        try:
            if inputs_lookup['client_platform'].lower().find('android') != -1:
                filename = 'PsiphonAndroid-%s-%s.apk' % (
                                inputs_lookup['propagation_channel_id'],
                                inputs_lookup['sponsor_id'])
            else:
                filename = 'psiphon-%s-%s.exe' % (
                                inputs_lookup['propagation_channel_id'],
                                inputs_lookup['sponsor_id'])
            path = os.path.join(psi_config.UPGRADE_DOWNLOAD_PATH, filename)
            with open(path, 'rb') as file:
                contents = file.read()
        # NOTE: exceptions other than IOError will kill the server thread, but
        # we expect only IOError in normal circumstances ("normal" being,
        # for example, an invalid ID so no file exists)
        except IOError as e:
            start_response('404 Not Found', [])
            return []
        response_headers = [('Content-Type', 'application/exe'),
                            ('Content-Length', '%d' % (len(contents),))]
        start_response('200 OK', response_headers)
        return [contents]

    @exception_logger
    def routes(self, environ, start_response):
        request = Request(environ)
        additional_inputs = [('session_id', lambda x: is_valid_ip_address(x) or
                                                      consists_of(x, string.hexdigits))]
        inputs = self._get_inputs(request, 'routes', additional_inputs)
        if not inputs:
            start_response('404 Not Found', [])
            return []
        self._log_event('routes', inputs)
        inputs_lookup = dict(inputs)
        return self._send_routes(inputs_lookup, start_response)

    def _send_routes(self, inputs_lookup, start_response):
        # Do not send routes to Android clients
        if inputs_lookup['client_platform'].lower().find('android') != -1:
            start_response('200 OK', [])
            return []
        try:
            path = os.path.join(
                        psi_config.ROUTES_PATH,
                        psi_config.ROUTE_FILE_NAME_TEMPLATE % (inputs_lookup['client_region'],))
            with open(path, 'rb') as file:
                contents = file.read()
            response_headers = [('Content-Type', 'application/octet-stream'),
                                ('Content-Length', '%d' % (len(contents),))]
            start_response('200 OK', response_headers)
            return [contents]
        except IOError as e:
            # When region route file is missing (including None, A1, ...) then
            # the response is empty.
            start_response('200 OK', [])
            return []

    @exception_logger
    def connected(self, environ, start_response):
        request = Request(environ)
        # Peek at input to determine required parameters
        # We assume VPN for backwards compatibility
        # Note: session ID is a VPN client IP address for backwards compatibility
        additional_inputs = [('session_id', lambda x: is_valid_ip_address(x) or
                                                      consists_of(x, string.hexdigits)),
                             ('last_connected', lambda x: is_valid_iso8601_date(x) or
                                                          x == 'None' or
                                                          x == 'Unknown')]
        inputs = self._get_inputs(request, 'connected', additional_inputs)
        if not inputs:
            start_response('404 Not Found', [])
            return []

        self._log_event('connected', inputs)
        inputs_lookup = dict(inputs)

        # For older Windows clients upon successful connection, we return
        # routing information for the user's country for split tunneling.
        # There is no need to do Android check since older clients ignore
        # this response.
        #
        # Latest Windows version is 44
        if (inputs_lookup['client_platform'].lower().find('windows') != -1
                and int(inputs_lookup['client_version']) <= 44):
            return self._send_routes(inputs_lookup, start_response)
        else:
            now = datetime.utcnow()
            connected_timestamp = {
                    'connected_timestamp' : now.strftime('%Y-%m-%dT%H:00:00.000Z')}
            response_headers = [('Content-type', 'text/plain')]
            start_response('200 OK', response_headers)
            return [json.dumps(connected_timestamp)]

    @exception_logger
    def failed(self, environ, start_response):
        request = Request(environ)
        additional_inputs = [('error_code', lambda x: consists_of(x, string.digits))]
        inputs = self._get_inputs(request, 'failed', additional_inputs)
        if not inputs:
            start_response('404 Not Found', [])
            return []
        self._log_event('failed', inputs)
        # No action, this request is just for stats logging
        start_response('200 OK', [])
        return []

    @exception_logger
    def status(self, environ, start_response):
        request = Request(environ)
        additional_inputs = [('session_id', lambda x: is_valid_ip_address(x) or
                                                      consists_of(x, string.hexdigits)),
                             ('connected', is_valid_boolean_str)]
        inputs = self._get_inputs(request, 'status', additional_inputs)
        if not inputs:
            start_response('404 Not Found', [])
            return []

        log_event = 'status' if request.params['connected'] == '1' else 'disconnected'
        self._log_event(log_event,
                         [('relay_protocol', request.params['relay_protocol']),
                          ('session_id', request.params['session_id'])])

        # Log page view and traffic stats, if available.

        # Traffic stats include session_id so we can report e.g., average bytes
        # transferred per session by region/sponsor.
        # NOTE: The session_id isn't associated with any PII.

        if request.body:
            try:
                stats = json.loads(request.body)

                if stats['bytes_transferred'] > 0:
                    self._log_event('bytes_transferred',
                                    inputs + [('bytes', stats['bytes_transferred'])])

                # Note: no input validation on page/domain.
                # Any string is accepted (regex transform may result in arbitrary string).
                # Stats processor must handle this input with care.

                for page_view in stats['page_views']:
                    self._log_event('page_views',
                                    inputs + [('page', page_view['page']),
                                              ('count', safe_int(page_view['count']))])

                for https_req in stats['https_requests']:
                    self._log_event('https_requests',
                                    inputs + [('domain', https_req['domain']),
                                              ('count', safe_int(https_req['count']))])

                # Older clients will not send this key in the message body
                if 'tunnel_stats' in stats.keys():
                    for tunnel in stats['tunnel_stats']:
                        self._log_event('session', inputs + [
                            ('session_id', tunnel['session_id']),
                            ('tunnel_number', tunnel['tunnel_number']),
                            ('tunnel_server_ip_address', tunnel['tunnel_server_ip_address']),
                            ('server_handshake_timestamp', tunnel['server_handshake_timestamp']),
                            # Tunnel Core sends durations in nanoseconds, divide to get to milliseconds
                            ('duration', (int(tunnel['duration']) / 1000000)),
                            ('total_bytes_sent', tunnel['total_bytes_sent']),
                            ('total_bytes_received', tunnel['total_bytes_received'])
                        ])

                # Older clients do not send this key
                if 'host_bytes' in stats.keys():
                    for domain, bytes in stats['host_bytes'].iteritems():
                        self._log_event('domain_bytes', inputs + [
                            ('domain', domain),
                            ('bytes', bytes)
                        ])

            except:
                start_response('403 Forbidden', [])
                return []

        # Clean up session data
        if request.params['connected'] == '0' and request.params.has_key('client_session_id'):
            self.session_redis.delete(request.params['client_session_id'])

        # No action, this request is just for stats logging
        start_response('200 OK', [])
        return []

    @exception_logger
    def speed(self, environ, start_response):
        request = Request(environ)

        # Note: 'operation' and 'info' are arbitrary strings. See note above.

        additional_inputs = [('operation', lambda x: True),
                             ('info', lambda x: True),
                             ('milliseconds', lambda x: consists_of(x, string.digits)),
                             ('size', lambda x: consists_of(x, string.digits))]
        inputs = self._get_inputs(request, 'speed', additional_inputs)
        if not inputs:
            start_response('404 Not Found', [])
            return []
        self._log_event('speed', inputs)
        # No action, this request is just for stats logging
        start_response('200 OK', [])
        return []

    @exception_logger
    def feedback(self, environ, start_response):
        # TODO: When enough people have upgraded, remove this handler completely
        start_response('200 OK', [])
        return []

    @exception_logger
    def check(self, environ, start_response):
        # Just check the server secret; no logging or action for this request
        request = Request(environ)
        if ('server_secret' not in request.params or
            not constant_time_compare(request.params['server_secret'], self.server_secret)):
            start_response('404 Not Found', [])
            return []
        start_response('200 OK', [])
        return []

    @exception_logger
    def stats(self, environ, start_response):
        # Just check the server secret; no logging or action for this request
        request = Request(environ)
        if ('server_secret' not in request.params or
            not constant_time_compare(request.params['server_secret'], self.server_secret) or
            'stats_client_secret' not in request.params or
            not hasattr(psi_config, 'STATS_CLIENT_SECRET') or
            not constant_time_compare(request.params['stats_client_secret'], psi_config.STATS_CLIENT_SECRET)):
            start_response('404 Not Found', [])
            return []
        contents = ''.join(list(cpstats.StatsPage().index()))
        response_headers = [('Content-Type', 'text/html'),
                            ('Content-Length', '%d' % (len(contents),))]
        start_response('200 OK', response_headers)
        return [contents]


def get_servers():
    # enumerate all interfaces with an IPv4 address and server entry
    # return an array of server info for each server to be run
    servers = []
    for interface in netifaces.interfaces():
        try:
            if (interface.find('ipsec') == -1 and interface.find('mast') == -1 and
                    netifaces.ifaddresses(interface).has_key(netifaces.AF_INET)):
                interface_ip_address = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
                server = psinet.get_server_by_internal_ip_address(interface_ip_address)
                if server:
                    servers.append(
                        (interface_ip_address,
                         server.web_server_port,
                         server.web_server_secret,
                         server.web_server_certificate,
                         server.web_server_private_key,
                         server.capabilities,
                         server.host_id))
        except ValueError as e:
            if str(e) != 'You must specify a valid interface name.':
                raise
    return servers


class WebServerThread(threading.Thread):

    def __init__(self, ip_address, port, secret, certificate, private_key, capabilities, host_id, server_threads):
        #super(WebServerThread, self).__init__(self)
        threading.Thread.__init__(self)
        self.ip_address = ip_address
        self.port = port
        self.secret = secret
        self.certificate = certificate
        self.private_key = private_key
        self.capabilities = capabilities
        self.host_id = host_id
        self.server = None
        self.certificate_temp_file = None
        self.private_key_temp_file = None
        self.server_threads = server_threads

    def stop_server(self):
        # Retry loop in case self.server.stop throws an exception
        for i in range(5):
            try:
                if self.server:
                    # blocks until server stops
                    self.server.stop()
                    self.server = None
                break
            except Exception as e:
                # Log errors
                for line in traceback.format_exc().split('\n'):
                    syslog.syslog(syslog.LOG_ERR, line)
                time.sleep(i)
        if self.certificate_temp_file:
            # closing the temp file auto deletes it (NOTE: not secure wipe)
            self.certificate_temp_file.close()
            self.certificate_temp_file = None
        if self.private_key_temp_file:
            self.private_key_temp_file.close()
            self.private_key_temp_file = None

    def run(self):
        # While loop is for recovery from 'unknown ca' issue.
        while True:
            try:
                server_instance = ServerInstance(self.ip_address, self.secret, self.capabilities, self.host_id)

                self.server = wsgiserver.CherryPyWSGIServer(
                                (self.ip_address, int(self.port)),
                                wsgiserver.WSGIPathInfoDispatcher(
                                    {'/handshake': server_instance.handshake,
                                     '/download': server_instance.download,
                                     '/connected': server_instance.connected,
                                     '/routes': server_instance.routes,
                                     '/failed': server_instance.failed,
                                     '/status': server_instance.status,
                                     '/speed': server_instance.speed,
                                     '/feedback': server_instance.feedback,
                                     '/check': server_instance.check,
                                     '/stats': server_instance.stats}),
                                numthreads=self.server_threads, timeout=20)

                self.server.stats['Enabled'] = True

                # Set maximum request input sizes to avoid processing DoS inputs
                self.server.max_request_header_size = 100000
                self.server.max_request_body_size = 100000

                # Lifetime of cert/private key temp file is lifetime of server
                # file is closed by ServerInstance, and that auto deletes tempfile
                self.certificate_temp_file = tempfile.NamedTemporaryFile()
                self.private_key_temp_file = tempfile.NamedTemporaryFile()
                self.certificate_temp_file.write(
                    '-----BEGIN CERTIFICATE-----\n' +
                    '\n'.join(split_len(self.certificate, 64)) +
                    '\n-----END CERTIFICATE-----\n');
                self.certificate_temp_file.flush()
                self.private_key_temp_file.write(
                    '-----BEGIN RSA PRIVATE KEY-----\n' +
                    '\n'.join(split_len(self.private_key, 64)) +
                    '\n-----END RSA PRIVATE KEY-----\n');
                self.private_key_temp_file.flush()
                self.server.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
                                              self.certificate_temp_file.name,
                                              self.private_key_temp_file.name,
                                              None)
                psi_web_patch.patch_ssl_adapter(self.server.ssl_adapter)
                # Blocks until server stopped
                syslog.syslog(syslog.LOG_INFO, 'started %s' % (self.ip_address,))
                self.server.start()
                break
            except (EnvironmentError,
                    EOFError,
                    SystemError,
                    ValueError,
                    ssl.SSLError,
                    socket.error) as e:
                # Log recoverable errors and try again
                for line in traceback.format_exc().split('\n'):
                    syslog.syslog(syslog.LOG_ERR, line)
                if self.server:
                    self.stop_server()
            except TypeError as e:
                trace = traceback.format_exc()
                for line in trace.split('\n'):
                    syslog.syslog(syslog.LOG_ERR, line)
                # Recover on this Cherrypy internal error
                # See bitbucket Issue 59
                if (str(e).find("'NoneType' object") == 0 and
                    trace.find("'SSL_PROTOCOL': cipher[1]") != -1):
                    if self.server:
                        self.stop_server()
                else:
                    raise
            except Exception as e:
                # Log other errors and abort
                for line in traceback.format_exc().split('\n'):
                    syslog.syslog(syslog.LOG_ERR, line)
                raise


# ===== GeoIP Service =====

class GeoIPServerInstance(object):

    @exception_logger
    def geoip(self, environ, start_response):
        request = Request(environ)
        geoip = psi_geoip.get_geoip(request.params['ip'])
        response_headers = [('Content-type', 'text/plain')]
        start_response('200 OK', response_headers)
        return [json.dumps(geoip)]


class GeoIPServerThread(threading.Thread):

    def __init__(self):
        #super(WebServerThread, self).__init__(self)
        threading.Thread.__init__(self)
        self.server = None

    def stop_server(self):
        # Retry loop in case self.server.stop throws an exception
        for i in range(5):
            try:
                if self.server:
                    # blocks until server stops
                    self.server.stop()
                    self.server = None
                break
            except Exception as e:
                # Log errors
                for line in traceback.format_exc().split('\n'):
                    syslog.syslog(syslog.LOG_ERR, line)
                time.sleep(i)

    def run(self):
        try:
            server_instance = GeoIPServerInstance()
            self.server = wsgiserver.CherryPyWSGIServer(
                            ('127.0.0.1', int(psi_config.GEOIP_SERVICE_PORT)),
                            wsgiserver.WSGIPathInfoDispatcher(
                                {'/geoip': server_instance.geoip}))

            # Blocks until server stopped
            syslog.syslog(syslog.LOG_INFO, 'started GeoIP service on port %d' % (psi_config.GEOIP_SERVICE_PORT,))
            self.server.start()
        except Exception as e:
            # Log other errors and abort
            for line in traceback.format_exc().split('\n'):
                syslog.syslog(syslog.LOG_ERR, line)
            raise


# ===== Main Process =====

def main():
    syslog.openlog(psi_config.SYSLOG_IDENT, syslog.LOG_NDELAY, psi_config.SYSLOG_FACILITY)
    threads = []
    servers = get_servers()
    # run a web server for each server entry
    # (presently web server-per-entry since each has its own certificate;
    #  we could, in principle, run one web server that presents a different
    #  cert per IP address)
    threads_per_server = 60
    if '32bit' in platform.architecture():
        # Only 381 threads can run on 32-bit Linux
        # Assuming 361 to allow for some extra overhead, plus the additional overhead
        # of 1 main thread and 2 threads per web server
        threads_per_server = min(threads_per_server, 360 / len(servers) - 2)
    for server_info in servers:
        thread = WebServerThread(*server_info, server_threads=threads_per_server)
        thread.start()
        threads.append(thread)
    print 'Web servers running...'

    geoip_thread = GeoIPServerThread()
    geoip_thread.start()
    threads.append(geoip_thread)
    print 'GeoIP server running...'

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt as e:
        pass
    print 'Stopping...'

    for thread in threads:
        thread.stop_server()
        thread.join()


if __name__ == "__main__":
    main()

