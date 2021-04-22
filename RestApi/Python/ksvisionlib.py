#################################################################################
#
# File:   ksvisionlib.py
# Date:   May 9, 2019
# Author: Fred Mota (fred.mota@keysight.com)
#
# Description:
# The intent of this file is to provide a Python package that will facilitate
# the access to Keysight Network Packet Broker (NPB) devices using the RESTful
# Web API interface.
#
# References:
#   - Using certificates in urllib3
#     http://stackoverflow.com/questions/23954120/using-certificates-in-urllib3
#
# History:i#
#  February 8, 2019:
#    - Initial version.
#    - In sync with the Network Visibility Software 5.0.0,
#      December 2018 - Web API version 5.0.0
#    - In sync with the "Ixia GSC 7400 Series Web API User Guide,"
#      GSC 1.5.0, October 2018
#
#  March 25, 2019:
#    - Added the getPortGroupProperties method.
#
#  April 15, 2019:
#    - Added getters and setters for: debud and request_timeout
#    - Check the return code after sending a request and raise an alarm if
#      necessary.
#
#  December 15, 2019:
#    - Added getFilterProperties
#
#  December 22, 2019:
#    - Replaced % string formatting with prefered format function.
#    - Renamed method getAeEventsSummaryReportAction to getAeEventsSummaryReport
#
#    - Added Vision NPB v5.0.2 Changes:
#        - Added method getAeEventsReportHistory
#
#    - Added Vision NPB v5.1.0 Changes:
#        - Added method getEventsSummaryReport
#        - Added method getChannelLatencyStats
#        - Added method getAllEodReportsInfo
#        - Added method getCteNeighbors
#        - Added method installNetservice
#        - Added method removeNetservice
#        - Added method removePortModuleConfiguration
#        - Added method validateAuthCalls
#        - Added method forcePowerPortModule
#        - Added all the methods for GTP FD resources
#        - Added all the methods for Netservice Instances
#
#    - Added Vision NPB v5.2.0 Changes:
#        - Added method markEodReportAsGolden
#        - Added method optimizeRoutes
#        - Added method getAllIfcRoutes
#        - Added method getIfcRoute
#        - Added method searchIfcRoute
#
# December 24, 2019:
#    - Added Vision NPB v5.3.0 Changes:
#        - Added method sendSyntheticPackets
#        - Added method restoreFirewall
#        - Added all the methods for CTE Monitors
#        - Added all the methods for CTE Netflow Resources
#
# April 30, 2020:
#    - Added method exportOfflineLicenseActivationRequest
#    - Added Vision NPB v5.4.0 Changes:
#        - Added method getLfdLocalPorts
#        - Added method getLfdPeerPorts
#        - Added method getChannelBurstStats
#        - Renamed method optimizeRoutes to optimizeCteRoutes
#        - Added method resetCteEventRateLimiterStatus
#        - Added all the methods for Kubernetes Nodes
#        - Added all the methods for IFC Capture Resources
#    - Added GSC v1.5.3 Changes:
#        - Added method getNumberSessions
#
# July 22, 2020:
#    - Fixed error in __str__
#    - Added Vision NPB v5.5.0 Changes:
#        - Added method getMemoryMetersPreview
#        - Added method autoDetectChannels
#        - Added method getAvailableFilterCriteria
#        - Added method getEarlyClassificationCriteria
#
# October 8, 2020:
#    - Added Vision NPB v5.6.0 Changes:
#        - Added method changeOfflinePortSpeed
#        - Added method deployNetServiceInstance
#        - Added method installMakoOs
#        - Added method removePlugin
#        - Added method clearCteAeChannelStatsHistory
#    - Fixed getAllNetserviceInstancesType, changed PUT to GET
#    - Fixed restartNetserviceInstance, changed PUT to POST
#
# November 18, 2020:
#    - Renamed createBypass to createInlineBypassConnector
#    - Renamed getBypass to getInlineBypassConnector
#    - Renamed getAllBypasses to getAllInlineBypasseConnectors
#    - Renamed searchBypass to searchInlineBypassConnectors
#    - Renamed modifyBypass to modifyInlineBypassConnector
#    - Added deleteInlineBypassConnector
#    - Renamed createInline to createInlineServiceChain
#    - Renamed deleteInline to deleteInlineServiceChain
#    - Renamed getInline to getInlineServiceChain
#    - Renamed getAllInlines to getAllInlineServiceChains
#    - Renamed searchInline to searchInlineServiceChains
#    - Renamed modifyInline to modifyInlineServiceChain
#    - Added all the methods for Inline Tool Connectors
#    - Added all the methods for Inline Tool Resources
#
# November 21, 2020:
#    - Added Vision NPB v5.6.1 Changes:
#        - Added method updateSingleIpAddress
#
# December 18, 2020:
#    - Added Vision NPB v5.7.0 Changes:
#        - Added all the methods for Aggregator Resources
#        - Added all the methods for GSC Resources
#        - Added method resumeItrTraffic
#        - Added method backupGscConfig
#        - Added method restoreGscConfig
#        - Added method discoverCteConnections
#        - Added method updateCteUpdateSingleIpAddress
#    - Added timeout and reties to the VisionWebApi __init__ function
#    - Added the retries decorators
#
# January 23, 2021
#    - Added method modifyCtePort
#    - Added method createCtePortGroup
#    - Added method deleteCtePortGroup
#    - Added method disableCtePortGroup
#    - Added method enableCtePortGroup
#    - Added method modifyCtePortGroup
#
# February 15, 2021
#    - Added API versioning support
#
# March 11, 2021:
#    - Added Vision NPB v5.7.1 Changes:
#        - Added method clearPort
#    - Added method createPort
#    - Added method deletePort
#    - Added method getPortTransceiverInfo
#
# April 22, 2021
#    - Added all the methods for Boards
#
# COPYRIGHT 2019-2021 Keysight Technologies.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
################################################################################

import urllib3
import base64
import json
import time
import os
import sys

class KeysightNpbExceptions(Exception):
    """Base class for exceptions in this module."""
    pass

class ConnectionError(KeysightNpbExceptions):
    """Exception raised for maximum retries connection errors."""
    pass

class AuthenticationError(KeysightNpbExceptions):
    """Exception raised for authentication errors."""
    pass

class webAPIError(KeysightNpbExceptions):
    """Exception raised for API errors."""
    def __init__(self, code):
        super(webAPIError, self).__init__()
        self.code = code

    def __str__(self):
        return "Return code = {0}".format(self.code)

class webAPIClientError(webAPIError):
    """Exception raised for API client errors."""
    pass

class webAPIServerError(webAPIError):
    """Exception raised for API server errors."""
    pass

class UnknownError(KeysightNpbExceptions):
    """Exception raised for unknown errors."""
    pass

class VisionWebApi(object):

    def __init__(self, host, username, password, port=8000, debug=False, log_file=None, timeout=30, retries=2, version=None):
        #urllib3.disable_warnings()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.host = host
        self.port = port
        self.user = username
        self.password = password
        self.__debug = debug
        self.auth_b64 = ''
        self.password_headers = ''
        self.token_headers = ''
        self.version = version
        self.connection = ''
        self.log_file = log_file
        self.__request_timeout = timeout
        self.__request_retries = retries

        self.auth_b64 = base64.b64encode(bytearray(username + ":" + password, 'ascii')).decode('ascii')
        self.password_headers = { 'Authorization' : 'Basic ' + self.auth_b64, 'Content-type' : 'application/json' }

        #self.connection = urllib3.connectionpool.HTTPSConnectionPool(host, port=port, ssl_version='TLSv1_2')
        self.connection = urllib3.connectionpool.HTTPSConnectionPool(host, port=port, cert_reqs='CERT_NONE', ca_certs=None, timeout=self.__request_timeout, retries=self.__request_retries)

        try:
            response = self.connection.urlopen('GET', '/api/auth', headers=self.password_headers)
        except urllib3.exceptions.MaxRetryError:
            raise ConnectionError
        except:
            raise UnknownError

        if self.__debug:
            self._log ("Status={:d}\n".format(response.status))
            self._log ("Reason={:s}\n".format(response.reason))
            self._log ("Headers={:}\n".format(response.headers))
            self._log ("Data={:}\n".format(response.data))

        try:
            self.token = response.headers['x-auth-token']
        except:
            raise AuthenticationError

        self.token_headers = { 'Authentication' : self.token, 'Content-type' : 'application/json' }
        if self.version:
            self.token_headers.update({'Version': self.version})

    def __str__(self):
        return "VisionWebApi(host='{:s}', port={:d}, user='{:s}', password='{:s}', auth64='{:s}', password_hdrs='{:s}', token_hdrs='{:s}', connection='{:s}', debug={:s}, log_file={:s}, timeout={:d}, retries={:d}, version={:s})".format(self.host, self.port,  self.user, self.password, self.auth_b64, str(self.password_headers), str(self.token_headers), str(self.connection), str(self.__debug), str(self.log_file), self.__request_timeout, self.__request_retries, str(self.version))

    def __repr__(self):
        return str(self)

    def _log(self, message):
        handle = open(self.log_file, 'a') if self.log_file else sys.stdout
        handle.write(message)
        if handle is not sys.stdout:
            handle.close()

    def _sendRequest(self, httpMethod, url, args=None, decode=True):
        """ Send the request to the Web API server."""

        response = None
        if self.__debug:
            self._log ("Sending a message to the server with parameters:\n")
            self._log (" httpMethod={:s}\n".format(httpMethod))
            self._log (" url={:s}\n".format(url))
            self._log (" args={:s}\n".format(str(args)))

        args = json.dumps(args)
        response = self.connection.urlopen(httpMethod, url, body=args, headers=self.token_headers)

        if self.__debug:
            self._log ("Response:\n")
            self._log (" Status={:d}\n".format(response.status))
            self._log (" Reason={:s}\n".format(response.reason))
            self._log (" Headers={:}\n".format(response.headers))
            self._log (" Data={:}\n".format(response.data))
            self._log (" decode={:}\n".format(decode))

        if (response.status >= 400) and (response.status <= 499):
            raise webAPIClientError(response.status)
        elif (response.status >= 500) and (response.status <= 599):
            raise webAPIServerError(response.status)
        elif response.status != 200:
            raise webAPIError(response.status)

        data = response.data
        if decode:
            #data = json.loads(data.decode('ascii'))
            data = json.loads(data.decode('iso-8859-1'))

        return data

    @property
    def debug(self):
        """ Get the debug flag """
        return self.__debug

    @debug.setter
    def debug(self, flag):
        """ Set the debug flag """
        self.__debug = flag

    @property
    def request_timeout(self):
        """ Get the request timeout """
        return self.__request_timeout

    @request_timeout.setter
    def request_timeout(self, timeout):
        """ Set the request timeout """
        self.__request_timeout = timeout
        self.connection.timeout = urllib3.Timeout(connect=timeout, read=timeout)

    @property
    def request_retries(self):
        """ Get the request retries """
        return self.__request_retries

    @request_retries.setter
    def request_retries(self, retries):
        """ Set the request retries """
        self.__request_retries = retries
        self.connection.retries = urllib3.Retry(connect=retries, read=retries)

    def authenticate(self):
        """ authenticate :
        Athenticate with the NTO using username and password.
        Sample usage:
        >>> nto.authenticate()
        """
        response = self.connection.urlopen('GET', '/api/auth', headers=self.password_headers)

        if self.__debug:
            self._log ("Status={:d}\n".format(response.status))
            self._log ("Reason={:s}\n".format(response.reason))
            self._log ("Headers={:s}\n".format(response.headers))
            self._log ("Data={:s}\n".format(response.data))

        self.token_headers = { 'Authentication' : response.headers['x-auth-token'], 'Content-type' : 'application/json' }

    ###################################################
    # Actions
    ###################################################
    def addAggregationSwitch(self):
        """ addAggregationSwitch :
        Adds a new Aggregation Switch to a Switch Cluster.
        
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/add_aggregation_switch', None)

    def autoDetectChannels(self, args):
        """ autoDetectChannels :
        Allows Auto Detection of Channels per Analysis Engine.
        
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/auto_detect_channels', args)

    def certificateManagement(self, args):
        """ certificateManagement :
        Allows Syslog and TLS/HTTPS certificates to be uploaded and deleted. Basic
        information can also be viewed for certificates installed on the system.
        
        Sample usage:
        >>> nto.certificateManagement({'action': 'VIEW', 'certificate_use': 'DEFAULT_TLS_HTTPS'})
        {u'authentication': [{u'valid_from': u'May 28, 2015 10:06:25 AM GMT', u'sha1_fingerprint': u'D3:75:74:30:D7:D8:50:FE:73:2F:10:E3:62:59:1B:EF:83:24:44:58', u'signature_algorithm': u'SHA256WITHRSA', u'valid_to': u'May 25, 2025 10:06:25 AM GMT', u'version': u'3', u'signature': u'12:B5:F1:75:7B:26:86:B2:C7:CE:A8:CE:74:CC:E8:82:8A:A3:45:45:AB:D3:DF:35:96:6A:50:61:F7:70:32:51:0A:03:5E:D1:14:1E:19:8E:ED:1A:E0:71:6E:CD:79:3C:67:70:F1:66:73:6C:1E:4F:97:97:94:79:25:D9:16:9C:B5:C7:E1:84:2A:A4:D6:FE:74:E7:E1:B5:B7:E0:32:0F:12:EA:A0:9C:62:75:D8:70:63:1B:C2:04:67:B9:33:5B:FE:9F:73:20:8B:AF:92:EA:6E:1A:61:B7:79:2A:AF:9E:50:EF:7D:7D:CE:DD:55:BD:20:E3:D7:C3:49:EB:A1:7D:B7:C8:89:43:19:13:59:4D:B6:2F:B9:22:8C:06:5C:4D:BB:8C:03:5B:45:B2:6D:DC:B5:4A:80:9A:14:32:2B:44:9D:CF:83:D8:E8:81:B8:77:94:2D:71:D0:54:ED:47:53:45:06:28:39:86:7D:EF:9D:3D:DC:BD:06:E0:BC:EF:62:AA:85:02:20:D7:E6:61:4E:12:81:04:9E:42:AA:40:18:4F:1B:3D:41:62:9B:E4:36:A9:F8:39:5F:60:2B:C1:83:5D:CF:FE:9F:3B:C0:FD:62:A7:D6:47:9E:C4:73:02:CA:C6:86:F5:7B:52:5B:E8:58:3B:23:57:3F:EE:2C:09:E2', u'serial_number': u'1165506059 (4578360b)', u'md5_fingerprint': u'57:7E:03:2E:2B:67:AA:E7:75:44:AA:21:5C:8F:BE:A1', u'subject': u'CN=Ixia, OU=Ixia, O=Ixia, L=Calabasas, ST=California, C=US', u'issuer': u'CN=Ixia, OU=Ixia, O=Ixia, L=Calabasas, ST=California, C=US'}]}
        """
        if 'action' in args:
            if (args['action'] == 'VIEW') or (args['action'] == 'DELETE'):
                return self._sendRequest('POST', '/api/actions/certificates', args)

            elif args['action'] == 'UPLOAD':
                # TLS/HTTPS
                authentication = None
                if 'authentication' in args:
                    authentication = args['authentication']
                    del args['authentication']

                # Syslog - Client
                client = None
                if 'client' in args:
                    client = args['client']
                    del args['client']

                # Syslog - Trsuted Root
                trusted_root = None
                if 'trusted_root' in args:
                    trusted_root = args['trusted_root']
                    del args['trusted_root']

                boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

                buffer = bytearray()

                # Set param
                buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
                buffer.extend(b'Content-Disposition: form-data; name="param"\r\n')
                buffer.extend(b'Content-Type: application/json\r\n')
                buffer.extend(b'\r\n')
                buffer.extend(bytearray(json.dumps(args), 'ascii'))
                buffer.extend(b'\r\n')
                buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')

                # Set creative contents part.
                if authentication:
                    buffer.extend(b'Content-Disposition: form-data; name="authentication"; filename=' + bytearray(authentication, 'ascii') + b'\r\n')
                    buffer.extend(b'Content-Type: application/octet-stream\r\n')
                    buffer.extend(b'\r\n')
                    # TODO: catch errors with opening file.
                    buffer.extend(open(authentication, 'rb').read())
                    buffer.extend(b'\r\n')

                    buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')

                if client:
                    buffer.extend(b'Content-Disposition: form-data; name="client"; filename=' + bytearray(client, 'ascii') + b'\r\n')
                    buffer.extend(b'Content-Type: application/octet-stream\r\n')
                    buffer.extend(b'\r\n')
                    # TODO: catch errors with opening file.
                    buffer.extend(open(client, 'rb').read())
                    buffer.extend(b'\r\n')

                    buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')

                if trusted_root:
                    buffer.extend(b'Content-Disposition: form-data; name="trusted_root"; filename=' + bytearray(trusted_root, 'ascii') + b'\r\n')
                    buffer.extend(b'Content-Type: application/octet-stream\r\n')
                    buffer.extend(b'\r\n')
                    # TODO: catch errors with opening file.
                    buffer.extend(open(trusted_root, 'rb').read())
                    buffer.extend(b'\r\n')

                    buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')

                buffer.extend(b'\r\n')

                hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
                response = self.connection.urlopen('POST', '/api/actions/certificates', body=buffer, headers=hdrs)
                #self._log (response.status, response.reason)
                data = response.data
                
                return data

    def changeRole(self):
        """ changeRole :
        This command changes role between supervisor and independent.
        Sample usage:
        >>> nto.changeRole()
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/change_role', args)

    def changeFilterPriority(self, args):
        """ changeFilterPriority :
        Allows changing the priority of connections between ports and port
        groups to out of band (i.e., non-inline) dynamic filters. To update
        the priority of inline filters, update the inline_service_chain_priority_list
        of the corresponding inline Bypass connector.
        This should only be used when the filter build mode is PRIORITY
        (see system memory_allocation property, filter_build_settings).
        This method is allowed only on the following models: Vision One, E40, E100
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/change_filter_priority', args)

    def changePortSpeed(self, args):
        """ changePortSpeed :
        Changes the speed configuration of port.
        Sample usage:
        >>> nto.changePortSpeed({'port_list': [64], 'qsfp28_port_mode': 'MODE_QSFP'})
        '{}'
        """
        return self._sendRequest('POST', '/api/actions/change_speed_configuration', args, False)

    def changeOfflinePortSpeed(self, args):
        """ changeOfflinePortSpeed :
        This action will change the speed configuration of an offline port.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/change_offline_speed_configuration', args, False)

    def clearAeChannelStatsHistory(self, args):
        """ clearAeChannelStatsHistory :
        Clears the Burst and/or Latency & Jitter Stats History Files from the Disk per AE.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/clear_ae_channel_statistics_history', args)

    def clearAggregationSwitch(self):
        """ clearAggregationSwitch :
        Clears the configuration of an aggregation switch.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/clear_aggregation_switch', None)

    def changeQsfp28PortMode(self, args):
        """ changeQsfp28PortMode :
        Changes the QSFP mode of a QSFP28 port.
        * This method was deprecated in v4.8.0, and replaced with change_speed_configuration.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/change_qsfp28_port_mode', args, False)

    def changeSpeedConfiguration(self, args):
        """ changeSpeedConfiguration :
        Changes the speed configuration of port..
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/change_speed_configuration', args, False)

    def changePortAggregationMode(self, args):
        """ changePortAggregationMode :
        * This method was deleted in v4.7.5.
        Agregates four 10G ports into one 40G port and backward.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/change_port_aggregation_mode', args, False)

    def clearConfig(self):
        """ clearConfig :
        Clear the configuration by deleting all filters, regular users, groups,
        filter templates, filter template collections, port groups, and custom
        icons and by setting all ports to default values.
        Sample usage:
        >>> nto.clearConfig()
        {u'message': u'Configuration cleared.'}
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/clear_config', args)
    
    def clearFiltersAndPorts(self):
        """ clearFiltersAndPorts :
        This command deletes all filters and port groups and sets all ports to
        default values.
        Sample usage:
        >>> nto.clearFiltersAndPorts()
        {u'message': u'Filters and ports cleared.'}
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/clear_filters_and_ports', args)

    def clearSystem(self):
        """ clearSystem :
        This command clears the system and restores it to a default state, including
        resetting the admin account to default values. The license currently
        installed will not be removed.
        Sample usage:
        >>> nto.clearSystem()
        {u'message': u'System restored to default state.'}
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/clear_system', args)

    def deployNetServiceInstance(self, args):
        """ deployNetServiceInstance :
        This command will deploy a netservice instance based on a default name.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/deploy_net_service_instance', args, False)

    def drainNetServiceInstance(self, args):
        """ drainNetServiceInstance :
        This command will drain a netservice instance based on a default name.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/drain_net_service_instance', args, False)

    def enableFipsServerEncryption(self):
        """ enableFipsServerEncryption :
        This commands causes FIPS encryption to be enabled on the server.
        Sample usage:
        *** TO BE TESTED ***
        >>> nto.enableFipsServerEncryption()
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/enable_fips_server_encryption', args)

    def exportConfig(self, args):
        """ exportConfig :
        Return configuration settings from an NTO to a file.
        Sample usage:
        nto.exportConfig({'boundary' : 'INCLUDE', 'description' : 'SNMP Config', 'export_type' : 'CUSTOM', 'file_name' : '/Users/fmota/Desktop/snmp+user.ata', 'user': None, 'system' : 'snmp_config'})
        """
        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest('POST', '/api/actions/export', args, False)
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def exportOfflineLicenseActivationRequest(self, args):
        """ exportOfflineLicenseActivationRequest :
        Export the request file for FNOOD offline license activation for the current system.
        Sample usage:
        *** TO BE TESTED ***
        """
        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest('POST', '/api/actions/export_offline_license_request_file', args, False)
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def exportKeyGenLicense(self, args):
        """ exportKeyGenLicense :
        Export the KeyGen license details to a json file that can be used
        on the migration portal to obtain a new style license for an NTO
        or an union.
        Sample usage:
        >>> nto.exportKeyGenLicense({'file_name': 'mylicense'})
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest('POST', '/api/actions/export_keygen_license_to_json', args, False)
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def fipsServerEncryptionStatus(self):
        """ fipsServerEncryptionStatus :
        This commands causes FIPS encryption to be enabled on the server.
        Sample usage:
        *** TO BE TESTED ***
        >>> nto.fipsServerEncryptionStatus()
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/fips_server_encryption_status', args)

    def factoryReset(self):
        """ factoryReset :
        This command clears the system and restores it to a factory default
        state, including resetting the admin account to default values. The
        license currently installed will also be removed.
        Sample usage:
        >>> nto.factoryReset()
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/factory_reset', args)

    def forcePowerPortModule(self, args):
        """ forcePowerPortModule :
        This command will power on/off the port module in the given module location.
        This method is allowed only on the following models: 8000.
        Sample usage:
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/force_power_port_module', args, False)

    def generateCsr(self, args):
        """ generateCsr :
        Allows Syslog and TLS/HTTPS certificates to be uploaded and deleted. Basic
        information can also be viewed for certificates installed on the system.
        Sample usage:
        >>> nto.generateCsr({'csr_use' : 'SYSLOG', 'tls_cert_request_info' : {'city' : 'Austin', 'common_name' : 'Test API', 'country' : 'US', 'organization' : 'Ixia', 'organization_unit' : 'NVS', 'state' : 'TX', 'subject_alt_name' : 'Anue'}})
        {u'csr': u'-----BEGIN CERTIFICATE REQUEST-----MIIC5zCCAc8CAQAwWzELMAkGA1UECBMCVFgxDzANBgNVBAcTBkF1c3RpbjELMAkGA1UEBhMCVVMxDDAKBgNVBAsTA05WUzENMAsGA1UEChMESXhpYTERMA8GA1UEAxMIVGVzdCBBUEkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4RNOnSPTRamGkAwj/otEgzAFYIEXlpsO4OS16P49l3c0n5ShDs0uo2pd4a0Qe4Wvh/KX4L1oZbxS/2YNJgNlLiRkHo5K62ZYYskfNGXPBYfkkRDLk76SrhgHyoGSEy8h6OdeE2QpfgsD/XLQVoFQ3dVemSwo76bE3Vap333fJmvtNJNgItkKqKBW3zF1doSWJwEHDwwhG9/KSfFBHf/qE51LRj2iybZQE4ijZGHv0I7CtSF20166sH75EhsoK8/vs1RT6LpyuEM9JKoRzmvE1ufk3nHtlvF3UniUluUCubXfldaEROIeBvYfoWZGGuyzAN01ZbxZ+/K2ENokpVKPbAgMBAAGgRzBFBgkqhkiG9w0BCQ4xODA2MA8GA1UdEQQIMAaCBEFudWUwDgYDVR0PAQH/BAQDAgUgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQAfVnwTv1t56YWU2W5+Fjlc9nuTL7eAoKqkioTJ1CuAINLybbHYUVXVfpBahfjj7g6ZmiWZ383SK7ImuPfHE7kt/eRDna+/+HUQ22799HQmyLcxCkYZVSH8gWkTNbUIhgh4AFMwt83zWu324P+qNkh5u0sckPTfNzry3Mxz2QzmM5sP+oU8/RCt04iYzz5KSu+tzHWJ9FOGLQqQ73Ausz0smTDFBlVLs8VCifHVc2QmSbIofHVPUOUEjWo+FFb6WK6/7NjgE4DM9rVDV7eW9WXZgos6WnXRVMIpedeibh31iM/sc63F0tQHXt696kfO19LBc6FLMKLCvVtkGfSnq5u9-----END CERTIFICATE REQUEST-----'}
        """
        return self._sendRequest('POST', '/api/actions/generate_csr', args)

    def getAllEodReportsInfo(self, args):
        """ getAllEodReportsInfo :
        Returns the list of all Eod events summary Report for all AEs in a TradeVision.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/get_ae_events_report_info', args)

    def getAvailableFilterCriteria(self, args):
        """ getAvailableFilterCriteria :
        Return a list of filter criteria which can be used given an already
        present set of filter criteria.
        Sample usage:
        >>> nto.getAvailableFilterCriteria({'filter_object_type': 'FILTER'})
        []
        """
        return self._sendRequest('POST', '/api/actions/get_available_filter_criteria', args)

    def getChannelBurstStats(self, args):
        """ getChannelBurstStats :
        This command is used to get the Channel Burst statisics for a given channel id and VLAN Match type per Analysis Engine.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/get_channel_burst_stats', args)

    def getChannelLatencyStats(self, args):
        """ getChannelLatencyStats :
        This command is used to get the latency/jitter statisics for a given channel id and VLAN Match type per Analysis Engine.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/get_channel_latency_stats', args)

    def getDtspChannelInfo(self, args):
        """ getDtspChannelInfo :
        This command is used to get the channel info based on a given list of channel IP:Port.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/get_dtsp_channel_info', args)

    def getEventsSummaryReport(self):
        """ getEventsSummaryReport :
        Return a End-Of-Day report by name or a comparison report between two different End-Of-Day reports.
        If report name is specified, event summary report is returned.
        If two report names are specified, a new report is generated holding the differences between the two EOD reports.
        Sample usage:
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/get_ae_events_report_action', args)

    def getAeEventsReportHistory(self):
        """ getAeEventsReportHistory :
        Return either a list of the latest 8 End-Of-Day reports run on the system or a comparison between
        two different End-Of-Day reports. If no report dates are specified, the latest 8 End-Of-Day reports
        are returned (the maximum number of EOD reports retained by the system). If two dates are specified
        (representing the end date of two different EOD reports), a new report is generated holding the
        differences between the two EOD reports. Note that the end dates must be from any of the latest 8
        EOD reports run.
        Sample usage:
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/get_ae_events_report_history_action', args)

    def getAeEventsSummaryReport(self):
        """ getAeEventsSummaryReport :
        Return events summary report for all the AEs in a TradeVision.
        Sample usage:
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/get_ae_events_summary_report_action', args)

    def getLoginInfo(self):
        """ getLoginInfo :
        Returns last login session details plus hardware info and sensor readings for the device
        Sample usage:
        >>> nto.getLoginInfo()
        {
            "hardware_info": {
                    "cpld_rev": null,
                    "fpga_rev": null,
                    "mac_address": "001B6E08D47F",
                    "mac_address2": "001b6e08d47f",
                    "max_cool_temperature": 49,
                    "max_hot_temperature": 81,
                    "max_ok_temperature": 57,
                    "module_list": [ ... ],
                    "primary_mgmt_port": "eth0",
                                    "secondary_mgmt_port": null,
                                    "snmp_engine_id": "0x80007f6c03001B6E08D47F",
                                    "system_id": "E40-00001456",
                                    "top_assembly_number": "Vision E40"
            },
            "has_license_file": true,
            "is_password_expired": false,
            "password_change_required": false,
            "prev_login_info": {
                    "client_ip_address": "156.140.231.30",
                    "failures_count": 0,
                    "is_sysadm_modified": false,
                    "timestamp": 1536342551729
            }
        }
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/get_login_info', args)

    def getFabricPorts(self, args):
        """ getFabricPorts :
        Return fabric ports information for one or more members. This
        information can be used as input to the update_fabric_ports action.
        Sample usage:
        >>> nto.getFabricPorts()
        """
        return self._sendRequest('POST', '/api/actions/get_fabric_ports', args)

    def getHaCliConfig(self):
        """ getHaCliConfig :
        Returns the HA config needed by CLI.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/get_ha_config_for_cli')

    def getMemoryMeters(self):
        """ getMemoryMeters :
        Return the filter memory meters showing memory allocation and percentage used.
        Sample usage:
        >>> nto.getMemoryMeters()
        [{u'unit_name': u'LC1', u'memory_meters': [{u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 89, u'avail_pcnt': 100, u'meter_name': u'FILTER_ETHERTYPE_VLAN_L3_L4'}, {u'alloc_pcnt': 89, u'avail_pcnt': 100, u'meter_name': u'FILTER_L2_L3_L4'}], u'memory_type': u'DYNAMIC_FILTER_NON_IP'}, {u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 50, u'avail_pcnt': 100, u'meter_name': u'DYNAMIC_SIP_IPV4'}, {u'alloc_pcnt': 50, u'avail_pcnt': 100, u'meter_name': u'DYNAMIC_DIP'}], u'memory_type': u'DYNAMIC_FILTER_IP'}, {u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 100, u'avail_pcnt': 100, u'meter_name': u'NETWORK_PORT_L2_L3_IPV4'}], u'memory_type': u'NETWORK_PORT_FILTER'}, {u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 100, u'avail_pcnt': 100, u'meter_name': u'TOOL_PORT_L2_L3_IPV4'}], u'memory_type': u'TOOL_PORT_FILTER'}]}, ...
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/get_memory_meters', args)

    def getMemoryMetersPreview(self, args):
        """ getMemoryMetersPreview :
        Accepts a memory allocation configuration and return what the filter memory meters would be for that allocation.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/get_memory_meters_preview', args)

    def getTransceiverInfo(self):
        """ getTransceiverInfo :
        Return the transceiver information.
        Sample usage:
        >>> nto.getTransceiverInfo()
        [{'lanes': 1, 'port_default_name': 'P01', 'port_id': '16', 'port_name': 'P01', 'transceiver_info': [{'cable': 'N/A', 'compliance': '100G AOC or 25GAUI C2M AOC', 'connector': 'No separable connector', 'diag_calibration': 'Not Applicable', 'identifier': 'QSFP28', 'length_comment': 'OM4 50um', 'length_mode': 'Unspecified', 'max_length': '6 meters', 'present': 'true', 'rx_input_power1': '1.3392', 'rx_input_power1_dbm': '1.27', 'rx_input_power2': '1.3545', 'rx_input_power2_dbm': '1.32', 'rx_input_power3': '1.3764', 'rx_input_power3_dbm': '1.39', 'rx_input_power4': '1.352', 'rx_input_power4_dbm': '1.31', 'rx_input_power_high_alert_threshold': '3.4673', 'rx_input_power_high_alert_threshold_dbm': '5.40', 'rx_input_power_high_warning_threshold': '1.7378', 'rx_input_power_high_warning_threshold_dbm': '2.40', 'rx_input_power_low_alert_threshold': '0.0467', 'rx_input_power_low_alert_threshold_dbm': '-13.31', 'rx_input_power_low_warning_threshold': '0.0933', 'rx_input_power_low_warning_threshold_dbm': '-10.30', 'rx_input_power_status1': 'Normal', 'rx_input_power_status2': 'Normal', 'rx_input_power_status3': 'Normal', 'rx_input_power_status4': 'Normal', 'temperature': '35', 'temperature_high_alert_threshold': '80', 'temperature_high_warning_threshold': '70', 'temperature_low_alert_threshold': '-10', 'temperature_low_warning_threshold': '0', 'temperature_status': 'Normal', 'tx_bias1': '6.75', 'tx_bias2': '6.75', 'tx_bias3': '6.75', 'tx_bias4': '6.75', 'tx_bias_high_alert_threshold': '8.5', 'tx_bias_high_warning_threshold': '8.0', 'tx_bias_low_alert_threshold': '5.492', 'tx_bias_low_warning_threshold': '6.0', 'tx_bias_status1': 'Normal', 'tx_bias_status2': 'Normal', 'tx_bias_status3': 'Normal', 'tx_bias_status4': 'Normal', 'tx_output_power1': '1.6412', 'tx_output_power1_dbm': '2.15', 'tx_output_power2': '1.6222', 'tx_output_power2_dbm': '2.10', 'tx_output_power3': '1.5521', 'tx_output_power3_dbm': '1.91', 'tx_output_power4': '1.5447', 'tx_output_power4_dbm': '1.89', 'tx_output_power_high_alert_threshold': '3.4673', 'tx_output_power_high_alert_threshold_dbm': '5.40', 'tx_output_power_high_warning_threshold': '1.7378', 'tx_output_power_high_warning_threshold_dbm': '2.40', 'tx_output_power_low_alert_threshold': '0.0724', 'tx_output_power_low_alert_threshold_dbm': '-11.40', 'tx_output_power_low_warning_threshold': '0.1445', 'tx_output_power_low_warning_threshold_dbm': '-8.40', 'tx_output_power_status1': 'Normal', 'tx_output_power_status2': 'Normal', 'tx_output_power_status3': 'Normal', 'tx_output_power_status4': 'Normal', 'vendor_date_code': '05-07-2018', 'vendor_lot_code': '  ', 'vendor_name': 'Mellanox', 'vendor_oui': '0002c9', 'vendor_part_number': 'MFA1A00-C003', 'vendor_rev': 'B1', 'vendor_serial_number': 'MT1823FT00529', 'voltage': '3.2691', 'voltage_high_alert_threshold': '3.5', 'voltage_high_warning_threshold': '3.465', 'voltage_low_alert_threshold': '3.1', 'voltage_low_warning_threshold': '3.135', 'voltage_status': 'Normal', 'wavelength': '8500'}]},
            <snip>
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/get_transceiver_info', args)

    def getNeighbors(self, args):
        """ getNeighbors :
        Get neighbors of a list of ports given as parameter. If the list given is empty or is not given at all, it will return
        all neighbors for all ports that are valid for LLDP and have valid neighbors registrations.
        This method is allowed only on the following models: E40, TradeVision
        Sample usage:
        >>> nto.getNeighbors({'port_id_list': [8]})
        {u'P49': [{u'system_name': u'Ixia Vision One (Neo10 project)', u'port_description': u'', u'system_description': u'', u'expired': False, u'age': 1, u'chassis_id': u'00:1b:6e:04:8d:44', u'custom_tlvs': [], u'ttl': 120, u'port_id': u'P50', u'system_capabilities': u'', u'management_addresses': [], u'last_seen': 1577241420}]}
        """
        return self._sendRequest('POST', '/api/actions/get_neighbors', args)['message']

    def getLfdLocalPorts(self):
        """ getLfdLocalPorts :
        Get a list of local ports valid for LFD.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/get_local_ports_valid_for_lfd', {})

    def getLfdPeerPorts(self):
        """ getLfdPeerPorts :
        Get a list of peer ports valid for LFD.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/get_peer_ports_valid_for_lfd', {})

    def getEarlyClassificationCriteria(self):
        """ getEarlyClassificationCriteria :
        Get a list of valid early classification criteria for Intersection filtering.
        This method is allowed only on the following models: 7816, 8000, E100.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/get_early_classification_criteria', {})

    def getAllNeighbors(self, port_id_list=[]):
        """ getAllNeighbors :
        Fetch a list containing summaries for all the neigbors the system learned by snooping on LLDP messages.
        Sample usage:
        >>> nto.getAllNeighbors()
        {u'P50': [{u'system_name': u'Ixia Vision One (Neo10 project)', u'port_description': u'', u'system_description': u'', u'expired': False, u'age': 1, u'chassis_id': u'00:1b:6e:04:8d:44', u'custom_tlvs': [], u'ttl': 120, u'port_id': u'P49', u'system_capabilities': u'', u'management_addresses': [], u'last_seen': 1577241872}], u'P49': [{u'system_name': u'Ixia Vision One (Neo10 project)', u'port_description': u'', u'system_description': u'', u'expired': False, u'age': 3, u'chassis_id': u'00:1b:6e:04:8d:44', u'custom_tlvs': [], u'ttl': 120, u'port_id': u'P50', u'system_capabilities': u'', u'management_addresses': [], u'last_seen': 1577241870}]}
        """
        # TODO TEST we got HTTP/200 with JSON back
        # TODO TEST we got 'message' key back
        return self._sendRequest('POST', '/api/actions/get_neighbors', {'port_id_list': port_id_list})['message']

    def getObjectType(self, args):
        """ getObjectType :
        Return the object type for an internal id.
        Sample usage:
        >>> nto.getObjectType({'id':238})
        {u'object_type': u'PORT'}
        """
        return self._sendRequest('POST', '/api/actions/get_object_type', args)

    def getProperties(self, args):
        """ getProperties :
        Return a list of the properties that are available for a particular type of object.
        Sample usage:
        >>> nto.getProperties({'object_type' : 'monitor'})
        {u'properties': [u'actions', u'created', u'description', u'history', u'id', u'mod_count', u'name', u'trigger']}
        """
        return self._sendRequest('POST', '/api/actions/get_props', args)

    def getPropertyValues(self, args):
        """ getPropertyValues :
        Return a list of the properties that are available for a particular type of object.
        Sample usage:
        >>> nto.getPropertyValues({'object_type': 'port', 'prop_name': 'force_link_up'})
        {u'value': [u'DISABLED', u'ENABLED', u'MIXED', u'NOT_SUPPORTED']}
        """
        return self._sendRequest('POST', '/api/actions/get_values', args)

    def importConfig(self, args):
        """ importConfig :
        Copy configuration settings from a file to an NTO.
        Sample usage:
        >>> nto.importConfig({'boundary': 'INCLUDE', 'import_type': 'CUSTOM', 'file_name': '/Users/fmota/Desktop/snmp+user.ata', 'system' : 'snmp_config'})
        '{"message": "Configuration imported from /Users/fmota/Desktop/snmp+user.ata."}'
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']
            del args['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        buffer = bytearray()

        # Set param
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="param"\r\n')
        buffer.extend(b'Content-Type: application/json\r\n')
        buffer.extend(b'\r\n')
        buffer.extend(bytearray(json.dumps(args), 'ascii'))
        buffer.extend(b'\r\n')

        # Set creative contents part.
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="file"; filename=' + bytearray(file_name, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Type: application/octet-stream\r\n')
        buffer.extend(b'\r\n')
        # TODO: catch errors with opening file.
        buffer.extend(open(file_name, 'rb').read())
        buffer.extend(b'\r\n')

        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')
        buffer.extend(b'\r\n')

        hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
        response = self.connection.urlopen('POST', '/api/actions/import', body=buffer, headers=hdrs)
        #self._log (response.status, response.reason)
        data = response.data
        
        return data

    def installMakoOs(self, args):
        """ installMakoOs :
        This command installs a Mako OS software upgrade file on Marshall cards.
        Sample usage:
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']
            del args['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        buffer = bytearray()

        # Set creative contents part.
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="file"; filename=' + bytearray(file_name, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Type: application/octet-stream\r\n')
        buffer.extend(b'\r\n')
        # TODO: catch errors with opening file.
        buffer.extend(open(file_name, 'rb').read())
        buffer.extend(b'\r\n')

        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')
        buffer.extend(b'\r\n')

        hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
        response = self.connection.urlopen('POST', '/api/actions/install_mako', body=buffer, headers=hdrs)
        #self._log (response.status, response.reason)
        data = response.data
        
        return data

    def installLicense(self, args):
        """ installLicense :
        This command installs a license file on a NTO, a union, or a member.
        Sample usage:
        >>> nto.installLicense({'file_name': '/Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt'})
        '{"message": "License installed from /Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt."}'
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']
            del args['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        buffer = bytearray()

        # Set param
        if len(args.keys()) > 0:
            buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
            buffer.extend(b'Content-Disposition: form-data; name="param"\r\n')
            buffer.extend(b'Content-Type: application/json\r\n')
            buffer.extend(b'\r\n')
            #buffer.extend(json.dumps({'action_target' : target}))
            buffer.extend(json.dumps(args))
            buffer.extend(b'\r\n')

        # Set creative contents part.
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="file"; filename=' + bytearray(file_name, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Type: application/octet-stream\r\n')
        buffer.extend(b'\r\n')
        # TODO: catch errors with opening file.
        buffer.extend(open(file_name, 'rb').read())
        buffer.extend(b'\r\n')

        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')
        buffer.extend(b'\r\n')

        hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
        response = self.connection.urlopen('POST', '/api/actions/install_license', body=buffer, headers=hdrs)
        #self._log (response.status, response.reason)
        data = response.data

        return data

    def installNetservice(self, args):
        """ installNetservice :
        This command installs a netservice upgrade file on an NTO.
        This method is allowed only on the following models: 8000
        Sample usage:
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']
            del args['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        buffer = bytearray()

        # Set param
        if len(args.keys()) > 0:
            buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
            buffer.extend(b'Content-Disposition: form-data; name="param"\r\n')
            buffer.extend(b'Content-Type: application/json\r\n')
            buffer.extend(b'\r\n')
            #buffer.extend(json.dumps({'action_target' : target}))
            buffer.extend(json.dumps(args))
            buffer.extend(b'\r\n')

        # Set creative contents part.
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="file"; filename=' + bytearray(file_name, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Type: application/octet-stream\r\n')
        buffer.extend(b'\r\n')
        # TODO: catch errors with opening file.
        buffer.extend(open(file_name, 'rb').read())
        buffer.extend(b'\r\n')

        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')
        buffer.extend(b'\r\n')

        hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
        response = self.connection.urlopen('POST', '/api/actions/install_netservice', body=buffer, headers=hdrs)
        #self._log (response.status, response.reason)
        data = response.data

        return data

    def installLicense_old(self, args):
        """ installLicense :
        This command installs a license file on a NTO, a union, or a member.
        Sample usage:
        >>> nto.installLicense({'file_name': '/Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt'})
        '{"message": "License installed from /Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt."}'
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']
            del args['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        parts = []

        # Set param
        if len(args.keys()) > 0:
            parts.append('--' + boundary)
            parts.append('Content-Disposition: form-data; name="param"')
            parts.append('Content-Type: application/json')
            parts.append('')
            #parts.append(json.dumps({'action_target' : target}))
            parts.append(json.dumps(args))

        # Set creative contents part.
        parts.append('--' + boundary)
        parts.append('Content-Disposition: form-data; name="file"; filename=' + file_name)
        parts.append('Content-Type: application/octet-stream')
        parts.append('')
        # TODO: catch errors with opening file.
        parts.append(open(file_name, 'r').read())

        parts.append('--' + boundary + '--')
        parts.append('')

        content = '\r\n'.join(parts)

        hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
        response = self.connection.urlopen('POST', '/api/actions/install_license', body=content, headers=hdrs)
        #self._log (response.status, response.reason)
        data = response.data

        return data

    def installSoftware(self, args):
        """ installSoftware :
        This command installs a software upgrade file on an NTO. When installing
        software on a supervisor in a union, all members in the union will be
        upgraded to the same software level automatically.
        Sample usage:
        >>> nto.installSoftware({'file_name': '/Users/fmota/Desktop/NVOS-4.3.1.1-52xx-141844-20150722-174244.zip'})
        '{"message": "Software installation complete. The system will be restarted. Visit the 5288 launch page in your browser to obtain the updated client software."}'
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        buffer = bytearray()

        # Set creative contents part.
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="file"; filename=' + bytearray(file_name, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Type: application/octet-stream\r\n')
        buffer.extend(b'\r\n')
        # TODO: catch errors with opening file.
        buffer.extend(open(file_name, 'rb').read())
        buffer.extend(b'\r\n')

        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')
        buffer.extend(b'\r\n')

        hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
        response = self.connection.urlopen('POST', '/api/actions/install_software', body=buffer, headers=hdrs)
        #self._log (response.status, response.reason)
        data = response.data

        return data

    def mtuQuery(self, args={}):
        """ mtuQuery :
        This commands returns the port, linecard and AFM MTUs based on the board type.
        Sample usage:
        >>> nto.mtuQuery({'port_id': 59})
        {u'port_mtu': 12284, u'port_id': 59, u'fabric_mtu': 12268, u'afmr_mtu': 0}
        >>> nto.mtuQuery({'filter_id': 96})
        {u'port_mtu': 0, u'fabric_mtu': 0, u'afmr_mtu': 0, u'filter_id': 96}
        """
        return self._sendRequest('POST', '/api/actions/mtu_query', args)

    def markEodReportAsGolden(self, args={}):
        """ markEodReportAsGolden :
        Marks a completed End-Of-Day Report as a Golden Report.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/mark_ae_eod_report_golden', args)

    def powerDown(self, args={}):
        """ powerDown :
        This command safely shuts down an NTO, a union or a member.
        Sample usage:
        >>> nto.powerDown()
        {u'message': u'System shutdown requested.'}
        """
        return self._sendRequest('POST', '/api/actions/power_down', args)

    def pullConfigFromHaPeer(self):
        """ pullConfigFromHaPeer :
        Pulls the configuration from the HA peer machine.
        Sample usage:
        *** TO BE TESTED ***
        >>> nto.pullConfigFromHaPeer()
        """
        args={}
        return self._sendRequest('POST', '/api/actions/pull_config_from_ha_peer', args)

    def pushConfigToHaPeer(self):
        """ pushConfigToHaPeer :
        Pushes the local configuration to the HA peer machine.
        Sample usage:
        *** TO BE TESTED ***
        >>> nto.pushConfigToHaPeer()
        """
        args={}
        return self._sendRequest('POST', '/api/actions/push_config_to_ha_peer', args)

    def removeLicense(self):
        """ removeLicense :
        This command will remove the license and power down the NTO.
        Sample usage:
        >>> nto.removeLicense()
        """
        args={}
        return self._sendRequest('POST', '/api/actions/remove_license', args)

    def removePlugin(self, args):
        """ removePlugin :
        This command will remove (uninstall) a plugin based on the given plugin type.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/remove_plugin', args, False)

    def removeNetservice(self, args):
        """ removeNetservice :
        This command will remove (uninstall) a netservice based on the given service id.
        This method is allowed only on the following models: 8000.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/remove_netservice', args, False)

    def removePortModuleConfiguration(self, args):
        """ removePortModuleConfiguration :
        This command will remove the port module configuration based on the given module location.
        This method is allowed only on the following models: 8000.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/remove_port_module_config', args, False)

    def removeLineCard(self, args):
        """ removeLineCard :
        This command will remove the line card based on the given line card id.
        Sample usage:
        >>> nto.removeLineCard({'line_card_id': 1})
        {u'message': u'System restart requested.'}
        """
        return self._sendRequest('POST', '/api/actions/remove_line_card', args)

    def resetFactoryDefaultsVAM(self, args={}):
        """ resetFactoryDefaultsVAM :
        This command resets to factory defaults the expansion board.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/reset_factory_defaults_vam', args)

    def restart(self, args={}):
        """ restart :
        This command safely restarts an NTO, a union, or a member.
        Sample usage:
        >>> nto.restart()
        {u'message': u'System restart requested.'}
        """
        return self._sendRequest('POST', '/api/actions/restart', args)

    def restoreFirewall(self):
        """ restoreFirewall :
        This command will restore the default firewall rules to allow all servers to access NTO.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/restore_firewall', None)

    def revertSoftware(self):
        """ revertSoftware :
        This command revert software to it's previous version.
        Sample usage:
        >>> nto.revertSoftware()
        {u'message': u'Software revert requested. The system will be restarted. Visit the 7300 launch page in your browser to obtain the reverted client software.'}
        """
        return self._sendRequest('POST', '/api/actions/revert_software', None)

    def saveLogs(self, args):
        """ saveLogs :
        Save the current system log files for subsequent delivery to Anue Support.
        Sample usage:
        >>> nto.saveLogs({'file_name': '/Users/fmota/Desktop/NTO-log.zip'})
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest('POST', '/api/actions/save_logs', args, False)
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def setHaSyncPort(self):
        """ setHaSyncPort :
        Set the HA sync port.
        Sample usage:
        *** TO BE TESTED ***
        >>> nto.setHaSyncPort()
        """
        args={}
        return self._sendRequest('POST', '/api/actions/set_ha_sync_port', args)

    def sendSyntheticPackets(self, args):
        """ sendSyntheticPackets :
        Send synthetic packet to the destination addresses configured under TradeStream->Synthetic
        Mesh Latency Settings. If no destination addresses are specified, then user will not be
        allowed to send synthetic packets.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/send_synthetic_packets', args)

    def setIpConfig(self, args):
        """ setIpConfig :
        Changes the IP configuration of a system.
        Sample usage:
        >>> nto.setIPConfig({'ipv4_address': '192.168.2.149', 'ipv4_enabled': True, 'ipv4_gateway': '192.168.2.2', 'ipv4_netmask': '255.255.255.0', 'ipv6_address': 'fe80::5daa:83ed:42f8:6c08%11', 'ipv6_enabled': False, 'ipv6_prefix_length': 64})
        {u'message': u'The new IP configuration has been submitted.'}
        """
        return self._sendRequest('POST', '/api/actions/set_ip_config', args)

    def setStackMode(self, args):
        """ setStackMode :
        Set the Stack mode of a switch.
        This action will set the Stack mode for a switch. Warning: The switch will be restarted.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/set_stack_mode', args, False)

    def swapPortLicenses(self, args):
        """ swapPortLicenses :
        Swaps port licenses.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/swap_port_licenses', args, False)

    def updateSingleIpAddress(self, args):
        """ updateSingleIpAddress :
        This action allows a single IP address to be added to or removed from a filter
        with an existing IP address criterion.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/update_single_ip_addr', args, False)

    def validateAuthCalls(self):
        """ validateAuthCalls :
        This command checks auth for rest calls.
        Sample usage:
        """
        args = {}
        return self._sendRequest('POST', '/api/actions/validate_auth', args)

    def modifyFabricPorts(self, args):
        """ modifyFabricPorts :
        Changes the fabric ports configuration for the specified member switch.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/update_fabric_ports', args)

    def resumeItrTraffic(self, args):
        """ resumeItrTraffic :
        This command will resume traffic on ITR based on ITR id.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/resume_itr_traffic', args, False)

    def backupGscConfig(self):
        """ backupGscConfig :
        Backup GSC configuration.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/backup_gsc_config', {})

    def restoreGscConfig(self):
        """ backupGscConfig :
        Restore GSC configuration.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/restore_gsc_config', {})

    ###################################################
    # Capture Resources
    ###################################################
    def getAllCaptures(self):
        """ getAllCaptures :
        Fetch a list containing the summaries for all the captures in the system.
        Sample usage:
        >>> nto.getAllCaptures()
        [{u'id': 546, u'name': u'L4-CAP'}]
        """
        return self._sendRequest('GET', '/api/capture_resources')
    
    def getCapture(self, resource):
        """ getCapture :
        Fetch the properties of a capture object.
        Sample usage:
        >>> nto.getCapture('177')
        {u'trailer_stripping_mode': u'USE_LOCAL_TIME', u'capture_count_unit': u'PACKETS', u'id': 177, u'has_dropped_packets': False, u'max_buffer_capacity': 14680063, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'connect_disconnect_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'status': u'IDLE_WITH_DATA', u'fill_to_trigger_position': False, u'description': None, u'trigger_position': 25, u'resource_status': u'READY', u'license_status': u'NOT_PRESENT', u'trailer_stripping_enabled': False, u'buffer_size': 200, u'trigger_criteria': {u'logical_operation': u'AND'}, u'name': u'L1-CAP', u'buffer_type': u'LINEAR', u'capture_source': 307, u'lineboard_id': 175, u'default_name': u'L1-CAP', u'trigger_mode': u'MANUAL', u'mod_count': 3, u'history': [{u'type': u'MODIFY', u'time': 1442009546427, u'caused_by': u'admin', u'details': None, u'props': [u'CAPTURE_SOURCE', u'BUFFER_SIZE']}]}
        """
        return self._sendRequest('GET', '/api/capture_resources/' + resource)

    def deleteCaptureFile(self, resource, args):
        """ deleteCaptureFile :
        Deletes a capture file from a capture resource.
        Sample usage:
        >>> nto.deleteFileCapture('546', {'file_name': 'File 1.pcap'})
        ''
        """
        return self._sendRequest('DELETE', '/api/capture_resources/' + resource + '/delete_file ', args, False)

    def disableCapture(self, resource):
        """ disableCapture :
        Disables a capture resource by disconnecting the attached filter.
        Sample usage:
        >>> nto.disableCapture('L1-CAP')
        ''
        """
        args = {}
        return self._sendRequest('PUT', '/api/capture_resources/' + resource + '/disable', args, False)

    def downloadCaptureFile(self, resource, args, local_file_name=None):
        """ downloadCaptureFile :
        Downloads a capture file of capture resource.
        Sample usage:
        >>> nto.downloadFileCapture('L1-CAP', {'file_name': 'Suspicious Netflow export.pcap'})
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest('POST', '/api/capture_resources/' + resource + '/download_file', args, False)
        if local_file_name is None:
            local_file_name = file_name
        f = open(local_file_name, 'wb')
        f.write(file)
        f.close()

    def enableCapture(self, resource, args):
        """ enableCapture :
        Enables a capture by attaching a filter to it.
        Sample usage:
        >>> nto.enableCapture('546', {'filter_id': '524'})
        ''
        """
        return self._sendRequest('PUT', '/api/capture_resources/' + resource + '/enable', args, False)

    def ftpTransferCapture(self, resource, args):
        """ ftpTransferCapture :
        Transfers via FTP a capture file or the buffer of a capture resource.
        Sample usage:
        >>> nto.ftpTransferCapture('317', {'address': '10.218.6.43', 'file_name': '150604_085131.pcap', 'password': '****', 'range_type': 'ALL_PACKETS', 'remote_file_name': 'fred-api.pcap', 'user': 'fredmota', 'port': 21})
        '{\n        "id": 2,\n        "progress": 0,\n        "state": "PENDING"\n}'
        """
        return self._sendRequest('POST', '/api/capture_resources/' + resource + '/ftp_file', args, False)

    def getTriggerPacketCapture(self, resource):
        """ getTriggerPacketCapture :
        Gets the number of the packet that triggered the capture.
        Sample usage:
        >>> nto1.getTriggerPacketCapture('546')
        {u'triggerPacketNumber': 1025}
        """
        return self._sendRequest('GET', '/api/capture_resources/' + resource + '/trigger_packet')

    def listCaptureFiles(self, resource):
        """ listCaptureFiles :
        Fetch a list containing the summaries for all the captures in the system.
        Sample usage:
        >>> nto.listFilesCapture('546')
        [{u'access_settings': {u'policy': u'REQUIRE_MEMBER', u'groups': [u'group1', u'group2']}, u'description': u'Capture file description', u'capture_date': 1440119146145, u'name': u'File 2.pcap', u'packet_count': 32, u'duration': 12, u'size': 262144, u'access_policy_id': u'7300-demodemo'}]
        """
        args = {}
        return self._sendRequest('GET', '/api/capture_resources/' + resource + '/files', args)

    def resetCaptureBuffer(self, resource):
        """ resetCaptureBuffer :
        Resets / clears the capture resource buffer.
        Sample usage:
        """
        args = {}
        return self._sendRequest('PUT', '/api/capture_resources/' + resource + '/reset_buffer', args, False)

    def scpTransferCapture(self, resource, args):
        """ scpTransferCapture :
        Transfers via SCP a capture file or the buffer of a capture resource.
        Sample usage:
        >>> nto.scpTransferCapture('317', {'address': '10.218.30.1', 'file_name': '150604_085131.pcap', 'password': 'Anue', 'port': 22, 'range_type': 'ALL_PACKETS', 'remote_file_name': 'fred-api.pcap', 'user': 'support'})
        '{\n        "id": 3,\n        "progress": 0,\n        "state": "PENDING"\n}'
        """
        return self._sendRequest('POST', '/api/capture_resources/' + resource + '/scp_file', args, False)

    def saveBufferCapture(self, resource, args):
        """ saveBufferCapture :
        Saves the buffer of a capture resource to a new capture file.
        Sample usage:
        >>> nto.saveBufferCapture('L1-CAP', {'file_name': 'wep_api_test.pcap', 'description': 'Web API Saved File', 'range' : '1-10', 'range_type': 'RANGE'})
        {u'progress': 0, u'state': u'PENDING', u'id': 1}
        """
        return self._sendRequest('POST', '/api/capture_resources/' + resource + '/save_buffer', args)

    def searchCapture(self, args):
        """ searchCapture :
        Search for a specific capture in the system by certain properties.
        Sample usage:
        >>> nto.searchCapture({'status': 'IDLE_WITH_DATA'})
        [{u'id': 177, u'name': u'L1-CAP'}]
        """
        return self._sendRequest('POST', '/api/capture_resources/search', args)

    def startCapture(self, resource):
        """ startCapture :
        Starts a capture resource to capture packets via the attached filter.
        Sample usage:
        >>> nto.startCapture('L1-CAP')
        ''
        """
        args = {}
        return self._sendRequest('PUT', '/api/capture_resources/' + resource + '/start', args, False)

    def stopCapture(self, resource):
        """ stopCapture :
        Stops a capture resource to capture packets via the attached filter.
        Sample usage:
        >>> nto.stopCapture('L1-CAP')
        ''
        """
        args = {}
        return self._sendRequest('PUT', '/api/capture_resources/' + resource + '/stop', args, False)

    def modifyCapture(self, resource, args):
        """ modifyCapture :
        Update the properties of an existing capture resource.
        Sample usage:
        >>> nto.modifyCapture('L1-CAP', {'buffer_size': 100})
        ''
        """
        return self._sendRequest('PUT', '/api/capture_resources/' + resource, args, False)

    ###################################################
    # Aggregator Resources
    ###################################################
    def getAllAggregators(self):
        """ getAllAggregators :
        Fetch a list containing the summaries for all the Aggregator resources in the system.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/aggregator_resources')

    def getAggregator(self, resource):
        """ getAggregator :
        Fetch the properties of an Aggregator resource object.
        To request only select properties (partial response), append to the URL the query
        parameter '?properties=value', where value is comma-separated list to select
        multiple fields for ex- /api/resource_type/{object-id}?properties=description,name.
        Query Parameter is optional.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/aggregator_resources/' + resource)

    def disableAggregator(self, resource, args):
        """ disableAggregator :
        Disables an Aggregator resource by disconnecting the attached port group.
        Sample usage:
        ''
        """
        return self._sendRequest('PUT', '/api/aggregator_resources/' + resource + '/disable', args, False)

    def enableAggregator(self, resource, args):
        """ enableAggregator :
        Enables an Aggregator resource by attaching a port group to it.
        Sample usage:
        ''
        """
        return self._sendRequest('PUT', '/api/aggregator_resources/' + resource + '/enable', args, False)

    def searchAggregator(self, args):
        """ searchAggregator :
        Search for a specific Aggregator resource in the system by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/aggregator_resources/search', args)

    def modifyAggregator(self, resource, args):
        """ modifyAggregator:
        Update the properties of an existing Aggregator resource.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/aggregator_resources/' + resource, args, False)

    ###################################################
    # ATIP Resources
    ###################################################
    def getAllAtips(self):
        """ getAllAtips :
        Fetch a list containing the summaries for all the ATIP resources in the system.
        Sample usage:
        >>> nto.getAllAtips()
        [{u'id': 179, u'name': u'L2-ATIP'}]
        """
        return self._sendRequest('GET', '/api/atip_resources')

    def getAtip(self, resource):
        """ getAtip :
        Fetch the properties of an ATIP resource.
        Sample usage:
        >>> nto.getAtip('L2-ATIP')
        {u'fill_to_trigger_position': False, u'description': None, u'capture_source': 304, u'lineboard_id': 173, u'default_name': u'L2-ATIP', u'resource_status': u'READY', u'name': u'L2-ATIP', u'mod_count': 5, u'license_status': u'VALID', u'modify_access_settings': {u'policy': u'REQUIRE_ADMIN', u'groups': []}, u'id': 179, u'connect_disconnect_access_settings': {u'policy': u'REQUIRE_ADMIN', u'groups': []}, u'history': [{u'type': u'MODIFY', u'time': 1442009546622, u'caused_by': u'admin', u'details': None, u'props': [u'NETFLOW_ENABLED']}]}
        """
        return self._sendRequest('GET', '/api/atip_resources/' + resource)

    def disableAtip(self, resource):
        """ disableAtip :
        Disables an ATIP by disconnecting the attached filter.
        Sample usage:
        >>> nto.disableAtip('319')
        ''
        """
        args = {}
        return self._sendRequest('PUT', '/api/atip_resources/' + resource + '/disable', args, False)

    def enableAtip(self, resource, args):
        """ enableAtip :
        Enables a capture by attaching a filter to it.
        Sample usage:
        >>> nto.enableAtip('319', {'filter_id': 'F1'})
        ''
        """
        return self._sendRequest('PUT', '/api/atip_resources/' + resource + '/enable', args, False)

    def searchAtip(self, args):
        """ searchAtip :
        Search for a specific ATIP resource in the system by certain properties.
        Sample usage:
        >>> nto.searchAtip({'resource_status': 'READY'})
        [{u'id': 179, u'name': u'L2-ATIP'}]
        """
        return self._sendRequest('POST', '/api/atip_resources/search', args)

    def modifyAtip(self, resource, args):
        """ modifyAtip:
        Update the properties of an existing ATIP resource.
        Sample usage:
        >>> nto.modifyAtip('L2-ATIP', {'description': 'ATIP at slot #2'})
        ''
        """
        return self._sendRequest('PUT', '/api/atip_resources/' + resource, args, False)

    ###################################################
    # Authentication
    ###################################################
    def logout(self):
        """ logout :
        This call is used to invalidate any token returned from other calls to the web API.
        Sample usage:
        >>> nto.logout()
        'User -admin- has logged out.'
        """
        try:
            # New API
            data = self._sendRequest('POST', '/api/auth/logout', {}, False)
        except:
            # Old API
            data = self._sendRequest('GET', '/api/auth/logout', {}, False)
        return data

    ###################################################
    # Bypass Connectors
    ###################################################
    def createInlineBypassConnector(self, args):
        """ createInlineBypassConnector :
        Create a new Inline Bypass Connector in the system.
        Sample usage:
        >>> nto.createInlineBypassConnector({"criteria": {"logical_operation": "AND"}, "filter_mode": "PASS_ALL", "name": "test bypass", "side_a_ports": [12], "side_b_ports": [13], "description": ""})
        {'default_name': 'BPP1', 'id': 117, 'name': 'test bypass'}
        """
        return self._sendRequest('POST', '/api/bypass_connectors', args)

    def deleteInlineBypassConnector(self, bypass_id):
        """ deleteInlineBypassConnector :
        Remove an existing inline Tool Bypass from the system.
        Sample usage:
        >>> nto.deleteInlineBypassConnector('117')
        b''
        """
        return self._sendRequest('DELETE', '/api/bypass_connectors/' + bypass_id, None, False)

    def getInlineBypassConnector(self, bypass_id):
        """ getInlineBypassConnector :
        Fetch the properties of an Inline Bypass Connector.
        Sample usage:
        >>> nto.getInlineBypassConnector('test bypass')
        {'connect_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'created': {'caused_by': 'admin', 'details': None, 'time': 1605730853970, 'type': 'CREATE'}, 'criteria': {'logical_operation': 'AND'}, 'default_name': 'BPP1', 'description': '', 'filter_mode': 'PASS_ALL', 'history': None, 'id': 117, 'inline_service_chain_list': [], 'inline_service_chain_priority_list': [], 'lfd_enabled': False, 'local_lfd_ports': [], 'misc': {'access_map': {'CONNECT_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Connect Service Chains', 'operation_phrase': 'connect service chains to', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}, 'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS', 'CONNECT_ACCESS_SETTINGS']}, 'mod_count': 1, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'test bypass', 'peer_lfd_ports': [], 'side_a_port_group': 115, 'side_a_ports': [12], 'side_b_port_group': 116, 'side_b_ports': [13], 'vlan': 2001, 'vlan_translation_setting': {'translation_map': []}}
        """
        return self._sendRequest('GET', '/api/bypass_connectors/' + bypass_id)

    def getAllInlineBypasseConnectors(self):
        """ getAllInlineBypasseConnectors :
        Fetch a list containing the summaries for all the Inline Bypass Connectors in the system.
        Sample usage:
        >>> nto.getAllInlineBypasseConnectors()
        [{'id': 117, 'name': 'test bypass'}]
        """
        return self._sendRequest('GET', '/api/bypass_connectors')

    def searchInlineBypassConnectors(self, args):
        """ searchInlineBypassConnectors :
        Search for a specific Inline Bypass Connector in the system by certain properties.
        Sample usage:
        >>> nto.searchInlineBypassConnectors({"filter_mode": "PASS_ALL"})
        [{'connect_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'created': {'caused_by': 'admin', 'details': None, 'time': 1605730853970, 'type': 'CREATE'}, 'criteria': {'logical_operation': 'AND'}, 'default_name': 'BPP1', 'description': '', 'filter_mode': 'PASS_ALL', 'history': None, 'id': 117, 'inline_service_chain_list': [], 'inline_service_chain_priority_list': [], 'lfd_enabled': False, 'local_lfd_ports': [], 'misc': {'access_map': {'CONNECT_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Connect Service Chains', 'operation_phrase': 'connect service chains to', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}, 'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS', 'CONNECT_ACCESS_SETTINGS']}, 'mod_count': 1, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'test bypass', 'peer_lfd_ports': [], 'side_a_port_group': 115, 'side_a_ports': [12], 'side_b_port_group': 116, 'side_b_ports': [13], 'vlan': 2001, 'vlan_translation_setting': {'translation_map': []}}]
        """
        return self._sendRequest('POST', '/api/bypass_connectors/search', args)

    def modifyInlineBypassConnector(self, bypass_id, args):
        """ modifyInlineBypassConnector:
        Update the properties of an existing Inline Bypass Connector.
        Sample usage:
        >>> nto.modifyInlineBypassConnector('117', {"side_b_ports": [14]})
        b''
        """
        return self._sendRequest('PUT', '/api/bypass_connectors/' + bypass_id, args, False)

    ####################################
    # IFC Clustering (Control Tower Evolution)
    ####################################

    # IFC Analysis Engine Resources

    def disableAnalysisEngine(self, ae_id):
        """ disableAnalysisEngine :
        Detaches an IFC Analysis Engine resource from a filter.
        Sample usage:
        """
        args = {}
        return self._sendRequest('PUT', '/api/cte_ae_resources/' + ae_id + '/disable', args, False)

    def enableAnalysisEngine(self, ae_id, args):
        """ enableAnalysisEngine :
        Attaches an IFC Analysis Engine resource to a filter.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_ae_resources/' + ae_id + '/enable', args)

    def getAnalysisEngine(self, ae_id):
        """ getAnalysisEngine :
        Fetch the properties of an IFC Analysis Engine resource.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_ae_resources/' + ae_id)

    def getAllAnalysisEngines(self, args):
        """ getAllAnalysisEngines :
        Fetch a list containing the summaries for all IFC Analysis Engine resources.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_ae_resources')

    def searchAnalysisEngine(self, args):
        """ searchAnalysisEngine :
        Search a specific IFC Analysis Engine resource by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_ae_resources', args)

    def modifyAnalysisEngine(self, ae_id, args):
        """ modifyAnalysisEngine :
        Update the properties of an existing IFC Analysis Engine Resource.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_ae_resources/' + ae_id, args, False)


    # IFC Capture Resources

    def getAllCteCaptures(self):
        """ getAllCteCaptures :
        Fetch a list containing the summaries for all the captures in the system.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_capture_resources')

    def getCteCapture(self, resource):
        """ getCteCapture :
        Fetch the properties of a capture object.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_capture_resources/' + resource)

    def deleteCteCaptureFile(self, resource, args):
        """ deleteCteCaptureFile :
        Deletes a capture file from a capture resource.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_capture_resources/' + resource + '/delete_file ', args, False)

    def disableCteCapture(self, resource):
        """ disableCteCapture :
        Detaches an IFC Capture resource from a filter.
        Sample usage:
        """
        args = {}
        return self._sendRequest('PUT', '/api/cte_capture_resources/' + resource + '/disable', args, False)

    def downloadCteCaptureFile(self, resource, args, local_file_name=None):
        """ downloadCteCaptureFile :
        Downloads a capture file of capture resource.
        Sample usage:
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest('POST', '/api/cte_capture_resources/' + resource + '/download_file', args, False)
        if local_file_name is None:
            local_file_name = file_name
        f = open(local_file_name, 'wb')
        f.write(file)
        f.close()

    def enableCteCapture(self, resource, args):
        """ enableCteCapture :
        Attaches an IFC Capture resource to a filter.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_capture_resources/' + resource + '/enable', args, False)

    def listCteCaptureFiles(self, resource):
        """ listCteCaptureFiles :
        Fetch a list containing the summaries for all the captures in the system.
        Sample usage:
        """
        args = {}
        return self._sendRequest('GET', '/api/cte_capture_resources/' + resource + '/files', args)

    def resetCteCaptureBuffer(self, resource):
        """ resetCteCaptureBuffer :
        Resets / clears the capture resource buffer.
        Sample usage:
        """
        args = {}
        return self._sendRequest('PUT', '/api/cte_capture_resources/' + resource + '/reset_buffer', args, False)

    def saveCteBufferCapture(self, resource, args):
        """ saveCteBufferCapture :
        Search for a specific capture in the system by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_capture_resources/' + resource + '/save_buffer', args)

    def searchCteCapture(self, args):
        """ searchCteCapture :
        Search for a specific capture in the system by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_capture_resources/search', args)

    def startCteCapture(self, resource):
        """ startCteCapture :
        Starts a capture resource to capture packets via the attached filter.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_capture_resources/' + resource + '/start', {}, False)

    def stopCteCapture(self, resource):
        """ stopCteCapture :
        Stops a capture resource to capture packets via the attached filter.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_capture_resources/' + resource + '/stop', {}, False)

    def modifyCteCapture(self, resource, args):
        """ modifyCteCapture :
        Update the properties of an existing capture resource.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_capture_resources/' + resource, args, False)


    # CTE Cluster

    def getCteCluster(self, args):
        """ getCteCluster :
        Retrieve the properties of the CTE cluster.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_cluster', args)


    # CTE Connections

    def createCteConnection(self, args):
        """ createCteConnection :
        Create a new CTE connection in the system.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_connections', args)

    def deleteCteConnection(self, cte_id):
        """ deleteCteConnection :
        Remove a CTE connection.
        Sample usage:
        """
        return self._sendRequest('DELETE', '/api/cte_connections/' + cte_id, None, False)

    def getCteConnection(self, cte_id):
        """ getCteConnection :
        Fetch the properties of a CTE connection.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_connections/' + cte_id)

    def getAllCteConnections(self):
        """ getAllCteConnections :
        Fetch a list containing the summaries for all the CTE connections.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_connections')

    def searchCteConnection(self, args):
        """ searchCteConnection :
        Search a specific CTE connection by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_connections/search', args)

    def modifyCteConnection(self, cte_id, args):
        """ modifyCteConnection :
        Update the properties of an existing CTE connection.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_connections/' + cte_id, args, False)


    # CTE Filters

    def createCteFilter(self, args):
        """ createCteFilter :
        Create a new CTE filter in the system.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_filters', args)

    def deleteCteFilter(self, cte_filter_id):
        """ deleteCteFilter :
        Remove a CTE filter.
        Sample usage:
        """
        return self._sendRequest('DELETE', '/api/cte_filters/' + cte_filter_id, None, False)

    def getCteFilter(self, cte_filter_id):
        """ getCteFilter :
        Fetch the properties of a CTE filter.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_filters/' + cte_filter_id)

    def getAllCteFilters(self):
        """ getAllCteFilters :
        Fetch a list containing the summaries for all the CTE filters.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_filters')

    def searchCteFilter(self, args):
        """ searchCteFilter :
        Search a specific CTE filter by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_filters/search', args)

    def modifyCteFilter(self, cte_filter_id, args):
        """ modifyCteFilter :
        Update the properties of an existing CTE connection.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_filters/' + cte_filter_id, args, False)


    # CTE Members

    def getCteMember(self, cte_member_id):
        """ getCteMember :
        Fetch the properties of a CTE member.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_members/' + cte_member_id)

    def getAllCteMembers(self):
        """ getAllCteMembers :
        Fetch a list containing the summaries for all the CTE members.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_members')

    def searchCteMember(self, args):
        """ searchCteMember :
        Search a specific CTE member by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_members/search', args)

    def modifyCteMember(self, cte_member_id, args):
        """ modifyCteMember :
        Update the properties of an existing IFC Member.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_members/' + cte_member_id, args, False)


    # CTE Monitors

    def createCteMonitor(self, args):
        """ createCteMonitor :
        The IFC monitors resource.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_monitors', args)

    def deleteCteMonitor(self, cte_monitor_id):
        """ deleteCteMonitor :
        Remove an IFC monitor.
        Sample usage:
        """
        return self._sendRequest('DELETE', '/api/cte_monitors/' + cte_monitor_id, None, False)

    def getCteMonitor(self, cte_monitor_id):
        """ getCteMonitor :
        Fetch the properties of an IFC monitor.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_monitors/' + cte_monitor_id)

    def getAllCteMonitors(self):
        """ getAllCteMonitors :
        Fetch a list containing the summaries for all IFC monitors.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_monitors')

    def searchCteMonitor(self, args):
        """ searchCteMonitor :
        Search a specific IFC monitor by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_monitors/search', args)

    def modifyCteMonitor(self, cte_monitor_id, args):
        """ modifyCteMonitor :
        Update the properties of an existing IFC monitor.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_monitors/' + cte_monitor_id, args, False)


    # CTE Netflow Resources

    def disableCteNetflowResource(self, cte_netflow_resource_id, args):
        """ disableCteNetflowResource :
        Detaches an IFC Netflow resource from an IFC filter.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_netflow_resources/' + cte_netflow_resource_id + '/disable', args, False)

    def enableCteNetflowResource(self, cte_netflow_resource_id, args):
        """ enableCteNetflowResource :
        Attaches an IFC Netflow to an IFC filter.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_netflow_resources/' + cte_netflow_resource_id + '/enable', args, False)

    def getCteNetflowResourceBandwidth(self, cte_netflow_resource_id):
        """ getCteNetflowResourceBandwidth :
        Gets the bandwidth details for the IFC Netflow resource.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_netflow_resources/' + cte_netflow_resource_id + '/get_bandwidth_details')

    def getCteNetflowResource(self, cte_netflow_resource_id):
        """ getCteNetflowResource :
        Fetch the properties of an IFC Netflow resource.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_netflow_resources/' + cte_netflow_resource_id)

    def getAllCteNetflowResources(self):
        """ getAllCteNetflowResources :
        Fetch a list containing the summaries for all IFC Netflow resources.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_netflow_resources')

    def searchCteNetflowResource(self, args):
        """ searchCteNetflowResource :
        Search a specific IFC Netflow resource by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_netflow_resources/search', args)

    def modifyCteNetflowResource(self, cte_netflow_resource_id, args):
        """ modifyCteNetflowResource :
        Update the properties of an existing IFC Netflow resource.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_netflow_resources/' + cte_netflow_resource_id, args, False)


    # CTE Operations

    def changeClusterRole(self, args):
        """ changeClusterRole :
        This action will change the role of a node in the cluster. If the node is
        CONTROLLER, then it will become FABRIC. IF the node is FABRIC, then it will
        become CONTROLLER.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/change_role', args)

    def clearCteAeChannelStatsHistory(self, args):
        """ clearCteAeChannelStatsHistory :
        Clears the Burst and/or Latency & Jitter Stats History Files from the Disk per AE.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/cte_clear_ae_channel_statistics_history', args)

    def clearCteConfig(self):
        """ clearCteConfig :
        Create a CTE topology.
        Sample usage:
        """
        args = {}
        return self._sendRequest('POST', '/api/cte_operations/cte_clear_config', args, False)

    def clearCteFiltersAndPort(self):
        """ clearCteFiltersAndPort :
        This command deletes all filters and port groups and sets all ports to default values..
        Sample usage:
        """
        args = {}
        return self._sendRequest('POST', '/api/cte_operations/cte_clear_filters_and_ports', args, False)

    def createCteTopology(self, args):
        """ createCteTopology :
        Create a CTE topology.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/create_topology', args)

    def disbandCteTopology(self, args):
        """ disbandCteTopology :
        Disband the CTE topology. The local device and all other members
        that can be notified will be forced out of the topology. Manual
        disband on unreachable devices is required to recover them.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/disband_topology', args)

    def discoverCteConnections(self):
        """ discoverCteConnections :
        Discover and create direct connections between members in IFC topology.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/discover_connections')

    def exportCteTopology(self, args):
        """ exportCteTopology :
        Export topology configuration to a file.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/export', args)

    def forceRemoveFromCteTopology(self, args):
        """ forceRemoveFromCteTopology :
        Given a failed member of a CTE topology by its IPv4 address, force
        remove it from the topology.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/force_remove', args)

    def getCteAvailableFilterCriteria(self, args={}):
        """ getCteAvailableFilterCriteria :
        Return a list of filter criteria which can be used given an already present set of filter criteria.
        This action is useful for a user interface which defines a filter.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/cte_get_available_filter_criteria', args)

    def getCteNeighbors(self, args={}):
        """ getCteNeighbors :
        Get discovered LLDP neighbors from cluster for specified list of members and specified lisf of ports.
        If both lists of members and ports given are empty or not given at all, then will return all discovered
        LLDP neighbors for all ports from members of cluster, that are valid for LLDP and have valid neighbors
        records. If only a list of members is specified, then will return all discovered LLDP neighbors for all
        ports from these members. If only a list of ports is specified, then will return all discovered LLDP
        neighbors for specified ports.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/cte_get_neighbors', args)

    def getPortTunnelingInfo(self):
        """ getPortTunnelingInfo :
        Get the tunnel termination and origination settings.
        Sample usage:
        """
        args = {}
        return self._sendRequest('POST', '/api/cte_operations/cte_get_port_tunneling_info', args)

    def importCteTopology(self, args):
        """ importCteTopology :
        Import topology configuration from a file.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/import', args)

    def installCteDtsp(self, args):
        """ installCteDtsp :
        Install TradeVision DTSP to all the TradeVision boxes in the IFC.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/cte_install_dtsp', args)

    def interruptCteAnalysisEngineTraffic(self, args):
        """ interruptCteAnalysisEngineTraffic :
        Interrupt traffic for a given analysis engine (AE).
        This will temporarily (10 sec) turn off traffic to AE.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/cte_interrupt_ae_traffic', args)

    def joinCteTopology(self, args):
        """ joinCteTopology :
        Join the current stack to a CTE topology.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/join_topology', args)

    def leaveCteTopology(self, args):
        """ leaveCteTopology :
        Given a member of a CTE topology by its IPv4 address, this action will
        disconnect it from the topology.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/leave_topology', args)

    def optimizeCteRoutes(self, args):
        """ optimizeCteRoutes :
        This command will perform route reconfiguration to ensure maximum filter coverage and
        better traffic load balancing across the cluster.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/optimize_routes', args)

    def resetCteEventRateLimiterStatus(self, args):
        """ resetCteEventRateLimiterStatus :
        Reset the event rate limiter status for the given event type.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/cte_reset_event_rate_limiter_status', args)

    def updateCteUpdateSingleIpAddress(self, args):
        """ updateCteUpdateSingleIpAddress :
        This action allows a single IP address to be added to or removed
        from a filter with an existing IP address criterion.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_operations/cte_update_single_ip_addr', args)


    # CTE Port Groups

    def createCtePortGroup(self, args):
        """ createCtePortGroup :
        Create a new IFC port group in the system.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_port_groups', args)

    def deleteCtePortGroup(self, cte_port_group_id):
        """ deleteCtePortGroup :
        Remove an IFC port group.
        Sample usage:
        """
        return self._sendRequest('DELETE', '/api/cte_port_groups/' + cte_port_group_id + '/disable', {}, False)

    def disableCtePortGroup(self, cte_port_group_id):
        """ disableCtePortGroup :
        Disables an IFC port group by disabling all contained IFC ports.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_port_groups/' + cte_port_group_id, {}, False)

    def enableCtePortGroup(self, cte_port_group_id):
        """ enableCtePortGroup :
        Enables an IFC port group by enabling all contained IFC ports.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_port_groups/' + cte_port_group_id + '/enable', {}, False)

    def getCtePortGroup(self, cte_port_group_id):
        """ getCtePortGroup :
        Fetch the properties of a CTE port group.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_port_groups/' + cte_port_group_id)

    def getAllCtePortGroups(self):
        """ getAllCtePortGroups :
        Fetch a list containing the summaries for all the CTE port groups.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_port_groups')

    def searchCtePortGroup(self, args):
        """ searchCtePortGroup :
        Search a specific CTE port group by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_port_groups/search', args)

    def modifyCtePortGroup(self, cte_port_group_id, args):
        """ modifyCtePortGroup :
        Update the properties of an existing IFC port group.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_port_groups/' + cte_port_group_id, args, False)


    # CTE Ports

    def createCtePort(self, args):
        """ createCtePort :
        Create a new CTE port on the system. This can be used only to
        create virtual ports for GRE origination on a Vision 7300 system.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_ports', args)

    def deleteCtePort(self, cte_port_id):
        """ deleteCtePort :
        Remove a CTE port from the system. This can be used only to
        remove virtual ports for GRE origination on a Vision 7300 system.
        Sample usage:
        """
        return self._sendRequest('DELETE', '/api/cte_ports/' + cte_port_id, {}, False)

    def getCtePort(self, cte_port_id):
        """ getCtePort :
        Fetch the properties of a CTE port.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_ports/' + cte_port_id)

    def getAllCtePorts(self):
        """ getAllCtePorts :
        Fetch a list containing the summaries for all the CTE ports.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_ports')

    def searchCtePortGroup(self, args):
        """ searchCtePortGroup :
        Search a specific CTE port by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_ports/search', args)

    def modifyCtePort(self, cte_port_id, args):
        """ modifyCtePort :
        Update the properties of an existing IFC port.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_ports/' + cte_port_id, args, False)


    # CTE Routes

    def getAllIfcRoutes(self):
        """ getAllIfcRoutes :
        Fetch a list containing the summaries for all IFC routes.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_routes/')

    def getIfcRoute(self, ifc_route_id):
        """ getIfcRoute :
        Fetch the properties of an IFC route.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_routes/' + ifc_route_id)

    def searchIfcRoute(self, args):
        """ searchIfcRoute :
        Search a specific IFC route by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_routes/search', args)

    # CTE Remote Systems (deprecated)

    def getAllCtes(self):
        """ getAllCtes :
        Fetch a list containing the summaries for all the CTE remote
        systems available on this device.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_remote_system')

    def getCte(self, cte_id):
        """ getCte :
        Fetch the properties of a CTE remote system available on the local device.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/cte_remote_system/' + cte_id)

    def connectCte(self, args):
        """ connectCte :
        Make a new CTE remote system available on the local device.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_remote_system', args)

    def disconnectCte(self, cte_id):
        """ disconnectCte :
        Remove a CTE remote system from the local device.
        Sample usage:
        """
        args = {}
        return self._sendRequest('DELETE', '/api/cte_remote_system/' + cte_id , args, False)

    def searchCte(self, args):
        """ searchCte :
        Search by certain properties for a specific CTE remote systems available on this device.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/cte_remote_system/search', args)

    def modifyCte(self, cte_id, args):
        """ modifyCte :
        Update the connection details of a CTE remote system available on the local device.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/cte_remote_system/' + cte_id, args, False)


    ####################################
    # Custom Icons
    ####################################
    def getAllIcons(self):
        """ getAllIcons :
        Fetch a list containing summaries for all custom icons in the system.
        Sample usage:
        >>> nto.getAllIcons()
        [{u'id': 71, u'name': u'JuniperLogoLarge'}, {u'id': 70, u'name': u'Tektronix'}, {u'id': 69, u'name': u'JDSU'}, {u'id': 68, u'name': u'Cisco'}, {u'id': 75, u'name': u'A Big Bomb!'}]
        """
        return self._sendRequest('GET', '/api/custom_icons')

    def getIcon(self, icon):
        """ getIcon :
        Fetch the properties of a custom icon which is specified by its custom_icon_id_or_name.
        Samle usage:
        >>> nto.getIcon('75')
        {u'description': u'A bomb!', u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1440623340772}, u'name': u'A Big Bomb!', u'mod_count': 2, u'id': 75, u'history': [{u'type': u'MODIFY', u'time': 1440623518301, u'caused_by': u'admin', u'details': None, u'props': [u'NAME']}]}
        """
        return self._sendRequest('GET', '/api/custom_icons/' + icon)

    def createIcon(self, args):
        """ createIcon :
        Create a new custom icon.
        Sample usage:
        >>> nto.createIcon({'description': 'A bomb!', 'file_name': '/Users/fmota/Desktop/bomb.jpeg', 'name' : 'Bomb'})
        {u'id': u'75'}
        """
        description = ''
        if 'description' in args:
            description = args['description']

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        name = ''
        if 'name' in args:
            name = args['name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        buffer = bytearray()

        # Set name
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="name"\r\n')
        buffer.extend(b'Content-Type: text/plain\r\n')
        buffer.extend(b'\r\n')
        buffer.extend(bytearray(name, 'ascii'))
        buffer.extend(b'\r\n')

        # Set Description
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="description"\r\n')
        buffer.extend(b'Content-Type: text/plain\r\n')
        buffer.extend(b'\r\n')
        buffer.extend(bytearray(description, 'ascii'))
        buffer.extend(b'\r\n')

        # Set creative contents part.
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="file"; filename=' + bytearray(file_name, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Type: application/octet-stream\r\n')
        buffer.extend(b'\r\n')
        # TODO: catch errors with opening file.
        buffer.extend(open(file_name, 'rb').read())
        buffer.extend(b'\r\n')

        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')

        hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
        response = self.connection.urlopen('POST', '/api/custom_icons', body=buffer, headers=hdrs)
        #self._log (response.status, response.reason)
        data = response.data
        data = json.loads(data.decode('ascii'))

        return data

    def modifyIcon(self, icon_id, args):
        """ modifyIcon :
        Update properties of a custom icon.
        Sample usage:
        >>> nto.modifyIcon('75', {'name' : 'A Big Bomb!'})
        ''
        """
        return self._sendRequest('PUT', '/api/custom_icons/' + icon_id, args, False)

    def searchIcon(self, args):
        """ searchIcon :
        Search for a specific custom icon in the system by certain properties.
        Sample usage:
        >>> nto.searchIcon({'name' : 'A Big Bomb!'})
        [{u'id': 75, u'name': u'A Big Bomb!'}]
        """
        return self._sendRequest('POST', '/api/custom_icons/search', args)

    def deleteIcon(self, icon_id):
        """ deleteIcon :
        Remove a custom icon from the system.
        The custom icon is specified by a custom_icon_id_or_name.
        Sample usage:
        >>>.deleteIcon('75')
        ''
        """
        return self._sendRequest('DELETE', '/api/custom_icons/' + icon_id, None, False)

    ####################################
    # Filter Template Collections
    ####################################
    def getAllFilterTemplateCollections(self):
        """ getAllFilterTemplateCollections :
        Fetch a list containing summaries for all the filter template collections in the system.
        Sample usage:
        >>> nto.getAllFilterTemplateCollections()
        [{u'id': 467, u'name': u'NET_TROUBLESHOOTING'}, {u'id': 57, u'name': u'Public'}]
        """
        return self._sendRequest('GET', '/api/filter_template_collections')

    def getFilterTemplateCollection(self, filter_template_collection):
        """ getFilterTemplateCollection :
        Fetch the properties of a filter template collection object which is specified by its
        filter_template_collection_id_or_name.
        Sample usage:
        >>> nto.getFilterTemplateCollection('467')
        {u'description': None, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1429303086082}, u'name': u'NET_TROUBLESHOOTING', u'mod_count': 2, u'id': 467, u'history': []}
        """
        return self._sendRequest('GET', '/api/filter_template_collections/' + filter_template_collection)

    def createFilterTemplateCollection(self, args):
        """ createFilterTemplateCollection :
        Create a new filter template collection.
        Sample usage:
        >>> nto.createFilterTemplateCollection({'description': 'My filter collection', 'name': 'Private Filter Collection'})
        {u'id': u'50'}
        """
        return self._sendRequest('POST', '/api/filter_template_collections', args)

    def modifyFilterTemplateCollection(self, filter_template_collection_id, args):
        """ modifyFilterTemplateCollection :
        Update properties of a filter template collection.
        Sample usage:
        >>> nto.modifyFilterTemplateCollection('50', {'description': 'My private filter collection'})
        ''
        """
        return self._sendRequest('PUT', '/api/filter_template_collections/' + filter_template_collection_id, args, False)

    def searchFilterTemplateCollections(self, args):
        """ searchFilterTemplateCollections :
        Search for a specific filter template collection in the system by certain properties.
        Sample usage:
        >>> nto.searchFilterTemplateCollections({'name': 'Private Filter Collection'})
        [{u'id': 50, u'name': u'Private Filter Collection'}]
        """
        return self._sendRequest('POST', '/api/filter_template_collections/search', args)

    def deleteFilterTemplateCollection(self, filter_template_collection_id):
        """ deleteFilterTemplate :
        Remove a filter template collection from the system. The filter is specified by a
        filter_template_collection_id_or_name.
        Sample usage:
        >>> nto.deleteFilterTemplateCollection('50')
        ''
        """
        return self._sendRequest('DELETE', '/api/filter_template_collections/' + filter_template_collection_id, None, False)

    ####################################
    # Filter Templates
    ####################################
    def getAllFilterTemplates(self):
        """ getAllFilterTemplates :
        Fetch a list containing summaries for all the filter templates in the system.
        Sample usage:
        >>> nto.getAllFilterTemplates()
        [{u'id': 468, u'name': u'Too Much Overhead'}, {u'id': 469, u'name': u'Syn Attack'}, {u'id': 470, u'name': u'ARP Storm'}, {u'id': 51, u'name': u'VLAN Gold'}]
        """
        return self._sendRequest('GET', '/api/filter_templates')

    def getFilterTemplate(self, filter_template):
        """ getFilterTemplate :
        Fetch the properties of a filter templates object which is specified by its filter_template_id.
        Sample usage:
        >>> nto.getFilterTemplate('468')
        {u'description': u'Use for base line tools.  Checks ICMP and SNMP traffic.', u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1429303123112}, u'collection': u'NET_TROUBLESHOOTING', u'name': u'Too Much Overhead', u'mod_count': 5, u'criteria': {u'logical_operation': u'AND', u'ip_protocol': {u'value': u'1'}, u'layer4_src_or_dst_port': {u'port': u'161-162'}}, u'id': 468, u'history': []}
        """
        return self._sendRequest('GET', '/api/filter_templates/' + filter_template)

    def createFilterTemplate(self, args):
        """ createFilterTemplate :
        Create a new filter template.
        Sample usage:
        >>> nto.createFilterTemplate({'collection': 'Public', 'name': 'Virtual Traffic', 'criteria': {'vlan': {'vlan_id': '100'}, 'logical_operation': 'AND'}})
        {u'id': u'52'}
        """
        return self._sendRequest('POST', '/api/filter_templates', args)

    def modifyFilterTemplate(self, filter_template_id, args):
        """ modifyFilterTemplate :
        Update properties of a filter template.
        Sample usage:
        >>> nto.modifyFilterTemplate('52', {'criteria': {'vlan': {'vlan_id': '200'}, 'logical_operation': 'AND'}})
        ''
        """
        return self._sendRequest('PUT', '/api/filter_templates/' + filter_template_id, args, False)

    def searchFilterTemplates(self, args):
        """ searchFilterTemplates :
        Search for a specific filter template in the system by certain properties.
        Sample usage:
        >>> nto.searchFilterTemplates({'collection': 'Public'})
        [{u'id': 51, u'name': u'VLAN Gold'}, {u'id': 52, u'name': u'Virtual Traffic'}]
        """
        return self._sendRequest('POST', '/api/filter_templates/search', args)

    def deleteFilterTemplate(self, filter_template_id):
        """ deleteFilterTemplate :
        Remove a filter template from the system. The filter template is specified by a filter_template_id.
        Sample usage:
        >>> nto.deleteFilterTemplate('52')
        ''
        """
        return self._sendRequest('DELETE', '/api/filter_templates/' + filter_template_id, None, False)

    ####################################
    # Filters
    ####################################
    def getAllFilters(self):
        """ getAllFilters :
        Fetch a list containing summaries for all the filters in the system.
        Sample usage:
        >>> nto.getAllFilters()
        [{u'id': 460, u'name': u'TCP, UDP, HTTP'}, {u'id': 461, u'name': u'Voice VLANs'}, {u'id': 462, u'name': u'ARP Storm'}, {u'id': 463, u'name': u'Syn Attack'}, {u'id': 464, u'name': u'DENY HTTPS'}, {u'id': 465, u'name': u'Too Much Overhead'}, {u'id': 466, u'name': u'F4'}]
        """
        return self._sendRequest('GET', '/api/filters')

    def getFilter(self, filter, properties=None):
        """ getFilter :
        Fetch the properties of a filter object which is specified by its filter_id_or_name.
        Sample usage:
        >>> nto.getFilter('461')
        {u'dynamic_filter_type': u'TWO_STAGE', u'connect_in_access_settings': {u'policy': u'INHERITED'}, u'dest_port_list': [], u'match_count_unit': u'PACKETS', u'description': None, u'resource_access_settings': {u'policy': u'INHERITED'}, u'created': None, u'modify_access_settings': {u'policy': u'INHERITED'}, u'default_name': u'F3', u'dest_port_group_list': [], u'name': u'Voice VLANs', u'mod_count': 6, u'snmp_tag': None, u'mode': u'PASS_BY_CRITERIA', u'criteria': {u'vlan': {u'priority': None, u'vlan_id': u'1000'}, u'logical_operation': u'AND'}, u'keywords': [], u'source_port_group_list': [], u'source_port_list': [410, 428], u'connect_out_access_settings': {u'policy': u'INHERITED'}, u'id': 461, u'history': [{u'type': u'MODIFY', u'time': 1442251734144, u'caused_by': u'internal', u'details': None, u'props': [u'SOURCE_PORT_LIST', u'DEST_PORT_LIST']}]}
        """
        query = ""
        if properties:
            query = '?properties=' + ''.join(properties.split())

        return self._sendRequest('GET', '/api/filters/' + filter + query)

    def createFilter(self, args, allowTemporayDataLoss=False):
        """ createFilter :
        Create a new filter.
        Sample usage:
        >>> nto.createFilter({'source_port_list': ['218', '220'], 'dest_port_list': ['219'], 'mode': 'PASS_ALL'})
        {u'id': u'466'}
        """
        return self._sendRequest('POST', '/api/filters?allowTemporayDataLoss=' + str(allowTemporayDataLoss), args)

    def modifyFilter(self, filter_id, args, allowTemporayDataLoss=False):
        """ modifyFilter :
        Update properties of a filter.
        Sample usage:
        >>> nto.modifyFilter('F4', {'mode' : 'PASS_BY_CRITERIA', 'criteria' : {'logical_operation': 'AND', 'ipv4_session_flow': {'session_sets': [{'a_sessions': ['10.0.0.0/24:1', '12.0.0.0/24:1'], 'b_sessions': ['14.0.0.0/24:1', '16.0.0.0/24:1']}], 'flow_type': 'UNI'}}})
        ''
        """
        return self._sendRequest('PUT', '/api/filters/' + filter_id + '?allowTemporayDataLoss=' + str(allowTemporayDataLoss), args, False)

    def searchFilters(self, args):
        """ searchFilters :
        Search for a specific port group in the system by certain properties.
        Sample usage:
        >>> nto.searchFilters({'mode' : 'PASS_BY_CRITERIA'})
        [{u'id': 463, u'name': u'Syn Attack'}, {u'id': 465, u'name': u'Too Much Overhead'}, {u'id': 466, u'name': u'F8'}, {u'id': 55, u'name': u'F4'}, {u'id': 460, u'name': u'TCP, UDP, HTTP'}, {u'id': 462, u'name': u'ARP Storm'}, {u'id': 461, u'name': u'Voice VLANs'}]
        """
        return self._sendRequest('POST', '/api/filters/search', args)

    def deleteFilter(self, filter_id):
        """ deleteFilter :
        Remove a filter from the system. The filter is specified by a filter_id_or_name.
        Sample usage:
        >>> nto.deleteFilter('F4')
        ''
        """
        return self._sendRequest('DELETE', '/api/filters/' + filter_id, None, False)

    def getFilterProperty(self, filter, property):
        """ getFilterProperty :
        Fetch a property of a filter object which is specified by its
        filter_id_or_name.
        Sample usage:
        >>> nto.getFilterProperty('F1', 'keywords')
        [u'TIME']
        """
        return self.getFilter(filter, property)[property]
        #return self._sendRequest('GET', '/api/filters/' + filter + '?properties=' + property)[property]

    def getFilterProperties(self, filter, properties):
        """ getFilterProperties :
        Fetch a list of properties of a filter object which is specified by its
        filter_id_or_name.
        Sample usage:
        >>> nto.getFilterProperties('F1', 'mode,name')
        {u'mode': u'PASS_ALL', u'name': u'L2-Resoure-Akamai'}
        """
        return self.getFilter(filter, properties)
        #return self._sendRequest('GET', '/api/filters/' + filter + '?properties=' + properties)

    ####################################
    # Groups
    ####################################
    def getAllGroups(self):
        """ getAllGroups :
        Fetch a list containing the summaries for all the user groups in the system.
        Sample usage:
        >>> nto.getAllGroups()
        [{u'id': 369, u'name': u'Security Mgmt'}, {u'id': 367, u'name': u'Network Mgmt'}, {u'id': 368, u'name': u'Security Engineering'}, {u'id': 365, u'name': u'group2'}, {u'id': 366, u'name': u'Network Operations'}, {u'id': 364, u'name': u'group1'}]
        """
        return self._sendRequest('GET', '/api/groups')

    def getGroup(self, group):
        """ getGroup :
        Fetch the properties of an user group object which is specified by its
        group_id_or_name.
        Sample usage:
        >>> nto.getGroup('369')
        {u'owners': [], u'auto_created': False, u'description': None, u'name': u'Security Mgmt', u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1256831414761}, u'accessible_ports': [], u'mod_count': 2, u'members': [u'bbrother', u'securityguy'], u'accessible_filters': [], u'id': 369, u'history': [{u'type': u'MODIFY', u'time': 1316645263611, u'caused_by': u'internal', u'details': None, u'props': [u'ACCESSIBLE_PORTS']}]}
        """
        return self._sendRequest('GET', '/api/groups/' + group)

    def createGroup(self, args):
        """ createGroup :
        Create a new user group.
        Sample usage:
        >>> nto.createGroup({'name' : 'Automation', 'members': ['bbrother', 'jfixit']})
        {u'id': u'477'}
        """
        return self._sendRequest('POST', '/api/groups', args)

    def modifyGroup(self, group_id, args):
        """ modifyGroup :
        Update the properties of an existing user group.
        Sample usage:
        >>> nto.modifyGroup('Automation', {'members': ['jfixit']})
        ''
        """
        return self._sendRequest('PUT', '/api/groups/' + group_id, args, False)

    def deleteGroup(self, group_id):
        """ deleteGroup :
        Remove a user from the system. The user is specified by a group_id_or_name.
        Sample usage:
        >>> nto.deleteGroup('477')
        ''
        """
        return self._sendRequest('DELETE', '/api/groups/' + group_id, None, False)

    def searchGroups(self, args):
        """ searchGroups :
        Search for a specific user group in the system by certain properties.
        Sample usage:
        >>> nto.searchGroups({'members': ['netopsguy']})
        [{u'id': 367, u'name': u'Network Mgmt'}]
        """
        return self._sendRequest('POST', '/api/groups/search', args)

    ####################################
    # GSC resources
    ####################################
    def disableGscResource(self, gsc_resource_id, args):
        """ disableGscResource :
        Disables an AFM resource by disconnecting the attached port, port group or filter.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/gsc_afm_resources/' + gsc_resource_id + '/disable', args, False)

    def enableGscResource(self, gsc_resource_id, args):
        """ enableGscResource :
        Enables an AFM resource by attaching a port, port group or filter to it.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/gsc_afm_resources/' + gsc_resource_id + '/enable', args, False)

    def getGscResourceBandwidth(self, gsc_resource_id):
        """ getGscResourceBandwidth :
        Gets the bandwidth details for the GSC AFM resource.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/gsc_afm_resources/' + gsc_resource_id + '/get_bandwidth_details')

    def getGscResource(self, gsc_resource_id):
        """ getGscResource :
        Fetch the properties of an GSC-FD resource object.
        To request only select properties (partial response), append to the URL the query
        parameter '?properties=value', where value is comma-separated list to select
        multiple fields for example: /api/resource_type/{object-id}?properties=description,name.
        Query Parameter is optional.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/gsc_afm_resources/' + gsc_resource_id)

    def getAllGscResources(self):
        """ getAllGscResources :
        Fetch a list containing the summaries for all the GSC-FD resources in the system.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/gsc_afm_resources')

    def resetGscFragmentationEngine(self, gsc_resource_id):
        """ resetGscFragmentationEngine :
        Resets the GSC fragmentation engine.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/gsc_afm_resources/' + gsc_resource_id + '/reset_gsc_fragmentation_engine')

    def searchGscResource(self, args):
        """ searchGscResource :
        Search for a specific GSC resource in the system by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/gsc_afm_resources/search', args)

    def modifyGscResource(self, gsc_resource_id, args):
        """ modifyGscResource :
        Update the properties of an existing GSC resource.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/gsc_afm_resources/' + gsc_resource_id, args, False)

    ####################################
    # GTP FD resources
    ####################################
    def disableGtpFdResource(self, gtp_fd_resource_id, args):
        """ disableGtpFdResource :
        Disables an AFM resource by disconnecting the attached port, port group or filter.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/gtp_fd_afm_resources/' + gtp_fd_resource_id + '/disable', args, False)

    def enableGtpFdResource(self, gtp_fd_resource_id, args):
        """ enableGtpFdResource :
        Enables an AFM resource by attaching a port, port group or filter to it.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/gtp_fd_afm_resources/' + gtp_fd_resource_id + '/enable', args, False)

    def getGtpFdResourceBandwidth(self, gtp_fd_resource_id):
        """ getGtpFdResourceBandwidth :
        Gets the bandwidth details for the Recirculated AFMresource.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/gtp_fd_afm_resources/' + gtp_fd_resource_id + '/get_bandwidth_details')

    def getGtpFdResource(self, gtp_fd_resource_id):
        """ getGtpFdResource :
        Fetch the properties of an GTP-FD resource object.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/gtp_fd_afm_resources/' + gtp_fd_resource_id)

    def getAllGtpFdResources(self):
        """ getAllGtpFdResources :
        Fetch a list containing the summaries for all the GTP-FD resources in the system.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/gtp_fd_afm_resources')

    def searchGtpFdResource(self, args):
        """ searchGtpFdResource :
        Search for a specific AFM resource in the system by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/gtp_fd_afm_resources/search', args)

    def modifyGtpFdResource(self, gtp_fd_resource_id, args):
        """ modifyGtpFdResource :
        Update the properties of an existing AFM resource.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/gtp_fd_afm_resources/' + gtp_fd_resource_id, args, False)

    ###################################################
    # Heartbeats
    ###################################################
    def createHeartbeat(self, args):
        """ createHeartbeat :
        Create a new tool heartbeat in the system.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/heartbeats', args)

    def deleteHeartbeat(self, heartbeat_id):
        """ deleteHeartbeat :
        Remove an existing tool heartbeat from the system.
        Sample usage:
        """
        return self._sendRequest('DELETE', '/api/heartbeats/' + heartbeat_id, None, False)

    def getHeartbeat(self, heartbeat_id):
        """ getHeartbeat :
        Fetch the properties of a tool heartbeat object.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/heartbeats/' + heartbeat_id)

    def getAllHeartbeats(self):
        """ getAllHeartbeats :
        Fetch a list containing the summaries for all the tool heartbeats in the system.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/heartbeats')

    def searchHeartbeat(self, args):
        """ searchHeartbeat :
        Search for a specific tool heartbeat in the system by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/heartbeats/search', args)

    def modifyHeartbeat(self, heartbeat_id, args):
        """ modifyHeartbeat:
        Update the properties of an existing tool heartbeat.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/heartbeats/' + heartbeat_id, args, False)

    ###################################################
    # Service Chains
    ###################################################
    def applyToolSharingMapInline(self, inline_id, args):
        """ applyToolSharingMapInline :
        Applies the tool sharing data received to all the BPPs associated with the
        service chain key received as argument.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/inline_service_chains/'+ inline_id + '/applyToolSharingMap', args, False)

    def applyVlanTranslationMapInline(self, inline_id, args):
        """ applyVlanTranslationMapInline :
        Applies the vlan translation data received to all BPPs associated with the
        service chain key received as argument.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/inline_service_chains/'+ inline_id + '/applyVlanTranslationMap', args, False)

    def createInlineServiceChain(self, args):
        """ createInlineServiceChain :
        Create a new inline service chain in the system.
        Sample usage:
        >>> nto.createInlineServiceChain({"bypass_connector_list": [120], "criteria": {"logical_operation": "AND", "vlan": [{"priority": None, "vlan_id": "100" }]}, "direction": "BIDI", "filter_mode": "PASS_BY_CRITERIA", "name": "Secure SC Python", "tool_resource_map": [{"tool_resource_failure_action": "FAIL_CLOSED", "tool_resource_id": 114}], "tool_sharing_enable": False, "vlan_translation_enabled": False})
        {'default_name': 'SC1', 'id': 121, 'name': 'Secure SC Python'}
        """
        return self._sendRequest('POST', '/api/inline_service_chains', args)

    def deleteInlineServiceChain(self, inline_id):
        """ deleteInlineServiceChain :
        Remove an existing inline service chain from the system.
        Sample usage:
        >>> nto.deleteInlineServiceChain('121')
        b''
        """
        return self._sendRequest('DELETE', '/api/inline_service_chains/' + inline_id, None, False)

    def getInlineServiceChain(self, inline_id):
        """ getInlineServiceChain :
        Fetch the properties of a inline service chain object.
        Sample usage:
        >>> nto.getInlineServiceChain('126')
        {'bypass_connector_list': [120], 'connect_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'created': {'caused_by': 'admin', 'details': None, 'time': 1605732093043, 'type': 'CREATE'}, 'criteria': {'logical_operation': 'AND', 'vlan': [{'priority': None, 'vlan_id': '100'}]}, 'default_name': 'SC1', 'description': None, 'direction': 'BIDI', 'filter_list': [127, 128, 129, 130], 'filter_mode': 'PASS_BY_CRITERIA', 'history': [{'caused_by': 'admin', 'details': None, 'props': ['INLINE_TOOL_RESOURCE_MAP'], 'time': 1605732093110, 'type': 'MODIFY'}], 'id': 126, 'misc': {'access_map': {'CONNECT_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *BPP1: Inherited *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Connect Bypass Port Pairs', 'operation_phrase': 'connect bypass port pairs to', 'tooltip': 'Inherit from BPPs', 'user_names': '', 'users_statement': 'Anyone can perform'}, 'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *BPP1: Inherited *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from BPPs', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS', 'CONNECT_ACCESS_SETTINGS'], 'warning': None}, 'mod_count': 1, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'Secure SC Python', 'tool_resource_map': [{'tool_resource_failure_action': 'FAIL_CLOSED', 'tool_resource_id': '114'}], 'tool_sharing_enable': False, 'vlan_translation_enabled': False}
        """
        return self._sendRequest('GET', '/api/inline_service_chains/' + inline_id)

    def getAllInlineServiceChains(self):
        """ getAllInlineServiceChains :
        Fetch a list containing the summaries for all the inline service chains in the system.
        Sample usage:
        >>> nto.getAllInlineServiceChains()
        [{'id': 126, 'name': 'Secure SC Python'}]
        """
        return self._sendRequest('GET', '/api/inline_service_chains')

    def searchInlineServiceChains(self, args):
        """ searchInlineServiceChains :
        Search for a specific inline service chain in the system by certain properties.
        Sample usage:
        >>> nto.searchInlineServiceChains({"direction": "BIDI"})
        [{'bypass_connector_list': [120], 'connect_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'created': {'caused_by': 'admin', 'details': None, 'time': 1605732093043, 'type': 'CREATE'}, 'criteria': {'logical_operation': 'AND', 'vlan': [{'priority': None, 'vlan_id': '100'}]}, 'default_name': 'SC1', 'description': None, 'direction': 'BIDI', 'filter_list': [127, 128, 129, 130], 'filter_mode': 'PASS_BY_CRITERIA', 'history': [{'caused_by': 'admin', 'details': None, 'props': ['INLINE_TOOL_RESOURCE_MAP'], 'time': 1605732093110, 'type': 'MODIFY'}], 'id': 126, 'misc': {'access_map': {'CONNECT_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *BPP1: Inherited *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Connect Bypass Port Pairs', 'operation_phrase': 'connect bypass port pairs to', 'tooltip': 'Inherit from BPPs', 'user_names': '', 'users_statement': 'Anyone can perform'}, 'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *BPP1: Inherited *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from BPPs', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS', 'CONNECT_ACCESS_SETTINGS'], 'warning': None}, 'mod_count': 1, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'Secure SC Python', 'tool_resource_map': [{'tool_resource_failure_action': 'FAIL_CLOSED', 'tool_resource_id': '114'}], 'tool_sharing_enable': False, 'vlan_translation_enabled': False}]
        """
        return self._sendRequest('POST', '/api/inline_service_chains/search', args)

    def modifyInlineServiceChain(self, inline_id, args):
        """ modifyInlineServiceChain:
        Update the properties of an existing inline service chain.
        Sample usage:
        >>> nto.modifyInlineServiceChain('126', {"description": "Chain Descr"})
        b''
        """
        return self._sendRequest('PUT', '/api/inline_service_chains/' + inline_id, args, False)

    ###################################################
    # Kubernetes Nodes
    ###################################################
    def getKubernetesNode(self, kubernetes_nodes_id):
        """ getKubernetesNode :
        Fetch the properties of a kubernetes node object.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/kubernetes_nodes/' + kubernetes_nodes_id)

    def getAllKubernetesNodes(self):
        """ getAllKubernetesNodes :
        Fetch a list containing the summaries for all the kubernetes nodes in the system.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/kubernetes_nodes')

    def resetFactoryDefaultKubernetesNode(self, kubernetes_nodes_id):
        """ resetFactoryDefaultKubernetesNode :
        Reset to factory default a specific kubernetes node from the Mako card.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/kubernetes_nodes/' + kubernetes_nodes_id + '/reset_factory', args, False)

    ###################################################
    # Line Boards
    ###################################################
    def getAllLineBoards(self):
        """ getAllLineBoards :
        Fetch a list containing the summaries for all the line boards in the system.
        Sample usage:
        >>> nto.getAllLineBoards()
        [{u'id': 471, u'name': u'LC6'}, {u'id': 476, u'name': u'LC1'}, {u'id': 474, u'name': u'LC5'}, {u'id': 475, u'name': u'LC3'}, {u'id': 472, u'name': u'LC2'}, {u'id': 473, u'name': u'LC4'}]
        """
        return self._sendRequest('GET', '/api/line_boards')

    def getLineBoard(self, line_board):
        """ getLineBoard :
        Fetch the properties of a line board.
        Sample usage:
        >>> nto.getLineBoard('LC6')
        {u'name': u'LC6', u'qsfp_card_mode': u'MODE_QSFP', u'default_name': u'LC6', u'mod_count': 9, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'id': 471}
        """
        return self._sendRequest('GET', '/api/line_boards/' + line_board)

    def searchLineBoard(self, args):
        """ searchLineBoard :
        Search for a specific capture in the system by certain properties.
        Sample usage:
        >>> nto.searchLineBoard({'name': 'LC6'})
        [{u'id': 471, u'name': u'LC6'}]
        """
        return self._sendRequest('POST', '/api/line_boards/search', args)

    def switchModeLineBoard(self, line_board):
        """ switchModeLineBoard :
        Switches the card mode to QSFP if in SFP mode and to SFP if in QSFP mode.
        Sample usage:
        >>> nto.switchModeLineBoard('LC6')
        ''
        """
        args = {}
        return self._sendRequest('PUT', '/api/line_boards/' + line_board + '/switch_mode', args, False)

    def modifyLineBoard(self, line_board, args):
        """ modifyLineBoard :
        Update the properties of an existing line board.
        Sample usage:
        >>> nto.modifyLineBoard('LC6', {'name' : 'Test LC'})
        ''
        """
        return self._sendRequest('PUT', '/api/line_boards/' + line_board, args, False)

    ###################################################
    # Boards
    ###################################################
    def getAllBoards(self):
        """ getAllBoards :
        Fetch a list containing the summaries for all the boards in the system.
        Sample usage:
        >>> nto.getAllBoards()
        [{'id': 74, 'management_port_enabled': False, 'name': 'Board: 1', 'number': None, 'port_module_mode': 'NONE', 'slot': 'A', 'smart_blank_present': False, 'state': 'READY', 'type': 'NETSTACK_16_QSFP'}, {'id': 75, 'management_port_enabled': False, 'name': 'Board: 3', 'number': None, 'port_module_mode': 'GSC_FD', 'slot': 'C', 'smart_blank_present': False, 'state': 'READY', 'type': 'PACKETSTACK_400_QSFP28'}, {'id': 76, 'management_port_enabled': False, 'name': 'Board: 5', 'number': None, 'port_module_mode': 'PACKETSTACK', 'slot': 'R', 'smart_blank_present': False, 'state': 'READY', 'type': 'PACKETSTACK_400_REAR'}, {'id': 77, 'management_port_enabled': False, 'name': 'Board: 2', 'number': None, 'port_module_mode': 'PACKETSTACK', 'slot': 'B', 'smart_blank_present': False, 'state': 'READY', 'type': 'PACKETSTACK_400_QSFP28'}, {'id': 78, 'management_port_enabled': False, 'name': 'Board: 4', 'number': None, 'port_module_mode': 'NONE', 'slot': 'D', 'smart_blank_present': False, 'state': 'READY', 'type': 'NETSERVICE_4_QSFP28'}]
        """
        return self._sendRequest('GET', '/api/boards')

    def getBoard(self, board):
        """ getBoard :
        Fetch the properties of a board object.
        Sample usage:
        >>> nto.getBoard('Board: 1')
        {'default_name': 'Board: 1', 'id': 74, 'management_port_enabled': False, 'mod_count': 4, 'modify_access_settings': {'groups': [], 'policy': 'ALLOW_ALL'}, 'name': 'Board: 1', 'number': None, 'port_module_mode': 'NONE', 'slot': 'A', 'smart_blank_present': False, 'state': 'READY', 'type': 'NETSTACK_16_QSFP'}
        """
        return self._sendRequest('GET', '/api/boards/' + board)

    def searchBoard(self, args):
        """ searchBoard :
        Fetch a list containing the summaries for all the boards in the system.
        Sample usage:
        >>> nto.searchBoard({'slot': 'C'})
        [{'default_name': 'Board: 3', 'id': 75, 'management_port_enabled': False, 'mod_count': 6, 'modify_access_settings': {'groups': [], 'policy': 'ALLOW_ALL'}, 'name': 'Board: 3', 'number': None, 'port_module_mode': 'GSC_FD', 'slot': 'C', 'smart_blank_present': False, 'state': 'READY', 'type': 'PACKETSTACK_400_QSFP28'}]
        """
        return self._sendRequest('POST', '/api/boards/search', args)

    def modifyBoard(self, board, args):
        """ modifyBoard :
        Update the properties of an existing board.
        Sample usage:
        >>> nto.modifyBoard('75', {'port_module_mode': 'PACKETSTACK'})
        b''
        """
        return self._sendRequest('PUT', '/api/boards/' + board, args, False)

    ###################################################
    # Monitors
    ###################################################
    def getAllMonitors(self):
        """ getAllMonitors :
        Fetch a list containing the summaries for all the monitors in the system.
        Sample usage:
        >>> nto.getAllMonitors()
        [{u'id': 572, u'name': u'Low Traffic'}]
        """
        return self._sendRequest('GET', '/api/monitors')

    def getMonitor(self, monitor):
        """ getMonitor :
        Fetch the properties of a monitor object which is specified by its
        monitor_id_or_name.
        Sample usage:
        >>> nto.getMonitor('572')
        {u'description': None, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1442432114344}, u'actions': [{u'min_interval': {u'value': 15, u'unit': u'SEC'}, u'type': u'TRAP', u'enabled': True}], u'name': u'Low Traffic', u'mod_count': 0, u'trigger': {u'stat': u'NP_CURRENT_RX_UTILIZATION', u'window_size': 1, u'window_count': 1, u'down_threshold_enabled': True, u'up_threshold': 99, u'up_threshold_enabled': False, u'down_threshold': 10, u'type': u'PERCENT_STAT', u'ports': [58]}, u'id': 572, u'history': []}
        """
        return self._sendRequest('GET', '/api/monitors/' + monitor)

    def createMonitor(self, args):
        """ createMonitor :
        Create a new monitor.
        Sample usage:
        >>> nto.createMonitor({'actions': [{'min_interval': {'value': 15, 'unit': 'SEC'}, 'type': 'TRAP', 'enabled': True}], 'name': 'Drop Packets', 'trigger': {'stat': 'TP_TOTAL_DROP_COUNT_PACKETS', 'window_size': 1, 'min_change': 10, 'window_count': 1, 'type': 'COUNT_STAT', 'ports': [59]}})
        '{"id": "574"}'
        """
        return self._sendRequest('POST', '/api/monitors', args, False)

    def modifyMonitor(self, monitor_id, args):
        """ modifyMonitor :
        Update properties of a monitor.
        Sample usage:
        >>> nto.modifyMonitor('574', {'trigger': {'stat': 'TP_TOTAL_DROP_COUNT_PACKETS', 'window_size': 1, 'min_change': 20, 'window_count': 1, 'type': 'COUNT_STAT', 'ports': [59]}})
        ''
        """
        return self._sendRequest('PUT', '/api/monitors/' + monitor_id, args, False)

    def searchMonitors(self, args):
        """ searchMonitors :
        Search for a specific port group in the system by certain properties.
        Sample usage:
        >>> nto.searchMonitors({'name': 'Drop Packets'})
        [{u'id': 574, u'name': u'Drop Packets'}]
        """
        return self._sendRequest('POST', '/api/monitors/search', args)

    def deleteMonitor(self, monitor_id):
        """ deleteMonitor :
        Remove a monitor from the system. The monitor is specified by a monitor_id_or_name.
        Sample usage:
        >>> nto.deleteMonitor('572')
        ''
        """
        return self._sendRequest('DELETE', '/api/monitors/' + monitor_id, None, False)

    ###################################################
    # Netservice Instances
    ###################################################
    def createNetserviceInstance(self, args):
        """ createNetserviceInstance :
        Create a new netservice instance in the system.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/netservice_instances', args)

    def deleteNetserviceInstance(self, netservive_id):
        """ deleteNetserviceInstance :
        Remove an existing netservice instance from the system.
        Sample usage:
        """
        return self._sendRequest('DELETE', '/api/netservice_instances/' + netservive_id, None, False)

    def deployNetserviceInstance(self, netservive_id):
        """ deployNetserviceInstance :
        Deployes a specific netservice instance in the system.
        This method is allowed only on the following models: 8000.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/netservice_instances/' + netservive_id + '/deploy', None, False)

    def drainNetserviceInstance(self, netservive_id):
        """ drainNetserviceInstance :
        Drains a specific netservice instance in the system.
        This method is allowed only on the following models: 8000.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/netservice_instances/' + netservive_id + '/drain', None, False)

    def getNetserviceInstance(self, netservice_id):
        """ getNetserviceInstance :
        Fetch the properties of a netservice instance object.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/netservice_instances/' + netservice_id)

    def getAllNetserviceInstancesType(self, netservive_type):
        """ getAllNetserviceInstancesType :
        Fetch a list containing the available resources for specified deployment type in the system.
        This method is allowed only on the following models: 8000.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/netservice_instances/' + netservive_type + '/list_available_resources', None)

    def getAllNetserviceInstances(self):
        """ getAllNetserviceInstances :
        Fetch a list containing the summaries for all the netservice instances in the system.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/netservice_instances')

    def restartNetserviceInstance(self, netservive_id):
        """ restartNetserviceInstance :
        Restarts a specific netservice instance in the system.
        This method is allowed only on the following models: 8000.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/netservice_instances/' + netservive_id + '/restart', None, False)

    def searchNetserviceInstance(self, args):
        """ searchNetserviceInstance :
        Search for a specific netservice instance in the system by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/netservice_instances/search', args)

    def modifyNetserviceInstance(self, netservive_id, args):
        """ modifyNetserviceInstance :
        Update the properties of an existing netservice instance.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/netservice_instances/' + netservive_id, args, False)

    ###################################################
    # Port Groups
    ###################################################
    def getAllPortGroups(self):
        """ getAllPortGroups :
        Fetch a list containing the summaries for all the port groups in the system.
        Sample usage:
        >>> nto.getAllPortGroups()
        [{u'id': 202, u'name': u'PGF27'}, {u'id': 203, u'name': u'PGF31'}, {u'id': 204, u'name': u'PGF30'}, {u'id': 205, u'name': u'PGF29'}, {u'id': 206, u'name': u'PGF28'}, {u'id': 251, u'name': u'PGF1'}, {u'id': 252, u'name': u'PGF2'}, {u'id': 253, u'name': u'PGF3'}, {u'id': 254, u'name': u'PGF4'}, {u'id': 255, u'name': u'PGF5'}, {u'id': 288, u'name': u'PGF6'}, {u'id': 289, u'name': u'PGF7'}, {u'id': 290, u'name': u'PGF8'}, {u'id': 291, u'name': u'PGF9'}, {u'id': 292, u'name': u'PGF10'}, {u'id': 325, u'name': u'PGF11'}, {u'id': 326, u'name': u'PGF12'}, {u'id': 327, u'name': u'PGF13'}, {u'id': 328, u'name': u'PGF14'}, {u'id': 329, u'name': u'PGF15'}, {u'id': 362, u'name': u'PGF16'}, {u'id': 363, u'name': u'PGF17'}, {u'id': 364, u'name': u'PGF18'}, {u'id': 365, u'name': u'PGF19'}, {u'id': 366, u'name': u'PGF20'}, {u'id': 399, u'name': u'PGF21'}, {u'id': 400, u'name': u'PGF22'}, {u'id': 401, u'name': u'PGF23'}, {u'id': 402, u'name': u'PGF24'}, {u'id': 403, u'name': u'PGF25'}, {u'id': 404, u'name': u'PG1'}]
        """
        return self._sendRequest('GET', '/api/port_groups')

    def getPortGroup(self, port_group, properties=None):
        """ getPortGroup :
        Fetch the properties of a port group object which is specified by its
        port_group_id_or_name.
        Sample usage:
        >>> nto.getPortGroup('404')
        {u'trim_settings': None, u'supports_timestamp': False, u'dedup_settings': None, u'vntag_strip_settings': None, u'vxlan_strip_settings': None, u'failover_mode': u'REBALANCE', u'keywords': [], u'supports_dedup': False, u'id': 404, u'fabric_path_strip_settings': None, u'supports_vntag_strip': False, u'has_dropped_packets': False, u'filtering_direction': u'INGRESS', u'supports_trailer_strip': False, u'icon_type': u'INTERCONNECT', u'last_filter_order_event': None, u'supports_mpls_strip': False, u'enabled_status': u'ENABLED', u'supports_burst_buffer': False, u'custom_icon_id': None, u'trailer_strip_settings': None, u'mpls_strip_settings': None, u'type': u'INTERCONNECT', u'tx_light_status': u'ON', u'filter_criteria': {u'logical_operation': u'AND'}, u'supports_std_vlan_strip': True, u'pause_frames_status': u'IGNORE', u'dest_filter_list': [], u'description': None, u'snmp_tag': None, u'l2gre_strip_settings': None, u'gtp_strip_settings': None, u'burst_buffer_settings': None, u'force_link_up': u'NOT_SUPPORTED', u'supports_trim': False, u'supports_gtp_strip': False, u'port_list': [58], u'supports_vxlan_strip': False, u'name': u'PG1', u'supports_l2gre_strip': False, u'supports_fabric_path_strip': False, u'link_status': {u'speed': 0, u'link_up': False}, u'interconnect_info': {u'addr': u'0.0.0.0', u'port_group': None}, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1442434236579}, u'default_name': u'PG1', u'supports_erspan_strip': False, u'mod_count': 1, u'timestamp_settings': None, u'erspan_strip_settings': None, u'mode': u'NETWORK', u'source_filter_list': [], u'filter_mode': u'PASS_ALL', u'std_vlan_strip_settings': {u'ingress_count': 0, u'egress_count': 0, u'enabled': False, u'strip_mode': None}, u'history': [{u'type': u'MODIFY', u'time': 1442434236579, u'caused_by': u'admin', u'details': None, u'props': [u'PORT_LIST']}]}
        """
        query = ""
        if properties:
            query = '?properties=' + ''.join(properties.split())

        return self._sendRequest('GET', '/api/port_groups/' + port_group + query)

    def createPortGroup(self, args):
        """ createPortGroup :
        Create a new port group.
        Sample usage:
        >>> nto.createPortGroup({'mode': 'NETWORK', 'type': 'INTERCONNECT', 'port_list': [59,60]})
        {u'id': u'405'}
        """
        return self._sendRequest('POST', '/api/port_groups', args)

    def modifyPortGroup(self, port_group_id, args):
        """ modifyPortGroup :
        Update properties of a port group.
        Sample usage:
        >>> nto.modifyPortGroup('PG2', {'port_list': [59,60,61,62]})
        ''
        """
        return self._sendRequest('PUT', '/api/port_groups/' + port_group_id, args, False)

    def searchPortGroups(self, args):
        """ searchPortGroups :
        Search for a specific port group in the system by certain properties.
        Sample usage:
        >>> nto.searchPortGroups({'enabled_status' : 'DISABLED'})
        [{u'id': 404, u'name': u'PG1'}]
        """
        return self._sendRequest('POST', '/api/port_groups/search', args)

    def deletePortGroup(self, port_group_id):
        """ deletePortGroup :
        Remove a port group from the system. The port group is specified by a port_group_id_or_name.
        Sample usage:
        >>> nto.deletePortGroup('PG2')
        ''
        """
        return self._sendRequest('DELETE', '/api/port_groups/' + port_group_id, None, False)

    def disablePortGroup(self, port_group_id):
        """ disablePortGroup :
        Disables a port group by disabling all the contained ports.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/port_groups/' + port_group_id + '/disable', None, False)

    def enablePortGroup(self, port_group_id):
        """ enablePortGroup :
        Enables a port group by enabling all the contained ports.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/port_groups/' + port_group_id + '/enable', None, False)

    def getPortGroupProperty(self, port_group, property):
        """ getPortGroupProperty :
        Fetch a property of a port group object which is specified by its
        port_id_or_name.
        Sample usage:
        >>> nto.getPortGroupProperty('PG1', 'keywords')
        [u'TIME']
        """
        return self.getPortGroup(port_group, property)[property]
        #return self._sendRequest('GET', '/api/port_groups/' + port_group + '?properties=' + property)[property]

    def getPortGroupProperties(self, port_group, properties):
        """ getPortGroupProperties :
        Fetch one or more properties of a port group object which is specified by its
        port_group_id_or_name.
        Sample usage:
        >>> nto.getPortGroupProperties('50', 'keywords,link_status,default_name,enabled,filter_mode')
        {u'filter_mode': u'DISABLE', u'keywords': [], u'default_name': u'PG1', u'enabled': None, u'link_status': {u'speed': 10000, u'link_up': True}}
        """
        return self.getPortGroup(port_group, properties)
        #return self._sendRequest('GET', '/api/port_groups/' + port_group + '?properties=' + properties)

    ###################################################
    # Ports
    ###################################################
    def clearPort(self, port):
        """ clearPort :
        Clears a port to default configuration. No properties are required in the HTTP Body.

        Sample usage:
        >>> nto.clearPort('P1-01')
        b''
        """
        return self._sendRequest('PUT', '/api/ports/' + port + '/clear', None, False)

    def createPort(self, args):
        """ createPort :
        Create a new port on the system. This can be used only to create
        virtual ports for GRE origination.

        Sample usage:
        >>> nto.createPort({'parent_port_id': 16, 'type': 'VIRTUAL_PORT', 'netstack_tunnel_origination_remote_settings': {'enable_arp': True, 'remote_ip_address': '10.0.1.3'}})
        {'default_name': 'P01-T01', 'id': 100, 'name': 'P01-T01'}
        >>> nto.modifyPort('P01', {'netstack_tunnel_origination_local_settings': {'enabled': True, 'l2gre_key': 1, 'vnid': None}})
        b''
        """
        return self._sendRequest('POST', '/api/ports', args)

    def deletePort(self, port):
        """ deletePort :
        Remove a port from the system. This can be used only to remove
        virtual ports for GRE origination.

        Sample usage:
        >>> nto.modifyPort('P01', {'netstack_tunnel_origination_local_settings': {'enabled': False}})
        b''
        >>> nto.deletePort('P01-T01')
        b''
        """
        return self._sendRequest('DELETE', '/api/ports/' + port, None, False)

    def getAllPorts(self):
        """ getAllPorts :
        Fetch a list containing summaries for all the ports in the system.

        Sample usage:
        >>> nto.getAllPorts()
        [{u'id': 58, u'name': u'P1-01'}, {u'id': 59, u'name': u'P1-02'}, {u'id': 60, u'name': u'P1-03'}, {u'id': 61, u'name': u'P1-04'}, {u'id': 62, u'name': u'P1-05'}, {u'id': 63, u'name': u'P1-06'}, {u'id': 64, u'name': u'P1-07'}, {u'id': 65, u'name': u'P1-08'}, {u'id': 66, u'name': u'P1-09'}, {u'id': 67, u'name': u'P1-10'}, {u'id': 68, u'name': u'P1-11'}, {u'id': 69, u'name': u'P1-12'}, {u'id': 70, u'name': u'P1-13'}, {u'id': 71, u'name': u'P1-14'}, {u'id': 72, u'name': u'P1-15'}, {u'id': 73, u'name': u'P1-16'}]
        """
        return self._sendRequest('GET', '/api/ports')

    def getPort(self, port, properties=None):
        """ getPort :
        Fetch the properties of a port object which is specified by its
        port_id_or_name.

        Sample usage:
        >>> nto.getPort('58')
        {u'trim_settings': None, u'supports_timestamp': False, u'dedup_settings': None, u'filter_criteria': {u'logical_operation': u'AND'}, u'vntag_strip_settings': None, u'std_port_tagging_settings': {u'enabled': False, u'vlan_id': 101}, u'link_up_down_trap_enabled': True, u'filter_match_count_unit': u'PACKETS', u'gtp_fd_settings': None, u'keywords': [u'LC1'], u'tunnel_termination_settings': {u'ip_version': 4, u'dest_ip_addr': None, u'enabled': False, u'empty_erspan_header': False, u'tunnel_protocol': None}, u'supports_dedup': False, u'id': 58, u'fabric_path_strip_settings': None, u'supports_vxlan_strip': False, u'port_group_id': None, u'mpls_strip_settings': None, u'max_licensed_speed': u'40G', u'supports_vntag_strip': False, u'has_dropped_packets': False, u'filtering_direction': u'INGRESS', u'supports_trailer_strip': False, u'tunnel_mac': None, u'supports_tunnel_termination': False, u'supports_mpls_strip': False, u'copper_link_polling': False, u'last_filter_order_event': None, u'vxlan_strip_settings': None, u'supports_burst_buffer': False, u'custom_icon_id': None, u'trailer_strip_settings': None, u'media_type': u'QSFP_PLUS_40G', u'expiration_time': 1449727199651, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'type': u'QSFP_PLUS', u'link_settings': u'40G_FULL', u'tx_light_status': u'ON', u'connect_in_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'supports_std_vlan_strip': True, u'dest_filter_list': [], u'description': None, u'snmp_tag': None, u'l2gre_strip_settings': None, u'gtp_strip_settings': None, u'burst_buffer_settings': None, u'force_link_up': u'NOT_SUPPORTED', u'supports_trim': False, u'supports_gtp_strip': False, u'license_status': u'VALID', u'resource_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'supports_std_port_tagging': True, u'remote_fabric_port': None, u'connect_out_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'name': u'P1-01', u'supports_l2gre_strip': False, u'supports_fabric_path_strip': False, u'ignore_pause_frames': True, u'link_status': {u'duplex': u'UNKNOWN', u'pause': u'UNKNOWN', u'speed': u'N/A', u'link_up': False}, u'icon_type': u'QSFP_PLUS', u'default_name': u'P1-01', u'enabled': False, u'supports_erspan_strip': False, u'mod_count': 21, u'timestamp_settings': None, u'erspan_strip_settings': None, u'mode': u'NETWORK', u'supports_gtp_flow_distribution': False, u'source_filter_list': [], u'filter_mode': u'PASS_ALL', u'std_vlan_strip_settings': {u'ingress_count': 0, u'egress_count': 0, u'enabled': False, u'strip_mode': None}, u'history': []}
        """
        query = ""
        if properties:
            query = '?properties=' + ''.join(properties.split())
            
        return self._sendRequest('GET', '/api/ports/' + port + query)

    def modifyPort(self, port_id, args):
        """ modifyPort :
        Update the properties of a port.
        Sample usage:
        >>> nto.modifyPort('58', {'mode': 'TOOL'})
        ''
        """
        return self._sendRequest('PUT', '/api/ports/' + port_id, args, False)

    def searchPorts(self, args):
        """ searchPorts :
        Search for a specific port in the system by certain properties.
        Sample usage:
        >>> nto.searchPorts({'mode': 'TOOL'})
        [{u'id': 58, u'name': u'P1-01'}]
        """
        return self._sendRequest('POST', '/api/ports/search', args)

    def getPortTransceiverInfo(self, port_id):
        """ getPortTransceiverInfo :
        Fetch the transceiver information of a port object which is specified by its
        port_id_or_nam
        Sample usage:

        >>> nto.getPortTransceiverInfo('P03')
        {'lanes': 1, 'port_default_name': 'P03', 'port_id': '18', 'port_name': 'P03', 'transceiver_info': [{'cable': 'N/A', 'compliance': '100G AOC or 25GAUI C2M AOC', 'connector': 'No separable connector', 'diag_calibration': 'Not Applicable', 'identifier': 'QSFP28', 'length_comment': 'OM4 50um', 'length_mode': 'Unspecified', 'max_length': '6 meters', 'present': 'true', 'rx_input_power1': '1.3392', 'rx_input_power1_dbm': '1.27', 'rx_input_power2': '1.3545', 'rx_input_power2_dbm': '1.32', 'rx_input_power3': '1.3764', 'rx_input_power3_dbm': '1.39', 'rx_input_power4': '1.352', 'rx_input_power4_dbm': '1.31', 'rx_input_power_high_alert_threshold': '3.4673', 'rx_input_power_high_alert_threshold_dbm': '5.40', 'rx_input_power_high_warning_threshold': '1.7378', 'rx_input_power_high_warning_threshold_dbm': '2.40', 'rx_input_power_low_alert_threshold': '0.0467', 'rx_input_power_low_alert_threshold_dbm': '-13.31', 'rx_input_power_low_warning_threshold': '0.0933', 'rx_input_power_low_warning_threshold_dbm': '-10.30', 'rx_input_power_status1': 'Normal', 'rx_input_power_status2': 'Normal', 'rx_input_power_status3': 'Normal', 'rx_input_power_status4': 'Normal', 'temperature': '35', 'temperature_high_alert_threshold': '80', 'temperature_high_warning_threshold': '70', 'temperature_low_alert_threshold': '-10', 'temperature_low_warning_threshold': '0', 'temperature_status': 'Normal', 'tx_bias1': '6.75', 'tx_bias2': '6.75', 'tx_bias3': '6.75', 'tx_bias4': '6.75', 'tx_bias_high_alert_threshold': '8.5', 'tx_bias_high_warning_threshold': '8.0', 'tx_bias_low_alert_threshold': '5.492', 'tx_bias_low_warning_threshold': '6.0', 'tx_bias_status1': 'Normal', 'tx_bias_status2': 'Normal', 'tx_bias_status3': 'Normal', 'tx_bias_status4': 'Normal', 'tx_output_power1': '1.6412', 'tx_output_power1_dbm': '2.15', 'tx_output_power2': '1.6222', 'tx_output_power2_dbm': '2.10', 'tx_output_power3': '1.5521', 'tx_output_power3_dbm': '1.91', 'tx_output_power4': '1.5447', 'tx_output_power4_dbm': '1.89', 'tx_output_power_high_alert_threshold': '3.4673', 'tx_output_power_high_alert_threshold_dbm': '5.40', 'tx_output_power_high_warning_threshold': '1.7378', 'tx_output_power_high_warning_threshold_dbm': '2.40', 'tx_output_power_low_alert_threshold': '0.0724', 'tx_output_power_low_alert_threshold_dbm': '-11.40', 'tx_output_power_low_warning_threshold': '0.1445', 'tx_output_power_low_warning_threshold_dbm': '-8.40', 'tx_output_power_status1': 'Normal', 'tx_output_power_status2': 'Normal', 'tx_output_power_status3': 'Normal', 'tx_output_power_status4': 'Normal', 'vendor_date_code': '05-07-2018', 'vendor_lot_code': '  ', 'vendor_name': 'Mellanox', 'vendor_oui': '0002c9', 'vendor_part_number': 'MFA1A00-C003', 'vendor_rev': 'B1', 'vendor_serial_number': 'MT1823FT00529', 'voltage': '3.2691', 'voltage_high_alert_threshold': '3.5', 'voltage_high_warning_threshold': '3.465', 'voltage_low_alert_threshold': '3.1', 'voltage_low_warning_threshold': '3.135', 'voltage_status': 'Normal', 'wavelength': '8500'}]}        """
        return self._sendRequest('GET', '/api/ports/' + port_id + '/transceiver_info', None)

    def getPortProperty(self, port, property):
        """ getPortProperty :
        Fetch a property of a port object which is specified by its
        port_id_or_name.
        Sample usage:
        >>> nto.getPortProperty('PB07', 'enabled')
        {u'enabled': True}
        """
        return self.getPort(port, property)[property]
        #return self._sendRequest('GET', '/api/ports/' + port + '?properties=' + property)[property]

    def getPortProperties(self, port, properties):
        """ getPortProperties :
        Fetch one or more properties of a port object which is specified by its
        port_id_or_name.
        Sample usage:
        >>> nto.getPortProperties('PB07', 'enabled,link_status')
        {u'enabled': True, u'link_status': {u'duplex': u'FULL', u'pause': u'DISABLED', u'speed': u'10G', u'link_up': True}}
        """
        return self.getPort(port, properties)
        #return self._sendRequest('GET', '/api/ports/' + port + '?properties=' + properties)

    ###################################################
    # RTP Correlator Resources
    ###################################################
    def disableRtp(self, rtp_id, args):
        """ disableRtp :
        Disables an RTP resource by disconnecting the attached filter.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/rtp_correlator_resources/' + rtp_id + '/disable', args, False)

    def enableRtp(self, rtp_id, args):
        """ enableRtp :
        Enables an RTP resource by attaching a filter to it.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/rtp_correlator_resources/' + rtp_id + '/enable', args, False)

    def getRtp(self, rtp_id):
        """ getRtp :
        Fetch the properties of a RTP Correlator resource object.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/rtp_correlator_resources/' + rtp_id)

    def getAllRtps(self):
        """ getAllRtps :
        Fetch a list containing the summaries for all the RTP Correlator resources in the system.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/rtp_correlator_resources')

    def searchRtp(self, args):
        """ searchRtp :
        Search for a specific RTP Correlator resource in the system by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/rtp_correlator_resources/search', args)

    def modifyRtp(self, rtp_id, args):
        """ modifyRtp :
        Update the properties of an existing RTP Correlator resource.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/rtp_correlator_resources/' + rtp_id, args, False)

    ###################################################
    # SIP Correlator Resources
    ###################################################
    def addSipWhiteListEntries(self, sip_id, args):
        """ addSipWhiteListEntries :
        Adds the entries sent in the 'whitelist' parameter as an array of Strings.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/sip_correlator_resources/' + sip_id + '/whiteList', args, False)

    def clearSipWhiteList(self, sip_id):
        """ clearSipWhiteList :
        Delete all the White List entries.
        Sample usage:
        """
        args = {}
        return self._sendRequest('DELETE', '/api/sip_correlator_resources/' + sip_id + '/clear', args, False)

    def deleteSipWhiteListEntries(self, sip_id, args):
        """ deleteSipWhiteListEntries :
        Deletes the entries sent in the 'whitelist' parameter as an array of Strings.
        Sample usage:
        """
        return self._sendRequest('DELETE', '/api/sip_correlator_resources/' + sip_id + '/whiteList', args, False)

    def disableSip(self, sip_id, args):
        """ disableSip :
        Detaches an SIP resource by disconnecting from the attached filter.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/sip_correlator_resources/' + sip_id + '/disable', args, False)

    def enableRtp(self, sip_id, args):
        """ enableRtp :
        Enables an RTP resource by attaching a filter to it.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/sip_correlator_resources/' + sip_id + '/enable', args, False)

    def exportSipWhiteListEntries(self, sip_id):
        """ exportSipWhiteListEntries :
        Exports WhiteList entries to a CSV. Each one will be on a separate line.
        Sample usage:
        """
        args = {}
        return self._sendRequest('POST', '/api/sip_correlator_resources/' + sip_id + '/exportWhiteList', args, False)

    def getSip(self, sip_id):
        """ getSip :
        Fetch the properties of a SIP Correlator resource object.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/sip_correlator_resources/' + sip_id)

    def importSipWhiteListEntries(self, sip_id, args):
        """ import_cfg :
        Imports White List entries from CSV. Each one should be on a separate line.
        Sample usage:
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']
            del args['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        buffer = bytearray()

        # Set param
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="param"\r\n')
        buffer.extend(b'Content-Type: application/json\r\n')
        buffer.extend(b'\r\n')
        buffer.extend(bytearray(json.dumps(args), 'ascii'))
        buffer.extend(b'\r\n')

        # Set creative contents part.
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="file"; filename=' + bytearray(file_name, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Type: application/octet-stream\r\n')
        buffer.extend(b'\r\n')
        # TODO: catch errors with opening file.
        buffer.extend(open(file_name, 'rb').read())
        buffer.extend(b'\r\n')

        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')
        buffer.extend(b'\r\n')

        hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
        response = self.connection.urlopen('POST', '/api/sip_correlator_resources/' + sip_id + '/importWhiteList', body=buffer, headers=hdrs)
        #self._log (response.status, response.reason)
        data = response.data

        return data

    def getAllSips(self):
        """ getAllSips :
        Fetch a list containing the summaries for all the SIP Correlator resources in the system.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/sip_correlator_resources')

    def retrieveSipWhitelistChunk(self, sip_id, args):
        """ retrieveSipWhitelistChunk :
        Retrieve a White List chunk using the 'start' parameter as the starting index. If that
        value exceeds the size of the White List, an empty array will be returned.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/sip_correlator_resources/' + sip_id + '/chunk', args, False)

    def retrieveSipFilteredWhitelistChunk(self, sip_id, args):
        """ retrieveSipFilteredWhitelistChunk :
        Retrieve a White List chunk using the 'start' parameter as the starting index and
        the 'filter' parameter as a RegExp pattern to filter the entries. If the 'start'
        parameter value exceeds the size of the White List, an empty array will be returned.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/sip_correlator_resources/' + sip_id + '/filter', args, False)

    def searchSip(self, args):
        """ searchSip :
        Search for a specific SIP Correlator resource in the system by certain properties.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/sip_correlator_resources/search', args)

    def modifySip(self, sip_id, args):
        """ modifySip :
        Update the properties of an existing SIP Correlator resource.
        Sample usage:
        """
        return self._sendRequest('PUT', '/api/sip_correlator_resources/' + sip_id, args, False)

    ###################################################
    # Recirculated AFM resources
    ###################################################
    def disableAfm(self, afm_id, args):
        """ disableAfm :
        Disables an recirculated AFM by disconnecting the attached port, port group or filter.
        Sample usage:
        >>> nto.disableAfm('96', {'object_id': '53'})
        ''
        """
        return self._sendRequest('PUT', '/api/recirculated_afm_resources/' + afm_id + '/disable', args, False)

    def enableAfm(self, afm_id, args):
        """ enableAfm :
        Enables an recirculated AFM by attaching a port, port group or filter to it.
        Sample usage:
        >>> nto.enableAfm('96', {'allocated_bandwidth': 10, 'object_id': '53', 'port_mode': 'NETWORK'})
        ''
        """
        return self._sendRequest('PUT', '/api/recirculated_afm_resources/' + afm_id + '/enable', args, False)

    def getBandwidthDetailsAfm(self, afm_id):
        """ getBandwidthDetailsAfm :
        Gets the bandwidth details for the Recirculated AFM resource.
        Sample usage:
        >>> nto.getBandwidthDetailsAfm('96')
        {u'allocated_bandwidth': 20, u'total_bandwidth': 160, u'available_bandwidth': 140, u'bandwidth_increment': 10}
        """
        return self._sendRequest('PUT', '/api/recirculated_afm_resources/' + afm_id + '/get_bandwidth_details', {})

    def getAfm(self, afm_id):
        """ getAfm :
        Fetch the properties of a recirculated AFM object.
        Sample usage:
        >>> nto.getAfm('96')
        {u'description': u'AFM Resources', u'lane_config_list': [{u'allocated_bandwidth': 10, u'attachment_id': u'52', u'attachment_type': u'PORT'}, {u'allocated_bandwidth': 10, u'attachment_id': u'53', u'attachment_type': u'PORT'}], u'capture_source': None, u'lineboard_id': None, u'default_name': u'L1-AFM', u'resource_status': u'READY', u'name': u'L1-AFM', u'mod_count': 20, u'license_status': u'NOT_PRESENT', u'capture_port_group': None, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'id': 96, u'connect_disconnect_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'history': [{u'type': u'MODIFY', u'time': 1497393506254, u'caused_by': u'admin', u'details': None, u'props': [u'DESCRIPTION']}]}
        >>> nto.getAfm('L1-AFM')
        {u'description': u'AFM Resources', u'lane_config_list': [{u'allocated_bandwidth': 10, u'attachment_id': u'52', u'attachment_type': u'PORT'}, {u'allocated_bandwidth': 10, u'attachment_id': u'53', u'attachment_type': u'PORT'}], u'capture_source': None, u'lineboard_id': None, u'default_name': u'L1-AFM', u'resource_status': u'READY', u'name': u'L1-AFM', u'mod_count': 20, u'license_status': u'NOT_PRESENT', u'capture_port_group': None, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'id': 96, u'connect_disconnect_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'history': [{u'type': u'MODIFY', u'time': 1497393506254, u'caused_by': u'admin', u'details': None, u'props': [u'DESCRIPTION']}]}
        """
        return self._sendRequest('GET', '/api/recirculated_afm_resources/' + afm_id)

    def getAllAfms(self):
        """ getAllAfms :
        Fetch a list containing the summaries for all the recirculated AFM resources in the system.
        Sample usage:
        >>> nto.getAllAfms()
        [{u'id': 96, u'name': u'L1-AFM'}]
        """
        return self._sendRequest('GET', '/api/recirculated_afm_resources')

    def searchAfm(self, args):
        """ searchAfm :
        Search for a specific recirculated AFM resource in the system by certain properties.
        Sample usage:
        >>> nto.searchAfm({'description': 'AFM Resources'})
        [{u'id': 96, u'name': u'L1-AFM'}]
        """
        return self._sendRequest('POST', '/api/recirculated_afm_resources/search', args)

    def modifyAfm(self, afm_id, args):
        """ modifyAfm:
        Update the properties of an existing recirculated AFM resource.
        Sample usage:
        >>> nto.modifyAfm('96', {'description': 'Shared AFM Resources'})
        ''
        """
        return self._sendRequest('PUT', '/api/recirculated_afm_resources/' + afm_id, args, False)

    ####################################
    # Statistics
    ####################################
    def getStats(self, args):
        """ getStats :
        Retrieve a stats snapshot containing the specified objects.
        Sample usage:
        >>> nto.getStats({'stat_name': ['np_peak_gtp_v2_deleted_sessions_time', 'np_total_rx_count_valid_packets'], 'port_group': '91'})
        {u'stats_snapshot': [{u'np_peak_gtp_v2_deleted_sessions_time': 1441391232493, u'reset_by': u'null', u'reset_time': 1441390286194, u'default_name': u'PG1', u'stats_time': 1441391232493, u'np_total_rx_count_valid_packets': 0, u'type': u'Port Group', u'id': u'91'}]}
        """
        return self._sendRequest('POST', '/api/stats', args)

    def resetStats(self, args):
        """ resetStats :
        Reset the stats for a set of specific NTO ports, port groups, and/or filters.
        Sample usage:
        >>> nto.resetStats({'PORT': [59], 'PORT_GROUP': [405]})
        {}
        """
        return self._sendRequest('POST', '/api/stats/reset', args)

    def getManagementStats(self):
        """ getManagementStats :
        Returns the statistics for active management port.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/stats/mgmt_port', None)

    def resetDrops(self, args):
        """ resetDrops :
        Reset the overflow drop counts for a set of specific NTO tool ports and/or output port groups.
        Sample usage:
        >>> nto.resetDrops({'PORT': [58]})
        {u'reset_drops_attempt_count': 134, u'reset_drops_success_count': 118}
        """
        return self._sendRequest('POST', '/api/stats/reset_drops', args)

    ####################################
    # System
    ####################################
    def getSpecificSystem(self, system_id):
        """ getSpecificSystem :
        Retrieve the properties of the system specified.
        Sample usage:
        """
        return self._sendRequest('GET', '/api/system/' + system_id)

    def getSystem(self, properties=None):
        """ getSystem :
        Retrieve the properties of the system.
        Sample usage:
        >>> nto.getSystem()
        {u'mgmt_port2_link_status': {u'duplex': u'FULL', u'active_port': False, u'speed': u'1G', u'link_up': True}, u'union_mode': u'INDEPENDENT', u'timestamp_config': {u'time_source': u'LOCAL'}, u'fan_failure_count': 0, u'web_api_config': {u'enabled': True, u'port': 9000, u'token_timeout': {u'value': 10, u'unit': u'MIN'}}, u'session_timeout_interval': 0,
            <snip>
        """
        query = ""
        if properties:
            query = '?properties=' + ''.join(properties.split())

        return self._sendRequest('GET', '/api/system' + query)

    def getSystemProperty(self, property):
        """ getSystemProperty :
        Fetch a systen property.
        Sample usage:
        >>> nto.getSystemProperty('snmp_config')
        {u'trap_recipients': [{u'remote_user': None, u'traps': [u'COLD_START', u'WARM_START', u'LINK_UP_DOWN', u'TEST_NOTIFICATION'], u'retry_count': 1, u'host': {u'value': u'155.174.7.97'}, u'version': u'V2', u'community_string': u'V2/155.174.7.97:162', u'timeout': 5, u'port': 162}], u'refresh_time': 1, u'gets_enabled': True, u'traps_enabled': True, u'get_access': [{u'version': u'V2', u'community_string': u'AnueComm4ATSro', u'local_user': None}]}
        """
        return self.getSystem(property)[property]
        #return self._sendRequest('GET', '/api/system?properties=' + property)[property]

    def getSystemProperties(self, properties):
        """ getSystemProperties :
        Fetch one or more systen properties.
        Sample usage:
        >>> nto.getSystemProperties('snmp_config,dns_config')
        {u'dns_config': {u'suffix1': None, u'suffix2': None, u'primary_server': None, u'alt_server': None}, u'snmp_config': {u'trap_recipients': [{u'remote_user': None, u'traps': [u'COLD_START', u'WARM_START', u'LINK_UP_DOWN', u'TEST_NOTIFICATION'], u'retry_count': 1, u'host': {u'value': u'155.174.7.97'}, u'version': u'V2', u'community_string': u'V2/155.174.7.97:162', u'timeout': 5, u'port': 162}], u'refresh_time': 1, u'gets_enabled': True, u'traps_enabled': True, u'get_access': [{u'version': u'V2', u'community_string': u'AnueComm4ATSro', u'local_user': None}]}}
        """
        return self.getSystem(properties)
        #return self._sendRequest('GET', '/api/system?properties=' + properties)

    def modifySystem(self, args):
        """ modifySystem :
        Update the system properties.
        Sample usage:
        >>> nto.modifySystem({'system_info': {u'location': 'Austin', u'name': 'The Big Box'}})
        ''
        """
        return self._sendRequest('PUT', '/api/system', args, False)

    def modifySpecificSystem(self, system_id, args):
        """ modifySpecificSystem :
        Update the properties of the system specified.
        Sample usage:
        >>> nto.modifySystem({'system_info': {u'location': 'Austin', u'name': 'The Big Box'}})
        ''
        """
        return self._sendRequest('PUT', '/api/system/' + system_id, args, False)

    ####################################
    # Tool Connectors
    ####################################
    def createInlineToolConnector(self, args):
        """ createInlineToolConnector :
        Create a new Inline Tool Connector in the system.
        Sample usage:
        >>> nto.createInlineToolConnector({'assigned_status': 'ACTIVE', 'description': 'Tool Connector', 'name': 'Test Tool Connector', 'side_a_port': 17, 'side_b_port': 18, 'sync_current_status': True})
        {'default_name': 'ITC1', 'id': 104, 'name': 'Test Tool Connector'}
        """
        return self._sendRequest('POST', '/api/tool_connectors', args)

    def deleteInlineToolConnector(self, tool_connector_id):
        """ deleteInlineToolConnector :
        Remove an existing inline Tool Connector from the system.
        Sample usage:
        >>> nto.deleteInlineToolConnector('101')
        b''
        """
        return self._sendRequest('DELETE', '/api/tool_connectors/' + tool_connector_id, None, False)

    def getInlineToolConnector(self, tool_conector_id):
        """ getInlineToolConnector :
        Fetch the properties of an Inline Tool Connector.
        To request only select properties (partial response), append to the URL the query parameter
        '?properties=value', where value is comma-separated list to select multiple fields for example:
        /api/resource_type/{object-id}?properties=description,name.
        Query Parameter is optional, see section Partial get under Usage Examples.
        Sample usage:
        >>> nto.getInlineToolConnector('101')
        {'assigned_status': 'ACTIVE', 'created': {'caused_by': 'admin', 'details': None, 'time': 1605729055930, 'type': 'CREATE'}, 'current_status': 'ACTIVE', 'default_name': 'ITC1', 'description': 'Tool Connector', 'history': None, 'id': 101, 'mod_count': 0, 'name': 'Test Tool Connector', 'side_a_port': 10, 'side_a_port_group': None, 'side_b_port': 11, 'side_b_port_group': None, 'sync_current_status': True, 'tool_resource_list': []}
        """
        return self._sendRequest('GET', '/api/tool_connectors/' + tool_conector_id)

    def getAllInlineToolConnectors(self):
        """ getAllInlineToolConnectors :
        Fetch a list containing the summaries for all the Inline Tool Connectors in the system.
        Sample usage:
        >>> nto.getAllInlineToolConnectors()
        [{'id': 101, 'name': 'Test Tool Connector'}]
        """
        return self._sendRequest('GET', '/api/tool_connectors')

    def searchInlineToolConnectors(self, args):
        """ searchnlineToolConnectors :
        Search for a specific Inline Tool Connector in the system by certain properties.
        Sample usage:
        >>> nto.searchInlineToolConnectors({'assigned_status': 'ACTIVE'})
        [{'assigned_status': 'ACTIVE', 'created': {'caused_by': 'admin', 'details': None, 'time': 1605729055930, 'type': 'CREATE'}, 'current_status': 'ACTIVE', 'default_name': 'ITC1', 'description': 'Tool Connector', 'history': None, 'id': 101, 'mod_count': 0, 'name': 'Test Tool Connector', 'side_a_port': 10, 'side_a_port_group': None, 'side_b_port': 11, 'side_b_port_group': None, 'sync_current_status': True, 'tool_resource_list': []}]
        """
        return self._sendRequest('POST', '/api/tool_connectors/search', args)

    def modifyInlineToolConnector(self, tool_conector_id, args):
        """ modifyInlineToolConnector :
        Update the properties of an existing Inline Tool Connector.
        Sample usage:
        >>> nto.modifyInlineToolConnector('101', {'description': 'new'})
        b''
        """
        return self._sendRequest('PUT', '/api/tool_connectors/' + tool_conector_id, args, False)

    ####################################
    # Tool Resources
    ####################################
    def createInlineToolResource(self, args):
        """ createInlineToolResource :
        Create a new inline tool resource in the system.
        Sample usage:
        >>> nto.createInlineToolResource({"name": "test resource", "tool_connector_list": [{"assigned_status": "ACTIVE", "description": "test resource descr", "name": "test connector", "side_a_port": 10, "side_b_port": 11, "sync_current_status": True}]})
        {'default_name': 'ITR1', 'id': 109, 'name': 'test resource'}
        """
        return self._sendRequest('POST', '/api/tool_resources', args)

    def deleteInlineToolResource(self, tool_resource_id):
        """ deleteInlineToolConnector :
        Remove an existing inline tool resource from the system.
        Sample usage:
        >>> nto.deleteInlineToolResource('New Name')
        b''
        """
        return self._sendRequest('DELETE', '/api/tool_resources/' + tool_resource_id, None, False)

    def getInlineToolResource(self, tool_resource_id):
        """ getInlineToolConnector :
        Fetch the properties of a inline tool resource object.
        To request only select properties (partial response), append to the URL the query
        parameter '?properties=value', where value is comma-separated list to select multiple
        fields for example:
        /api/resource_type/{object-id}?properties=description,name.
        Query Parameter is optional, see section Partial get under Usage Examples.
        Sample usage:
        >>> nto.getInlineToolResource('109')
        {'alert_type': 'NO_ALERT', 'created': {'caused_by': 'admin', 'details': None, 'time': 1605730117523, 'type': 'CREATE'}, 'default_name': 'ITR1', 'description': None, 'heartbeat_id': None, 'history': None, 'id': 109, 'ignore_mod_count': True, 'inline_service_chain_priority_list': [], 'is_mac_reversed_rhb': False, 'misc': {'access_map': {'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'10': 'Allow All', '11': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P08, P09: Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS']}, 'mod_count': 0, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'test resource', 'negative_heartbeat_id': None, 'state': 'ACTIVE', 'tool_connector_list': [{'assigned_status': 'ACTIVE', 'connector_type': 'TOOL_CONNECTOR', 'current_status': 'ACTIVE', 'name': 'test connector', 'side_a_port': '10', 'side_b_port': '11', 'sync_current_status': True}]}
        """
        return self._sendRequest('GET', '/api/tool_resources/' + tool_resource_id)

    def getAllInlineToolResources(self):
        """ getAllInlineToolResources :
        Fetch a list containing the summaries for all the inline tool resources in the system.
        Sample usage:
        >>> nto.getAllInlineToolResources()
        [{'id': 109, 'name': 'test resource'}]
        """
        return self._sendRequest('GET', '/api/tool_resources')

    def searchInlineToolResources(self, args):
        """ searchInlineToolResources :
        Search for a specific inline tool resource in the system by certain properties.
        Sample usage:
        >>> nto.searchInlineToolResources({'heartbeat_id': None})
        [{'alert_type': 'NO_ALERT', 'created': {'caused_by': 'admin', 'details': None, 'time': 1605730117523, 'type': 'CREATE'}, 'default_name': 'ITR1', 'description': None, 'heartbeat_id': None, 'history': None, 'id': 109, 'ignore_mod_count': True, 'inline_service_chain_priority_list': [], 'is_mac_reversed_rhb': False, 'misc': {'access_map': {'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'10': 'Allow All', '11': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P08, P09: Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS']}, 'mod_count': 0, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'test resource', 'negative_heartbeat_id': None, 'state': 'ACTIVE', 'tool_connector_list': [{'assigned_status': 'ACTIVE', 'connector_type': 'TOOL_CONNECTOR', 'current_status': 'ACTIVE', 'name': 'test connector', 'side_a_port': '10', 'side_b_port': '11', 'sync_current_status': True}]}]
        """
        return self._sendRequest('POST', '/api/tool_resources/search', args)

    def modifyInlineToolResource(self, tool_resource_id, args):
        """ modifyInlineToolConnector :
        Update the properties of an existing inline tool resource.
        Sample usage:
        >>> nto.modifyInlineToolResource('109', {'name': 'New Name'})
        b''
        """
        return self._sendRequest('PUT', '/api/tool_resources/' + tool_resource_id, args, False)

    ####################################
    # Users
    ####################################
    def getAllUsers(self):
        """ getAllUsers :
        Fetch a list containing the summaries for all the users in the system, or
        if a user ID is specified, fetch the properties of that user object.
        Sample usage:
        >>> nto.getAllUsers()
        [{u'id': 56, u'name': u'admin'}, {u'id': 52, u'name': u'tcl'}]
        """
        return self._sendRequest('GET', '/api/users')

    def getUser(self, user):
        """ getUser :
        Fetch a list containing the summaries for all the users in the system, or
        if a user ID is specified, fetch the properties of that user object.
        Sample usage:
        >>> nto.getUser('tcl')
        {u'login_id': u'tcl', u'session_type': None, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1442436968401}, u'is_sysadm': True, u'phone': u'867-53009', u'email': u'tcl@nto.com', u'mod_count': 0, u'is_logged_in': False, u'full_name': u'tcl', u'authentication_mode': u'LOCAL', u'id': 52, u'history': []}
        """
        return self._sendRequest('GET', '/api/users/' + user)

    def changePasswordUser(self, user_id, args):
        """ changePasswordUser :
        Change the user password.
        Sample usage:
        >>> nto.changePasswordUser('tcl1', {'new_password' : 'tcl1', 'old_password' : 'fredMota@123'})
        ''
        """
        return self._sendRequest('PUT', '/api/users/' + user_id + '/change_password', args, False)

    def createUser(self, args):
        """ createUser :
        Create a new user.
        Sample usage:
        >>> nto.createUser({'login_id': 'oper', 'is_sysadm': False, 'password': 'oper'})
        {u'id': u'54'}
        """
        return self._sendRequest('POST', '/api/users', args)

    def modifyUser(self, user_id, args):
        """ modifyUser :
        Update the properties of an existing user.
        Sample usage:
        >>> nto.modifyUser('oper', {'password': '***'})
        ''
        """
        return self._sendRequest('PUT', '/api/users/' + user_id, args, False)

    def deleteUser(self, user_id):
        """ deleteUser :
        Remove a user from the system. The user is specified by an user_id.
        Sample usage:
        >>> nto.deleteUser('54')
        ''
        """
        return self._sendRequest('DELETE', '/api/users/' + user_id, None, False)

    def searchUsers(self, args):
        """ searchUsers :
        Search a specific user from the system by certain properties.
        Sample usage:
        >>> nto.searchUsers({'is_sysadm': False})
        [{u'id': 54, u'name': u'oper'}]
        """
        return self._sendRequest('POST', '/api/users/search', args)

    ####################################
    # Search
    ####################################
    def search(self, entity_type, args):
        """ search :
        Search an entity.
        Sample usage:
        >>> nto.search('port_groups', {'mode': 'NETWORK'})
        [{u'id': 94, u'name': u'GSC Network Ports PB09-PB16'}, {u'id': 92, u'name': u'GSC Network Ports PB01-PB08'}, {u'id': 91, u'name': u'GSC Network Ports PA01-PA08'}, {u'id': 95, u'name': u'GSC Network Ports PA09-PA16'}]
        """
        return self._sendRequest('POST', '/api/' + entity_type + '/search', args)

    ###################################################
    # GSC Actions
    ###################################################
    def assignMirrorPortGroups(self, args):
        """ assignMirrorPortGroups :
        Assigns a new mirror port groups to a GSC session port group.
        The mirror port groups will receive a copy of the traffic
        that goes to the source port group.
        Sample usage:
        >>> gsc.assignMirrorPortGroups({'port_group_id': 92, 'port_group_id_list': [101]})
        {u'message': u'Mirror port groups assigned successfully.'}
        """
        return self._sendRequest('POST', '/api/actions/assign_gsc_mirror_port_groups', args)

    def changePortGroups(self, args):
        """ changePortGroups :
        Changes the port groups for a GSC port - one of three uses: - from a session
        port group to another session port group - from the non-session port group
        to a session port group - from a session port group to the non-session port
        group.
        Sample usage:
        >>> gsc.changePortGroups({'port_group_id': 92, 'port_id_list': [34]})
        {u'message': u'Port Group successfully changed'}
        """
        return self._sendRequest('POST', '/api/actions/change_port_group', args)

    def clearCriticalAlarm(self, args):
        """ clearCriticalAlarm :
        Clears a GSC critical alarm.
        Sample usage:
        >>> gsc.clearCriticalAlarm()
        """
        return self._sendRequest('POST', '/api/actions/clear_gsc_critical_alarm', args)

    def clearProbeFailedState(self, args):
        """ clearProbeFailedState :
        Clears the given probes failed state by setting their status to active.
        Sample usage:
        >>> gsc.clearProbeFailedState()
        """
        return self._sendRequest('POST', '/api/actions/clear_probe_failed_state', args)

    def clearSystemRecoveryAppliance(self):
        """ clearSystemRecoveryAppliance:
        Clear all system properties of the Recovery Appliance.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/clear_system_recovery_appliance', {})

    def connectRecoveryAppliance(self, args):
        """ connectRecoveryAppliance :
        Connect a GSC to a Recovery Appliance by providing the hostname and port.
        Sample usage:
        >>> gsc.connectRecoveryAppliance()
        """
        return self._sendRequest('POST', '/api/actions/connect_recovery_appliance', args)

    def createGscMirror(self, args):
        """ createGscMirror:
        Creates a new GSC mirror port group and to assign it to a session.
        Sample usage:
        >>> gsc.createGscMirror({'description': 'GSC Mirror PG', 'name': 'GSC Mirror', 'port_group_id': 92, 'port_id_list': [36, 37]})
        {u'message': u'New GSC mirror port group created successfully.'}
        """
        return self._sendRequest('POST', '/api/actions/create_new_gsc_mirror', args)

    def discardBackup(self):
        """ discardBackup:
        Clears the data of a backup of GSC info from the Recovery Appliance.
        This will cause a GSC restart.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/discard_backup', {})

    def disconnectRecoveryAppliance(self, args):
        """ disconnectRecoveryAppliance:
        Unpair and disconnect a GSC from a Recovery Appliance.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/disconnect_recovery_appliance', args)

    def exportRecoveryApplianceConfig(self, args):
        """ exportRecoveryApplianceConfiguration:
        Export Recovery Appliance configuration to a output file.
        Sample usage:
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest('POST', '/api/actions/export_recovery_appliance_config', args, False)
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def failover(self):
        """ failover:
        The Failover action is used by a probe to signal a failure.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/failover', {})

    def getProbeHeartbeat(self):
        """ getProbeHeartbeat:
        The Heartbeat action is used to receive the "alive" signal from probes.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/heartbeat', {})

    def importRecoveryApplianceConfig(self, args):
        """ importRecoveryApplianceConfig :
        Import Recovery Appliance configuration from an input file.
        Sample usage:
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']
            del args['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        buffer = bytearray()

        # Set param
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="param"\r\n')
        buffer.extend(b'Content-Type: application/json\r\n')
        buffer.extend(b'\r\n')
        buffer.extend(bytearray(json.dumps(args), 'ascii'))
        buffer.extend(b'\r\n')

        # Set creative contents part.
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="file"; filename=' + bytearray(file_name, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Type: application/octet-stream\r\n')
        buffer.extend(b'\r\n')
        # TODO: catch errors with opening file.
        buffer.extend(open(file_name, 'rb').read())
        buffer.extend(b'\r\n')

        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')
        buffer.extend(b'\r\n')

        hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
        response = self.connection.urlopen('POST', '/api/actions/import_recovery_appliance_config', body=buffer, headers=hdrs)
        #self._log (response.status, response.reason)
        data = response.data

        return data

    def installRecoveryApplianceSoftware(self, args):
        """ installRecoveryApplianceSoftware :
        Install software on Recovery Appliance.
        Sample usage:
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        buffer = bytearray()

        # Set creative contents part.
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="file"; filename=' + bytearray(file_name, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Type: application/octet-stream\r\n')
        buffer.extend(b'\r\n')
        # TODO: catch errors with opening file.
        buffer.extend(open(file_name, 'rb').read())
        buffer.extend(b'\r\n')

        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')
        buffer.extend(b'\r\n')

        hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
        response = self.connection.urlopen('POST', '/api/actions/install_appliance_software', body=buffer, headers=hdrs)
        #self._log (response.status, response.reason)
        data = response.data

        return data

    def pairRecoveryAppliance(self, args):
        """ pairRecoveryAppliance:
        Pair a GSC with a Recovery Appliance.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/pair_recovery_appliance', args)

    def recoverBackup(self):
        """ recoverBackup:
        Triggers a GSC restart, which will then start recovering the backup data from the Recovery Appliance.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/recover_backup', {})

    def relocatePortModuleLicenses(self, args):
        """ relocatePortModuleLicenses:
        Allocates the licenses for port modules as specified in the map.
        When licensed with FNE license, for port modules KAHANA_SFPP_16,
        MOKOLII_CX4, MOKOLII_SFPPLUS, MOKOLII_XFP and WAIKIKI_SFPPLUS
        the user can change the license allocation between modules.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/relocate_port_module_license', args)

    def resetPacketFragmentation(self, args):
        """ resetPacketFragmentation:
        Reset packet Fragmentation on one or more GSC network port groups.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/reset_packet_fragmentation', args)

    def restartRecoveryAppliance(self):
        """ restartRecoveryAppliance:
        Initiate a restart on the Recovery Appliance.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/restart_recovery_appliance', {})

    def searchSubscriberByFTeid(self, args):
        """ searchSubscriberByFTeid:
        Searches whether a given subscriber (that is identified by a TEID and an
        IPv4 or IPv6) has an active session and if so which port has been allocated
        to that subscriber's active session(s). If the given subscriber has an
        active session then it returns all the pairs of {source port groups,
        allocated tool port default name}.
        Sample usage:
        gsc.searchSubscriberByFTeid({'subscriber_ip': '10.10.10.10', 'subscriber_ip_type': 'IPv4', 'subscriber_teid': '12345678'})
        TBD
        """
        return self._sendRequest('POST', '/api/actions/search_subscriber_by_fteid', args)

    def searchSubscriberByImsi(self, args):
        """ searchSubscriberByImsi:
        Searches whether a given subscriber (that is identified by IMSI) has an
        active session and if so which port has been allocated to that
        subscriber's active session(s). If the given subscriber has an active
        session then it returns all the pairs of {source port groups, allocated
        tool port default name}.
        Sample usage:
        >>> gsc.searchSubscriberByImsi({'subscriber_imsi': '123456789012345'})
        {u'subscribers': [{u'subscriber_source_port_groups': [u'PG1', u'PG2', u'PG3', u'PG4'], u'subscriber_destination_tool_port': u'PC01'}]}
        """
        return self._sendRequest('POST', '/api/actions/search_subscriber_by_imsi', args)

    def shutdownRecoveryAppliance(self):
        """ shutdownRecoveryAppliance:
        Initiate a shutdown of the Recovery Appliance.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/shutdown_recovery_appliance', {})

    def startBackup(self):
        """ startBackup:
        Starts a backup of GSC info on the Recovery Appliance.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/start_backup', {})

    def stopMirroring(self, args):
        """ stopMirroring:
        Stops mirroring on a GSC session port group.
        Sample usage:
        >>> gsc.stopMirroring({'port_group_id': 100})
        {u'message': u'Stop GSC mirroring completed successfully.'}
        """
        return self._sendRequest('POST', '/api/actions/stop_gsc_mirroring', args)

    def stopBackup(self):
        """ stopBackup:
        Stops a backup of GSC info on the Recovery Appliance.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/stop_backup', {})

    def unpairRecoveryAppliance(self, args):
        """ unpairRecoveryAppliance:
        Pair a GSC with a Recovery Appliance.
        Sample usage:
        """
        return self._sendRequest('POST', '/api/actions/unpair_recovery_appliance', args)

    def getNtpServersStatus(self):
        """ getNtpServersStatus:
        Retrieve NTP servers status configured for the Recovery Appliance.
        Sample usage:
        >>> gsc.getNTPServersStatus()
       TBD
        """
        return self._sendRequest('GET', '/api/recovery_appliance/ntp_servers_status', {})

    def getNumberSessions(self):
        """ getNumberSessions:
        Retrieve the number sessions backed up in the Recovery Appliance.
        Sample usage:
        TBD
        """
        return self._sendRequest('GET', '/api/recovery_appliance/get_num_sessions', {})

    def getRecoveryApplianceProperties(self, args):
        """ getRecoveryApplianceProperties:
        Retrieve the properties of the Recovery Appliance.
        Sample usage:
        >>> gsc.getRecoveryApplianceProperties()
        TBD
        """
        return self._sendRequest('GET', '/api/recovery_appliance', args)

    def modifyRecoveryApplianceProperties(self, args):
        """ modifyRecoveryApplianceProperties:
        Update the properties of the Recovery Appliance.
        Sample usage:
        >>> gsc.modifyRecoveryApplianceProperties()
        TBD
        """
        return self._sendRequest('PUT', '/api/recovery_appliance', args)

    def createProbe(self, port_group, args):
        """ createProbe:
        Adds a probe to a port group.
        Sample usage:
        >>> gsc.createProbe('100', {'description': 'GRE Probe', 'ip_address': '10.218.20.20', 'is_redundant': False, 'name': 'RADCOM Probe', 'port_id_list': [36, 37]})
        {u'id': 1}
        """

        return self._sendRequest('POST', '/api/port_groups/' + port_group + '/probes', args)

    def deleteProbe(self, port_group, probe):
        """ deleteProbe:
        Delete a probe associated with a port group.
        Sample usage:
        gsc.deleteProbe('100', '1')
        """

        return self._sendRequest('DELETE', '/api/port_groups/' + port_group + '/probes/' + probe, None, False)

    def getAllProbes(self, port_group):
        """ getAllProbes:
        Retrieves all probes associated with a port group.
        Sample usage:
        >>> gsc.getAllProbes('100')
        [{u'is_redundant': False, u'description': u'GRE Probe', u'created_date_time': 1503632180163, u'last_modified_date_time': 1503632180163, u'is_active': True, u'created_by_user': u'admin', u'last_modified_by_user': u'admin', u'failed_over_to_probe_id': None, u'ip_address': u'10.218.20.20', u'id': 2, u'port_id_list': [36, 37], u'name': u'RADCOM Probe'}]
        """
        return self._sendRequest('GET', '/api/port_groups/' + port_group + '/probes', None)

    def getProbe(self, port_group, probe):
        """ getProbe:
        Retrieves a probe associated with a port group.
        Sample usage:
        >>> gsc.getProbe('100', '3')
        {u'is_redundant': False, u'description': u'GRE Probe', u'created_date_time': 1503632397617, u'last_modified_date_time': 1503632397617, u'is_active': False, u'created_by_user': u'admin', u'last_modified_by_user': u'admin', u'failed_over_to_probe_id': None, u'ip_address': u'10.218.20.20', u'id': 3, u'port_id_list': [36, 37], u'name': u'RADCOM Probe'}
        """
        return self._sendRequest('GET', '/api/port_groups/' + port_group + '/probes/' + probe, None)

    def modifyProbe(self, port_group, probe, args):
        """ modifyProbe:
        Updates a probe associated with a port group.
        Sample usage:
        >>> gsc.modifyProbe('100', '4', {'ip_address': '10.218.20.30'})
        ''
        """

        return self._sendRequest('PUT', '/api/port_groups/' + port_group + '/probes/' + probe, args, False)

    def getImsiCsvFile(self, filter_id, args):
        """ getImsiCsvFile :
        All IMSIs configured for the filter object is returned in a CSV file.
        The file is returned as an application/octet-stream.
        Sample usage:
        >>> gsc.getImsiCsvFile('F1', {'file_name': '/Users/fedemota/Desktop/IMSI-List1.csv'})
        """
        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest('GET', '/api/filters/' + filter_id + '/get_imsi_csv_file', args, False)
        f = open(file_name, 'w')
        f.write(file)
        f.close()

    def partiallyModifyFilter(self, filter_id, args):
        """ partiallyModifyFilter :
        Partially update properties of a filter.
        Sample usage:
        >>> gsc.partiallyModifyFilter('F1', {'gsc_session_filter_settings': {'imsi_list': ['************9**']}})
        ''
        OR
        >>> gsc.partiallyModifyFilter('F1', {'file_name': '/Users/fedemota/Desktop/IMSI-List.csv'})
        ''
        """
        if 'gsc_session_filter_settings' in args:
            args['gsc_session_filter_settings']['imsi_list'] = list(set(args['gsc_session_filter_settings']['imsi_list']))
            return self._sendRequest('PATCH', '/api/filters/' + filter_id, args, False)
        elif 'file_name' in args:
            file_name = args['file_name']

            boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

            buffer = bytearray()

            # Set creative contents part.
            buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
            buffer.extend(b'Content-Disposition: form-data; name="file"; filename=' + bytearray(file_name, 'ascii') + b'\r\n')
            buffer.extend(b'Content-Type: application/octet-stream\r\n')
            buffer.extend(b'\r\n')
            # TODO: catch errors with opening file.
            buffer.extend(open(file_name, 'r').read())
            buffer.extend(b'\r\n')

            buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')

            hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
            response = self.connection.urlopen('PATCH', '/api/filters/' + filter_id, body=buffer, headers=hdrs)
            #self._log (response.status, response.reason)
            data = response.data
            #data = json.loads(data.decode('ascii'))

            return data

    def partiallyDeleteFilter(self, filter_id, args):
        """ partiallyDeleteFilter :
        Partially delete a filter from the system.
        Sample usage:
        >>> gsc.partiallyDeleteFilter('F1', {'gsc_session_filter_settings': {'imsi_list': ['************9**']}})
        ''
        OR
        >>> gsc.partiallyDeleteFilter('F1', {'file_name': '/Users/fedemota/Desktop/IMSI-List.csv'})
        ''
        """
        if 'gsc_session_filter_settings' in args:
            args['gsc_session_filter_settings']['imsi_list'] = list(set(args['gsc_session_filter_settings']['imsi_list']))
            return self._sendRequest('DELETE', '/api/filters/' + filter_id, args, False)
        elif 'file_name' in args:
            file_name = args['file_name']

            boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

            buffer = bytearray()

            # Set creative contents part.
            buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
            buffer.extend(b'Content-Disposition: form-data; name="file"; filename=' + bytearray(file_name, 'ascii') + b'\r\n')
            buffer.extend(b'Content-Type: application/octet-stream\r\n')
            buffer.extend(b'\r\n')
            # TODO: catch errors with opening file.
            buffer.extend(open(file_name, 'r').read())
            buffer.extend(b'\r\n')

            buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'--\r\n')

            hdrs =  { 'Authentication' : self.token, 'Content-type' : 'multipart/form-data; boundary=' + boundary }
            response = self.connection.urlopen('DELETE', '/api/filters/' + filter_id, body=buffer, headers=hdrs)
            #self._log (response.status, response.reason)
            data = response.data
            #data = json.loads(data.decode('ascii'))

            return data

    ###################################################
    # GSC CPP Resources
    ###################################################
    def getAllGscFilters(self):
        """ getAllGscFilters :
        Fetch a list containing the summaries for all the filters in the system.
        Sample usage:
        >>> nto.getAllGscFilters()
        """
        return self._sendRequest('GET', '/api/gsc_filters')

    def getGscFilter(self, filter, properties=None):
        """ getGscFilter :
        Fetch the properties of a filter object.
        Sample usage:
        >>> nto.getGscFilter('461')
        {u'dynamic_filter_type': u'TWO_STAGE', u'connect_in_access_settings': {u'policy': u'INHERITED'}, u'dest_port_list': [], u'match_count_unit': u'PACKETS', u'description': None, u'resource_access_settings': {u'policy': u'INHERITED'}, u'created': None, u'modify_access_settings': {u'policy': u'INHERITED'}, u'default_name': u'F3', u'dest_port_group_list': [], u'name': u'Voice VLANs', u'mod_count': 6, u'snmp_tag': None, u'mode': u'PASS_BY_CRITERIA', u'criteria': {u'vlan': {u'priority': None, u'vlan_id': u'1000'}, u'logical_operation': u'AND'}, u'keywords': [], u'source_port_group_list': [], u'source_port_list': [410, 428], u'connect_out_access_settings': {u'policy': u'INHERITED'}, u'id': 461, u'history': [{u'type': u'MODIFY', u'time': 1442251734144, u'caused_by': u'internal', u'details': None, u'props': [u'SOURCE_PORT_LIST', u'DEST_PORT_LIST']}]}
        """
        query = ""
        if properties:
            query = '?properties=' + ''.join(properties.split())

        return self._sendRequest('GET', '/api/gsc_filters/' + filter + query)

    def createGscFilter(self, args, allowTemporayDataLoss=False):
        """ createGscFilter :
        Create a new filter in the system.
        Sample usage:
        >>> nto.createGscFilter({'source_port_list': ['218', '220'], 'dest_port_list': ['219'], 'mode': 'PASS_ALL'})
        {u'id': u'466'}
        """
        return self._sendRequest('POST', '/api/gsc_filters?allowTemporayDataLoss=' + str(allowTemporayDataLoss), args)

    def modifyGscFilter(self, filter_id, args, allowTemporayDataLoss=False):
        """ modifyGscFilter :
        Update the properties of an existing gsc filter.
        Sample usage:
        >>> nto.modifyFilter('F4', {'mode' : 'PASS_BY_CRITERIA', 'criteria' : {'logical_operation': 'AND', 'ipv4_session_flow': {'session_sets': [{'a_sessions': ['10.0.0.0/24:1', '12.0.0.0/24:1'], 'b_sessions': ['14.0.0.0/24:1', '16.0.0.0/24:1']}], 'flow_type': 'UNI'}}})
        ''
        """
        return self._sendRequest('PUT', '/api/gsc_filters/' + filter_id + '?allowTemporayDataLoss=' + str(allowTemporayDataLoss), args, False)

    def searchGscFilters(self, args):
        """ searchGscFilters :
        Search for a specific filter in the system by certain properties.
        Sample usage:
        >>> nto.searchFilters({'mode' : 'PASS_BY_CRITERIA'})
        [{u'id': 463, u'name': u'Syn Attack'}, {u'id': 465, u'name': u'Too Much Overhead'}, {u'id': 466, u'name': u'F8'}, {u'id': 55, u'name': u'F4'}, {u'id': 460, u'name': u'TCP, UDP, HTTP'}, {u'id': 462, u'name': u'ARP Storm'}, {u'id': 461, u'name': u'Voice VLANs'}]
        """
        return self._sendRequest('POST', '/api/gsc_filters/search', args)

    def deleteGscFilter(self, filter_id):
        """ deleteGscFilter :
        Remove a filter from the system.
        Sample usage:
        >>> nto.deleteGscFilter('F4')
        ''
        """
        return self._sendRequest('DELETE', '/api/gsc_filters/' + filter_id, None, False)

    def getGscFilterProperty(self, filter, property):
        """ getGscFilterProperty :
        Fetch a property of a filter object which is specified by its filter_id_or_name.
        Sample usage:
        >>> nto.getFilterProperty('F1', 'keywords')
        [u'TIME']
        """
        return self.getGscFilter(filter, property)[property]
        #return self._sendRequest('GET', '/api/filters/' + filter + '?properties=' + property)[property]

    def getGscFilterProperties(self, filter, properties):
        """ getGscFilterProperties :
        Fetch a list of properties of a filter object which is specified by its filter_id_or_name.
        Sample usage:
        >>> nto.getFilterProperties('F1', 'mode,name')
        {u'mode': u'PASS_ALL', u'name': u'L2-Resoure-Akamai'}
        """
        return self.getGscFilter(filter, properties)
        #return self._sendRequest('GET', '/api/filters/' + filter + '?properties=' + properties)

    ###################################################
    # GSC CPP Resource
    ###################################################
    def getAllGscCppResources(self):
        """ getAllGscCppResources :
        Fetch a list containing the summaries for all the ATIP resources in the system.
        Sample usage:
        >>> nto.getAllGscFilters()
        [{'id': 77, 'name': 'GSC1'}, {'id': 78, 'name': 'GSC2'}]
        """
        return self._sendRequest('GET', '/api/gsc_cpp_resources')

    def getGscCppResource(self, resource, properties=None):
        """ getGscCppResource :
        Fetch the properties of an ATIP resource.
        Sample usage:
        >>> nto.getGscFilter('77')
        {'channel_id': -1, 'created': {'caused_by': 'admin', 'details': None, 'time': 1617722510407, 'type': 'CREATE'}, 'default_name': 'GSC1', 'description': None, 'dest_port_group_list': [74], 'id': 77, 'misc': {'access_map': {}, 'access_props': []}, 'mod_count': 9, 'name': 'GSC1', 'number': 1, 'source_port_group_list': [75]}
        """
        query = ""
        if properties:
            query = '?properties=' + ''.join(properties.split())

        return self._sendRequest('GET', '/api/gsc_cpp_resources/' + resource + query)

    def modifyGscCppResource(self, resource_id, args, allowTemporayDataLoss=False):
        """ modifyGscFilter :
        Update the properties of an existing ATIP resource.
        Sample usage:
        >>> nto.modifyGscFilter('GSC3', {'description': 'The second GSC Session Filter'})
        b''
        """
        return self._sendRequest('PUT', '/api/gsc_filters/' + resource_id, args, False)

    def searchGscCppResources(self, args):
        """ searchGscCppResources :
        Search for a specific ATIP resource in the system by certain properties.
        Sample usage:
        >>> nto.searchGscFilters({'channel_id': 1})
        [{'channel_id': 1, 'created': {'caused_by': 'admin', 'details': None, 'time': 1618421128534, 'type': 'CREATE'}, 'default_name': 'GSC3', 'description': 'The second GSC Session Filter', 'dest_port_group_list': [76], 'id': 92, 'misc': {'access_map': {}, 'access_props': []}, 'mod_count': 1, 'name': 'GSC3', 'number': 3, 'source_port_group_list': [75]}]
        """
        return self._sendRequest('POST', '/api/gsc_cpp_resources/search', args)

    def getGscCppResourceProperty(self, resource, property):
        """ getGscFilterProperty :
        Fetch a property of a GSC CPP resource object which is specified by its resource_id_or_name.
        Sample usage:
        >>> nto.getGscFilterProperty('GSC3', 'channel_id')
        1
        """
        return self.getGscFilter(resource, property)[property]
        #return self._sendRequest('GET', '/api/gsc_cpp_resources/' + resource + '?properties=' + property)[property]

    def getGscFilterProperties(self, filter, properties):
        """ getGscFilterProperties :
        Fetch a list of properties of a GSC CPP resource object which is specified by its resource_id_or_name.
        Sample usage:
        >>> nto.getGscFilterProperties('GSC3', 'channel_id, description')
        {'channel_id': 1, 'description': 'The second GSC Session Filter'}
        """
        return self.getGscFilter(filter, properties)
        #return self._sendRequest('GET', '/api/gsc_cpp_resources/' + resource + '?properties=' + properties)

    ###################################################
    # GSC Filters
    ###################################################
    def getAllGscFilters(self):
        """ getAllGscFilters :
        Fetch a list containing the summaries for all the filters in the system.
        Sample usage:
        >>> nto.getAllGscFilters()
        [{'id': 77, 'name': 'GSC1'}, {'id': 78, 'name': 'GSC2'}]
        """
        return self._sendRequest('GET', '/api/gsc_filters')

    def getGscFilter(self, filter, properties=None):
        """ getGscFilter :
        Fetch the properties of a filter object.
        Sample usage:
        >>> nto.getGscFilter('77')
        {'channel_id': -1, 'created': {'caused_by': 'admin', 'details': None, 'time': 1617722510407, 'type': 'CREATE'}, 'default_name': 'GSC1', 'description': None, 'dest_port_group_list': [74], 'id': 77, 'misc': {'access_map': {}, 'access_props': []}, 'mod_count': 9, 'name': 'GSC1', 'number': 1, 'source_port_group_list': [75]}
        """
        query = ""
        if properties:
            query = '?properties=' + ''.join(properties.split())

        return self._sendRequest('GET', '/api/gsc_filters/' + filter + query)

    def createGscFilter(self, args, allowTemporayDataLoss=False):
        """ createGscFilter :
        Create a new filter in the system.
        Sample usage:
        >>> nto.createGscFilter({'dest_port_group_list': [76], 'source_port_group_list': [75]})
        {'channel_id': 1, 'default_name': 'GSC3', 'id': 92, 'name': 'GSC3'}
        """
        return self._sendRequest('POST', '/api/gsc_filters?allowTemporayDataLoss=' + str(allowTemporayDataLoss), args)

    def modifyGscFilter(self, filter_id, args, allowTemporayDataLoss=False):
        """ modifyGscFilter :
        Update the properties of an existing gsc filter.
        Sample usage:
        >>> nto.modifyGscFilter('GSC3', {'description': 'The second GSC Session Filter'})
        b''
        """
        return self._sendRequest('PUT', '/api/gsc_filters/' + filter_id + '?allowTemporayDataLoss=' + str(allowTemporayDataLoss), args, False)

    def searchGscFilters(self, args):
        """ searchGscFilters :
        Search for a specific filter in the system by certain properties.
        Sample usage:
        >>> nto.searchGscFilters({'channel_id': 1})
        [{'channel_id': 1, 'created': {'caused_by': 'admin', 'details': None, 'time': 1618421128534, 'type': 'CREATE'}, 'default_name': 'GSC3', 'description': 'The second GSC Session Filter', 'dest_port_group_list': [76], 'id': 92, 'misc': {'access_map': {}, 'access_props': []}, 'mod_count': 1, 'name': 'GSC3', 'number': 3, 'source_port_group_list': [75]}]
        """
        return self._sendRequest('POST', '/api/gsc_filters/search', args)

    def deleteGscFilter(self, filter_id):
        """ deleteGscFilter :
        Remove a filter from the system.
        Sample usage:
        >>> nto.deleteGscFilter('GSC3')
        Data=b'Not implemeted yet'
        """
        return self._sendRequest('DELETE', '/api/gsc_filters/' + filter_id, None, False)

    def getGscFilterProperty(self, filter, property):
        """ getGscFilterProperty :
        Fetch a property of a filter object which is specified by its filter_id_or_name.
        Sample usage:
        >>> nto.getGscFilterProperty('GSC3', 'channel_id')
        1
        """
        return self.getGscFilter(filter, property)[property]
        #return self._sendRequest('GET', '/api/gsc_filters/' + filter + '?properties=' + property)[property]

    def getGscFilterProperties(self, filter, properties):
        """ getGscFilterProperties :
        Fetch a list of properties of a filter object which is specified by its filter_id_or_name.
        Sample usage:
        >>> nto.getGscFilterProperties('GSC3', 'channel_id, description')
        {'channel_id': 1, 'description': 'The second GSC Session Filter'}
        """
        return self.getGscFilter(filter, properties)
        #return self._sendRequest('GET', '/api/gsc_filters/' + filter + '?properties=' + properties)
