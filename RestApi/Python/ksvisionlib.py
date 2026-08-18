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
# History:
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
# April 30, 2021
#    - Modified all the methods that had an ID parameter to convert it to a string
#    - Added all the methods for Netservice Settings
#    - Added all the methods for Netservices
#    - Added Vision NPB v5.8.0 Changes:
#        - Added method getNetserviceLicensedFeatures
#        - In SIP Correlator Resources, changed "White List" to "Allow List"
#
# May 3, 2021
#    - Fixed/renamed duplicated searchCtePortGroup to searchCtePorts
#    - Renamed searchCapture to searchCaptures
#    - Renamed searchAggregator to searchAggregators
#    - Renamed searchAtip to searchAtips
#    - Renamed searchAnalysisEngine to searchAnalysisEngines
#    - Renamed saveCteBufferCapture to saveCteBufferCaptures
#    - Renamed searchCteCapture to searchCteCaptures
#    - Renamed searchCteConnection to searchCteConnections
#    - Renamed searchCteFilter to searchCteFilters
#    - Renamed searchCteMember to searchCteMembers
#    - Renamed searchCteMonitor to searchCteMonitors
#    - Renamed searchCteNetflowResource to searchCteNetflowResources
#    - Renamed searchCtePortGroup to searchCtePortGroups
#    - Renamed searchIfcRoute to searchIfcRoutes
#    - Renamed searchCte to searchCtes
#    - Renamed searchIcon to searchIcons
#    - Renamed searchGscResource to searchGscResources
#    - Renamed searchGtpFdResource to searchGtpFdResources
#    - Renamed searchHeartbeat to searchHeartbeats
#    - Renamed searchLineBoard to searchLineBoards
#    - Renamed searchBoard to searchBoards
#    - Renamed searchNetserviceInstance to searchNetserviceInstances
#    - Renamed searchRtp to searchRtps
#    - Renamed searchSip to searchSips
#    - Renamed searchAfm to searchAfms
#    - Renamed searchSubscriberByFTeid to searchSubscribersByFTeid
#    - Renamed searchSubscriberByImsi to searchSubscribersByImsi
#
# June 11, 2021
#    - Added Vision NPB v5.8.1 Changes:
#        - Added method clearCtePort
#
# June 28, 2021
#    - Added the GSC filters configuration methods
#    - Added the GSC IMSI lists methods
#
# August 4, 2021
#    - Added Vision NPB v5.9.0 Changes:
#        - Added the IFC Dual Home Tools methods
#    - Added the getTradeVisionEvents method
#    - Added the getTradeVisionEventsValuesRanges method
#    - Fixed the installCteDtsp method
#    - Added the IFC custom icons methods
#
# November 8, 2021
#    - No changes for v5.9.1 and v5.10.0
#
# January 24, 2022
#    - No changes for v5.10.1
#    - Added the getLogs method
#
# April 6, 2022
#    - No changes for v5.11.0
#
# June 13, 2022
#    - Added Vision NPB v5.11.1 Changes:
#        - Added the downloadServerLog method
#        - Added the saveServerLogs method
#    - Added all the Analysis Engine (AE) resource methods.
#    - Renamed all the IFC Analysis Engine (AE) resource methods.
#      This will break existing scripts that use these methods.
#      Assuming these methods are not being used.
#
# June 23, 2022
#    - Added Vision NPB v5.12.0 Changes:
#        - Added the requestPortLicenseConfiguration method
#    - Added the resetEventRateLimiterStatus method
#    - Added the getFnoodLicensePublicInfo method
#    - Added the interruptAeTraffic method
#
# September 23, 2022
#    - Added Vision NPB v6.0.0 Changes:
#        - Added the createInternalLoopbackPort method
#        - Added the getOfflineToken method
#        - Added the getPodsStatus method
#        - Added the requestKvoCertificate method
#        - Added the requestLocalLicenseAvailability method
#        - Added the setKvoState method
#        - Added the setGlobalNetStackTunnelTermination method
#
# April 24, 2023
#    - Added Vision NPB v6.0.1 Changes:
#        - Added the setAfmLoadBalance method
#        - Added all the IFC Generic Netservice Resources methods
#        - Added all the IFC PacketStack resources methods
#    - Added Vision NPB v6.1.0 Changes:
#        - Added the getNetserviceConfig method
#        - Added the saveNetserviceConfig method
#        - Added the relearnAnalysisEngineMuxStreams method
#    - Added Vision NPB v6.1.1 Changes:
#        - Added method requestSystemLicenseCheckout
#    - Added Vision NPB v6.2.0 Changes:
#        - Added method getNetserviceConfigHashValue
#        - Added method requestLicenseUsageInfo
#
# September 12, 2023
#    - Added Vision NPB v6.3.1 Changes:
#        - Added the clearAaaUserLastLogin_info method
#        - Added the getPortListNeighbors method
#        - Added the getAggregatorResourceInternalInfo method
#        - Added all the FlowStack Resources methods
#        - Added the installDtsp method
#
# February 21, 2024
#    - Renamed clearAaaUserLastLogin_info to clearAaaUserLastLoginInfo
#    - Added Vision NPB v6.4.0 Changes:
#        - Added the clearPacketStackPlusDedupLiteHash method
#    - Added Vision NPB v6.5.0 Changes:
#        - Added the startPortCapture method
#        - Added the deletePortPcapFile method
#        - Added the downloadPortPcapFiles method
#        - Added the getPortPcapFileList method
#
# June 12, 2024
#    - Added support for IPv6, enclose IPv6 within "[]"
#    - Change verify default to False
#    - Added Vision NPB v6.6.0 Changes:
#        - Added the requestFanStatus method
#        - Added the requestPowerSupplyStatus method
#        - Added the backupGscConfigFromKvo method
#
# August 12, 2026
#    - Synchronized the Vision 7816 Web API coverage with Network Visibility
#      Software v6.10.0.
#    - Added missing Actions: getCertInfo, getSoftwareVersion,
#      installSoftwareFromFtp, and getLdapMultiCertificates.
#    - Added Cache stamp/update methods and the new v6.10.0 List details
#      methods for supported resources.
#    - Added missing Internal Filter, Internal Port Group, Internal Port,
#      Object Template Collection, Object Template, and IFC AppStack methods.
#    - Added missing object-template and writable-property methods for Filters,
#      Port Groups, Ports, IFC Analysis Engines, IFC Filters, IFC Port Groups,
#      and IFC Ports.
#    - Added missing IFC operations autoDetectCteChannels and setCteStackMode.
#    - Fixed Web API verb/path mismatches for management-port statistics,
#      resetStats, getCteCluster, searchIfcAnalysisEngines, CTE port-group
#      delete/disable, and Port PCAP download/list operations.
#    - Updated startPortCapture to pass the optional capture request body.
#    - Updated _sendRequest to safely return None for successful responses with
#      an empty body when JSON decoding is requested.
#

# August 12, 2026
#    - Synchronized Vision Edge 50 Web API coverage with Network Visibility
#      Software v6.10.0.
#    - Added method processKsmLicenseUpdates.
#
# August 12, 2026
#    - Synchronized Vision X Web API coverage with Network Visibility Software
#      v6.10.0.
#    - Added missing Vision X Actions, List details, internal-resource,
#      Netservice generic resource, and PassiveSSL resource methods.
#    - Corrected FlowStack, GSC resource, GSC CPP resource, and Netservice
#      instance Web API endpoint/verb mismatches.
#
# August 12, 2026
#    - Synchronized Vision One Web API coverage with Network Visibility Software
#      v6.10.0.
#    - Added Change QSFP Mode and Vision One RTP/SIP List details methods.
#    - Corrected the SIP enable wrapper name so it no longer overrides enableRtp.
#    - Allowed getNetserviceSettings() to be called without an unused argument.
#
# August 12, 2026
#    - Synchronized Vision Edge OS 9516 Web API coverage with Network Visibility
#      Software v6.10.0.
#    - Corrected createInternalLoopbackPort to accept and send the required
#      create_internal_loopback_port_req_spec request dictionary.
#
# August 12, 2026
#    - Synchronized Vision Edge OS 7712 Web API coverage with Network Visibility
#      Software v6.10.0.
#    - Corrected allowTemporaryDataLoss URL query handling in createFilter and
#      modifyFilter while accepting the legacy misspelled Python keyword.
#    - Added optional dual-mode side selection to getPort and modifyPort.
#    - Added optional toolUid and streamName query parameters to getStats.
#
# August 12, 2026
#    - Synchronized Vision Edge OS 5812 Web API coverage with Network Visibility
#      Software v6.10.0.
#    - Corrected setHaSyncPort to accept and send the required set_ha_sync_port
#      request dictionary containing the HA sync port.
#
# August 12, 2026
#    - Synchronized Vision Edge 400S Web API coverage with Network Visibility
#      Software v6.10.0.
#    - No functional wrapper changes were required; all documented Vision Edge
#      400S endpoints are already represented by the cumulative library.
#
# August 13, 2026
#    - Synchronized Vision Edge 400P Web API coverage with Network Visibility
#      Software v6.10.0.
#    - No functional wrapper changes were required; all documented Vision Edge
#      400P endpoints are already represented by the cumulative library.
#
# August 13, 2026
#    - Synchronized Vision Edge 100 Web API coverage with Network Visibility
#      Software v6.10.0.
#    - Corrected IFC Filter allowTemporaryDataLoss query handling for create,
#      delete, and update operations.
#    - Corrected getAggregatorResourceInternalInfo and getLogs to send their
#      documented request bodies.
#    - Corrected disableIfcPacketStack to accept and send the required detach
#      request body.
#    - Normalized IFC PacketStack and IFC Route collection GET paths to match
#      the documented URLs exactly.
#
# August 13, 2026
#    - Synchronized Vision Edge 40 Web API coverage with Network Visibility
#      Software v6.10.0.
#    - No functional wrapper changes were required; the Vision Edge 40 API is
#      an exact documented subset of the already-synchronized Vision Edge 100
#      API surface.
#

# August 13, 2026
#    - Synchronized Vision Edge 10S Web API coverage with Network Visibility
#      Software v6.10.0.
#    - Added all local Netflow resource methods: attach, detach, bandwidth
#      details, get, list, List details, search, and update.
#    - Confirmed existing PacketStack and Set Stack Mode wrappers match the
#      Vision Edge 10S guide.
#
# August 13, 2026
#    - Synchronized Vision 400 Web API coverage with Network Visibility Software
#      v6.10.0.
#    - Added FlowStack IP-list actions, Validate Bandwidth Option, missing AE
#      resource operations, and PacketStack Update Attachment.
#    - Corrected AE resource paths/request bodies, EOD report request handling,
#      and JSON decoding for createInternalLoopbackPort and
#      requestLocalLicenseAvailability.
#
# August 13, 2026
#    - Refactored Web API query parameters to use requests params= instead of
#      embedding query strings in endpoint paths.
#    - Replaced the decode boolean in _sendRequest with an explicit response_type
#      value: 'json', 'bytes', or 'none'.
#    - Response types for endpoints documented in the supplied v6.10.0 User
#      Guides follow the documented response; undocumented legacy endpoints
#      retain their previous decode behavior.
#
# August 13, 2026
#    - Added Platforms metadata to API wrapper docstrings.
#    - Methods whose endpoints could not be matched to any supplied Web API
#      User Guide are marked "UNMATCHED - likely deprecated" for easy search.
#
# August 13, 2026
#    - Synchronized the library with the supplied Network Visibility Software
#      v6.12.0 Web API User Guides.
#    - Added support for TradeVision, Vision 400XT, Vision Edge 400P Rev2,
#      and Vision X 400G platform-specific API documentation.
#    - Added v6.12 actions for trap messages, netcat, ping, traceroute,
#      finish-install-netservice, Query IMSI v2, wipe-all-netservice-data,
#      AE analytics clearing, and MobileStack auto-recovery alarm clearing.
#    - Updated Vision One SIP Allow List routes and added Allow List hash support.
#    - Refreshed Platforms metadata from the complete v6.12.0 guide set while
#      preserving historically documented platform coverage.
#
# COPYRIGHT 2019-2026 Keysight Technologies.
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

import sys
import requests
import re
import json
from contextlib import ExitStack

from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter, Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning

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

class webAPIInvalidSwError(webAPIError):
    """Exception raised for invalid software errors."""
    pass

class UnknownError(KeysightNpbExceptions):
    """Exception raised for unknown errors."""
    pass

class VisionWebApi(object):

    def __init__(self, host, username, password, port=8000, debug=False, log_file=None, timeout=10, retries=2, verify=False, version=None):
        if not verify:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.host = host
        self.port = port
        self.user = username
        self.password = password
        self.__debug = debug
        self.headers = {}
        self.version = version
        self.sw_major_version = None
        self.sw_minor_version = None
        self.session = requests.Session()
        self.log_file = log_file
        self.__request_timeout = timeout
        self.__request_retries = retries
        self.verify=verify

        self.authentication = HTTPBasicAuth(username, password)
        retry_strategy = Retry(
            total=retries,
            connect=retries,          # <- retry on connection failures (e.g., host unreachable/DNS)
            read=retries,             # <- retry on read timeouts
            status=retries,           # <- retry on certain HTTP statuses
            #backoff_factor=0.1,       # exponential backoff: 0.5, 1.0, 2.0, ...
            #status_forcelist=[429, 500, 502, 503, 504],
            #allowed_methods={"HEAD","GET","OPTIONS","POST","PUT","PATCH","DELETE"},
            #respect_retry_after_header=True
        )
        self.session.mount('https://', HTTPAdapter(max_retries=retry_strategy))

        # IPv6 addresses must be within "[]"
        self.ip_addr = self.host
        if ":" in self.ip_addr:
            self.ip_addr = f'[{self.ip_addr}]'

        try:
            response = self.session.get(f'https://{self.ip_addr}:{self.port}/auth', auth=self.authentication, verify=self.verify, timeout=timeout)
        except requests.exceptions.ConnectTimeout:
            raise ConnectionError
        except:
            raise UnknownError

        if self.__debug:
            self._log (f"Status={response.status_code}\n")
            self._log (f"Reason={response.reason}\n")
            self._log (f"Headers={response.headers}\n")
            self._log (f"Data={response.text}\n")

        try:
            self.token = response.headers['X-Auth-Token']
        except:
            raise AuthenticationError

        self.headers = {'Authentication' : self.token}
        #self.headers = {'Authentication' : self.token, 'Content-type' : 'application/json'}
        if self.version:
            self.headers.update({'Version': self.version})

    def __str__(self):
        return f"VisionWebApi(host={self.host}, port={self.port}, user={self.user}, password={self.password}, headers={self.headers}, debug={self.__debug}, log_file={self.log_file}, timeout={self.__request_timeout}, retries={self.__request_retries}, version={self.version})"

    def __repr__(self):
        return str(self)

    def _log(self, message):
        handle = open(self.log_file, 'a') if self.log_file else sys.stdout
        handle.write(message)
        if handle is not sys.stdout:
            handle.close()

    def _sendRequest(self, *, http_method, url, args=None, params=None, response_type='json', file_info=None):
        """ Send the request to the Web API server."""

        http_method = http_method.upper()
        if http_method not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'):
            raise ValueError(f"Unsupported HTTP method: {http_method}")

        if response_type not in ('json', 'bytes', 'none'):
            raise ValueError("response_type must be 'json', 'bytes', or 'none'")

        if self.__debug:
            self._log (f"Sending a message to the server with parameters:\n")
            self._log (f" http_method={http_method}\n")
            self._log (f" url={url}\n")
            self._log (f" params={params}\n")
            self._log (f" args={args}\n")
            self._log (f" files={file_info}\n")

        response = self.session.request(
            method = http_method,
            url = f'https://{self.ip_addr}:{self.port}{url}',
            timeout=self.__request_timeout,
            params=params,
            json=args,
            auth=self.authentication,
            headers=self.headers,
            verify=self.verify,
            files=file_info)

        if self.__debug:
            self._log (f"Response:\n")
            self._log (f" Status={response.status_code}\n")
            self._log (f" Reason={response.text}\n")
            self._log (f" Headers={response.headers}\n")
            #self._log (f" Data={response.content}\n")
            self._log (f" Response type={response_type}\n")

        if (response.status_code // 100 == 4):
            raise webAPIClientError(response.status_code)
        elif (response.status_code // 100 == 5):
            raise webAPIServerError(response.status_code)
        elif (response.status_code // 100 != 2):
            raise webAPIError(response.status_code)

        if response_type == 'json':
            return response.json() if response.content else None
        elif response_type == 'bytes':
            return response.content
        else:
            return None

    def _buildIdsParams(self, ids=None):
        """Build the optional ids query parameters used by List details endpoints."""
        if ids is None:
            return None
        if isinstance(ids, (list, tuple, set)):
            if not ids:
                return None
            ids = ','.join(str(item) for item in ids)
        return {'ids': str(ids)}

    def _set_sw_version(self):
        if self.sw_major_version is None or self.sw_minor_version is None:
            sw_version = self.getSystemProperty('software_version')
            #m = re.search("(\d+)\.(\d+)\.\d+\.\d+-\d+-\d+-[0-9a-f]+", sw_version.lower())
            m = re.search(r"^\D*(\d+)\.(\d+).*", sw_version.lower())
            if m != None:
                self.sw_major_version = int(m.group(1))
                self.sw_minor_version = int(m.group(2))
            else:
                raise webAPIInvalidSwError

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

    @property
    def request_retries(self):
        """ Get the request retries """
        return self.__request_retries

    @request_retries.setter
    def request_retries(self, retries):
        """ Set the request retries """
        self.__request_retries = retries
        retries = Retry(total = retries)
        #        backoff_factor=0.1,
        #        status_forcelist=[ 500, 502, 503, 504 ])
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

    def authenticate(self):
        """ authenticate :
        Athenticate with the NTO using username and password.
        Example:
        >>> nto.authenticate()
        """

        try:
            response = self.session.get(f'https://{self.ip_addr}:{self.port}/auth', auth=self.authentication, verify=self.verify)
        except requests.exceptions.ConnectTimeout:
            raise ConnectionError
        except:
            raise UnknownError

        if self.__debug:
            self._log (f"Status={response.status_code}\n")
            self._log (f"Reason={response.reason}\n")
            self._log (f"Headers={response.headers}\n")
            self._log (f"Data={response.text}\n")

        try:
            self.token = response.headers['X-Auth-Token']
        except:
            raise AuthenticationError

    #########################################################################
    # Web API endpoints -- sorted alphabetically by endpoint path
    #########################################################################

    # /actions

    def addAggregationSwitch(self):
        """ addAggregationSwitch :
        Adds a new Aggregation Switch to a Switch Cluster.
        
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/add_aggregation_switch', args=None, response_type='json')

    def assignMirrorPortGroups(self, args):
        """ assignMirrorPortGroups :
        Assigns a new mirror port groups to a GSC session port group.
        The mirror port groups will receive a copy of the traffic
        that goes to the source port group.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.assignMirrorPortGroups({'port_group_id': 92, 'port_group_id_list': [101]})
        {u'message': u'Mirror port groups assigned successfully.'}
        """
        return self._sendRequest(http_method='POST', url='/actions/assign_gsc_mirror_port_groups', args=args, response_type='json')

    def autoDetectChannels(self, args):
        """ autoDetectChannels :
        Allows Auto Detection of Channels per Analysis Engine.
        
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/auto_detect_channels', args=args, response_type='json')

    def backupGscConfig(self):
        """ backupGscConfig :
        Backup GSC configuration.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/backup_gsc_config', args={}, response_type='json')

    def certificateManagement(self, args):
        """ certificateManagement :
        Allows Syslog and TLS/HTTPS certificates to be uploaded and deleted. Basic
        information can also be viewed for certificates installed on the system.
        
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.certificateManagement({'action': 'VIEW', 'certificate_use': 'DEFAULT_TLS_HTTPS'})
        {u'authentication': [{u'valid_from': u'May 28, 2015 10:06:25 AM GMT', u'sha1_fingerprint': u'D3:75:74:30:D7:D8:50:FE:73:2F:10:E3:62:59:1B:EF:83:24:44:58', u'signature_algorithm': u'SHA256WITHRSA', u'valid_to': u'May 25, 2025 10:06:25 AM GMT', u'version': u'3', u'signature': u'12:B5:F1:75:7B:26:86:B2:C7:CE:A8:CE:74:CC:E8:82:8A:A3:45:45:AB:D3:DF:35:96:6A:50:61:F7:70:32:51:0A:03:5E:D1:14:1E:19:8E:ED:1A:E0:71:6E:CD:79:3C:67:70:F1:66:73:6C:1E:4F:97:97:94:79:25:D9:16:9C:B5:C7:E1:84:2A:A4:D6:FE:74:E7:E1:B5:B7:E0:32:0F:12:EA:A0:9C:62:75:D8:70:63:1B:C2:04:67:B9:33:5B:FE:9F:73:20:8B:AF:92:EA:6E:1A:61:B7:79:2A:AF:9E:50:EF:7D:7D:CE:DD:55:BD:20:E3:D7:C3:49:EB:A1:7D:B7:C8:89:43:19:13:59:4D:B6:2F:B9:22:8C:06:5C:4D:BB:8C:03:5B:45:B2:6D:DC:B5:4A:80:9A:14:32:2B:44:9D:CF:83:D8:E8:81:B8:77:94:2D:71:D0:54:ED:47:53:45:06:28:39:86:7D:EF:9D:3D:DC:BD:06:E0:BC:EF:62:AA:85:02:20:D7:E6:61:4E:12:81:04:9E:42:AA:40:18:4F:1B:3D:41:62:9B:E4:36:A9:F8:39:5F:60:2B:C1:83:5D:CF:FE:9F:3B:C0:FD:62:A7:D6:47:9E:C4:73:02:CA:C6:86:F5:7B:52:5B:E8:58:3B:23:57:3F:EE:2C:09:E2', u'serial_number': u'1165506059 (4578360b)', u'md5_fingerprint': u'57:7E:03:2E:2B:67:AA:E7:75:44:AA:21:5C:8F:BE:A1', u'subject': u'CN=Ixia, OU=Ixia, O=Ixia, L=Calabasas, ST=California, C=US', u'issuer': u'CN=Ixia, OU=Ixia, O=Ixia, L=Calabasas, ST=California, C=US'}]}
        """
        if 'action' in args:
            if (args['action'] == 'VIEW') or (args['action'] == 'DELETE'):
                return self._sendRequest(http_method='POST', url='/actions/certificates', args=args, response_type='json')

            elif args['action'] == 'UPLOAD':

                multipart_form_data = {}

                # TLS/HTTPS
                if 'authentication' in args:
                    multipart_form_data['authentication'] = (args['authentication'], open(args['authentication'], 'rb'))

                # Syslog - Client
                if 'client' in args:
                    multipart_form_data['client'] = (args['client'], open(args['client'], 'rb'))

                # Syslog - Trsuted Root
                if 'trusted_root' in args:
                    multipart_form_data['trusted_root'] = (args['trusted_root'], open(args['trusted_root'], 'rb'))

                return self._sendRequest(http_method='POST', url='/actions/certificates', args=args, file_info=multipart_form_data, response_type='json')

    def changeFilterPriority(self, args):
        """ changeFilterPriority :
        Allows changing the priority of connections between ports and port
        groups to out of band (i.e., non-inline) dynamic filters. To update
        the priority of inline filters, update the inline_service_chain_priority_list
        of the corresponding inline Bypass connector.
        This should only be used when the filter build mode is PRIORITY
        (see system memory_allocation property, filter_build_settings).
        This method is allowed only on the following models: Vision One, E40, E100
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/change_filter_priority', args=args, response_type='json')

    def changeOfflinePortSpeed(self, args):
        """ changeOfflinePortSpeed :
        This action will change the speed configuration of an offline port.
        Platforms:
            Vision Edge 50, Vision Edge OS 5812, Vision Edge OS 7712

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/change_offline_speed_configuration', args=args, response_type='json')

    def changePortAggregationMode(self, args):
        """ changePortAggregationMode :
        * This method was deleted in v4.7.5.
        Agregates four 10G ports into one 40G port and backward.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/change_port_aggregation_mode', args=args, response_type='none')

    def changePortGroups(self, args):
        """ changePortGroups :
        Changes the port groups for a GSC port - one of three uses: - from a session
        port group to another session port group - from the non-session port group
        to a session port group - from a session port group to the non-session port
        group.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.changePortGroups({'port_group_id': 92, 'port_id_list': [34]})
        {u'message': u'Port Group successfully changed'}
        """
        return self._sendRequest(http_method='POST', url='/actions/change_port_group', args=args, response_type='json')

    def changeQsfp28PortMode(self, args):
        """ changeQsfp28PortMode :
        Changes the QSFP mode of a QSFP28 port.
        * This method was deprecated in v4.8.0, and replaced with change_speed_configuration.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/change_qsfp28_port_mode', args=args, response_type='none')

    def changeQsfpMode(self):
        """ changeQsfpMode :
        This action will change the QSFP mode for a switch with a main board having QSFP ports.
        Platforms:
            TradeVision, Vision One

        """
        return self._sendRequest(http_method='POST', url='/actions/change_qsfp_mode', args=None, response_type='json')

    def changeRole(self):
        """ changeRole :
        This command changes role between supervisor and independent.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.changeRole()
        """
        return self._sendRequest(http_method='POST', url='/actions/change_role', args={}, response_type='json')

    def changePortSpeed(self, args):
        """ changePortSpeed :
        Changes the speed configuration of port.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        >>> nto.changePortSpeed({'port_list': [64], 'qsfp28_port_mode': 'MODE_QSFP'})
        '{}'
        """
        return self._sendRequest(http_method='POST', url='/actions/change_speed_configuration', args=args, response_type='json')

    def changeSpeedConfiguration(self, args):
        """ changeSpeedConfiguration :
        Changes the speed configuration of port.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/change_speed_configuration', args=args, response_type='json')

    def clearAaaUserLastLoginInfo(self):
        """ clearAaaUserLastLoginInfo :
        This action clears the data from aaa_user_last_login_info.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/clear_aaa_user_last_login_info', args=None, response_type='none')

    def clearAeChannelStatsHistory(self, args):
        """ clearAeChannelStatsHistory :
        Clears the Burst and/or Latency & Jitter Stats History Files from the Disk per AE.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/clear_ae_channel_statistics_history', args=args, response_type='json')

    def clearAggregationSwitch(self):
        """ clearAggregationSwitch :
        Clears the configuration of an aggregation switch.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/clear_aggregation_switch', args=None, response_type='json')

    def clearConfig(self):
        """ clearConfig :
        Clear the configuration by deleting all filters, regular users, groups,
        filter templates, filter template collections, port groups, and custom
        icons and by setting all ports to default values.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.clearConfig()
        {u'message': u'Configuration cleared.'}
        """
        return self._sendRequest(http_method='POST', url='/actions/clear_config', args={}, response_type='json')

    def clearFiltersAndPorts(self):
        """ clearFiltersAndPorts :
        This command deletes all filters and port groups and sets all ports to
        default values.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.clearFiltersAndPorts()
        {u'message': u'Filters and ports cleared.'}
        """
        return self._sendRequest(http_method='POST', url='/actions/clear_filters_and_ports', args={}, response_type='json')

    def clearCriticalAlarm(self, args):
        """ clearCriticalAlarm :
        Clears a GSC critical alarm.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.clearCriticalAlarm()
        """
        return self._sendRequest(http_method='POST', url='/actions/clear_gsc_critical_alarm', args=args, response_type='json')

    def clearFlowStackIpFlowsList(self):
        """ clearFlowStackIpFlowsList :
        Remove all entries from the FlowStack IP Flows List.
        Platforms:
            Vision 400, Vision 400XT

        """
        return self._sendRequest(http_method='POST', url='/actions/clear_ipflows_ip_list', response_type='json')

    def clearProbeFailedState(self, args):
        """ clearProbeFailedState :
        Clears the given probes failed state by setting their status to active.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.clearProbeFailedState()
        """
        return self._sendRequest(http_method='POST', url='/actions/clear_probe_failed_state', args=args, response_type='json')

    def clearPacketStackPlusDedupLiteHash(self):
        """ clearPacketStackPlusDedupLiteHash :
        This command clears the PacketStack Plus Dedup Lite hash tables.
        Platforms:
            Vision 400, Vision 400XT, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge
            OS 9516, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/clear_ps_plus_dedup_lite_hash', args={}, response_type='json')

    def clearSystem(self):
        """ clearSystem :
        This command clears the system and restores it to a default state, including
        resetting the admin account to default values. The license currently
        installed will not be removed.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.clearSystem()
        {u'message': u'System restored to default state.'}
        """
        return self._sendRequest(http_method='POST', url='/actions/clear_system', args={}, response_type='json')

    def clearSystemRecoveryAppliance(self):
        """ clearSystemRecoveryAppliance:
        Clear all system properties of the Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/clear_system_recovery_appliance', args={}, response_type='json')

    def connectRecoveryAppliance(self, args):
        """ connectRecoveryAppliance :
        Connect a GSC to a Recovery Appliance by providing the hostname and port.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.connectRecoveryAppliance()
        """
        return self._sendRequest(http_method='POST', url='/actions/connect_recovery_appliance', args=args, response_type='json')

    def createInternalLoopbackPort(self, args):
        """ createInternalLoopbackPort :
        Creates an Internal Loopback Port.
        The args dictionary must contain the create_internal_loopback_port_req_spec
        properties documented by the Web API (including num_ports and port_speed_mode).
        Platforms:
            Vision 400, Vision 400XT, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge
            OS 9516

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/create_internal_loopback_port', args=args, response_type='json')

    def createGscMirror(self, args):
        """ createGscMirror:
        Creates a new GSC mirror port group and to assign it to a session.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.createGscMirror({'description': 'GSC Mirror PG', 'name': 'GSC Mirror', 'port_group_id': 92, 'port_id_list': [36, 37]})
        {u'message': u'New GSC mirror port group created successfully.'}
        """
        return self._sendRequest(http_method='POST', url='/actions/create_new_gsc_mirror', args=args, response_type='json')

    def deployNetServiceInstance(self, args):
        """ deployNetServiceInstance :
        This command will deploy a netservice instance based on a default name.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/deploy_net_service_instance', args=args, response_type='json')

    def discardBackup(self):
        """ discardBackup:
        Clears the data of a backup of GSC info from the Recovery Appliance.
        This will cause a GSC restart.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/discard_backup', args={}, response_type='json')

    def disconnectRecoveryAppliance(self, args):
        """ disconnectRecoveryAppliance:
        Unpair and disconnect a GSC from a Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/disconnect_recovery_appliance', args=args, response_type='json')

    def downloadServerLog(self, args):
        """ downloadServerLog :
        Used to download a system log file that was previously created using SaveServerLogsAction
        for subsequent delivery to Keysight Support.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest(http_method='POST', url='/actions/download_server_log', args=args, response_type='bytes')
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def drainNetServiceInstance(self, args):
        """ drainNetServiceInstance :
        This command will drain a netservice instance based on a default name.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/drain_net_service_instance', args=args, response_type='json')

    def enableFipsServerEncryption(self):
        """ enableFipsServerEncryption :
        This commands causes FIPS encryption to be enabled on the server.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        *** TO BE TESTED ***
        >>> nto.enableFipsServerEncryption()
        """
        return self._sendRequest(http_method='POST', url='/actions/enable_fips_server_encryption', args={}, response_type='json')

    def exportConfig(self, args):
        """ exportConfig :
        Return configuration settings from an NTO to a file.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        nto.exportConfig({'boundary' : 'INCLUDE', 'description' : 'SNMP Config', 'export_type' : 'CUSTOM', 'file_name' : '/Users/fmota/Desktop/snmp+user.ata', 'user': None, 'system' : 'snmp_config'})
        """
        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest(http_method='POST', url='/actions/export', args=args, response_type='bytes')
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def exportFlowStackIpFlowsList(self):
        """ exportFlowStackIpFlowsList :
        Export the FlowStack IP Flows List and return the binary file content.
        Platforms:
            Vision 400, Vision 400XT

        """
        return self._sendRequest(http_method='POST', url='/actions/export_ipflows_ip_list', args=None, response_type='bytes')

    def exportKeyGenLicense(self, args):
        """ exportKeyGenLicense :
        Export the KeyGen license details to a json file that can be used
        on the migration portal to obtain a new style license for an NTO
        or an union.
        Platforms:
            GSC 7400, NTO 5200

        Example:
        >>> nto.exportKeyGenLicense({'file_name': 'mylicense'})
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest(http_method='POST', url='/actions/export_keygen_license_to_json', args=args, response_type='bytes')
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def exportOfflineLicenseActivationRequest(self, args):
        """ exportOfflineLicenseActivationRequest :
        Export the request file for FNOOD offline license activation for the current system.
        Platforms:
            Vision Edge OS 5812, Vision Edge OS 7712

        Example:
        *** TO BE TESTED ***
        """
        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest(http_method='POST', url='/actions/export_offline_license_request_file', args=args, response_type='bytes')
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def exportRecoveryApplianceConfig(self, args):
        """ exportRecoveryApplianceConfiguration:
        Export Recovery Appliance configuration to a output file.
        Platforms:
            GSC 7400

        Example:
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest(http_method='POST', url='/actions/export_recovery_appliance_config', args=args, response_type='bytes')
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def factoryReset(self):
        """ factoryReset :
        This command clears the system and restores it to a factory default
        state, including resetting the admin account to default values. The
        license currently installed will also be removed.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.factoryReset()
        """
        return self._sendRequest(http_method='POST', url='/actions/factory_reset', args={}, response_type='json')

    def failover(self):
        """ failover:
        The Failover action is used by a probe to signal a failure.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/failover', args={}, response_type='none')

    def fipsServerEncryptionStatus(self):
        """ fipsServerEncryptionStatus :
        This commands causes FIPS encryption to be enabled on the server.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        *** TO BE TESTED ***
        >>> nto.fipsServerEncryptionStatus()
        """
        return self._sendRequest(http_method='POST', url='/actions/fips_server_encryption_status', args={}, response_type='json')

    def finishInstallNetservice(self, args):
        """ finishInstallNetservice :
        Finish installation of a netservice upgrade after EULA confirmation.
        The v6.12.0 guide requires the JSON part containing the EULA confirmation status.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/finish_install_netservice', args=args, response_type='none')

    def forcePowerPortModule(self, args):
        """ forcePowerPortModule :
        This command will power on/off the port module in the given module location.
        This method is allowed only on the following models: 8000.
        Platforms:
            Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/force_power_port_module', args=args, response_type='json')

    def generateCsr(self, args):
        """ generateCsr :
        Allows Syslog and TLS/HTTPS certificates to be uploaded and deleted. Basic
        information can also be viewed for certificates installed on the system.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.generateCsr({'csr_use' : 'SYSLOG', 'tls_cert_request_info' : {'city' : 'Austin', 'common_name' : 'Test API', 'country' : 'US', 'organization' : 'Ixia', 'organization_unit' : 'NVS', 'state' : 'TX', 'subject_alt_name' : 'Anue'}})
        {u'csr': u'-----BEGIN CERTIFICATE REQUEST-----MIIC5zCCAc8CAQAwWzELMAkGA1UECBMCVFgxDzANBgNVBAcTBkF1c3RpbjELMAkGA1UEBhMCVVMxDDAKBgNVBAsTA05WUzENMAsGA1UEChMESXhpYTERMA8GA1UEAxMIVGVzdCBBUEkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4RNOnSPTRamGkAwj/otEgzAFYIEXlpsO4OS16P49l3c0n5ShDs0uo2pd4a0Qe4Wvh/KX4L1oZbxS/2YNJgNlLiRkHo5K62ZYYskfNGXPBYfkkRDLk76SrhgHyoGSEy8h6OdeE2QpfgsD/XLQVoFQ3dVemSwo76bE3Vap333fJmvtNJNgItkKqKBW3zF1doSWJwEHDwwhG9/KSfFBHf/qE51LRj2iybZQE4ijZGHv0I7CtSF20166sH75EhsoK8/vs1RT6LpyuEM9JKoRzmvE1ufk3nHtlvF3UniUluUCubXfldaEROIeBvYfoWZGGuyzAN01ZbxZ+/K2ENokpVKPbAgMBAAGgRzBFBgkqhkiG9w0BCQ4xODA2MA8GA1UdEQQIMAaCBEFudWUwDgYDVR0PAQH/BAQDAgUgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQAfVnwTv1t56YWU2W5+Fjlc9nuTL7eAoKqkioTJ1CuAINLybbHYUVXVfpBahfjj7g6ZmiWZ383SK7ImuPfHE7kt/eRDna+/+HUQ22799HQmyLcxCkYZVSH8gWkTNbUIhgh4AFMwt83zWu324P+qNkh5u0sckPTfNzry3Mxz2QzmM5sP+oU8/RCt04iYzz5KSu+tzHWJ9FOGLQqQ73Ausz0smTDFBlVLs8VCifHVc2QmSbIofHVPUOUEjWo+FFb6WK6/7NjgE4DM9rVDV7eW9WXZgos6WnXRVMIpedeibh31iM/sc63F0tQHXt696kfO19LBc6FLMKLCvVtkGfSnq5u9-----END CERTIFICATE REQUEST-----'}
        """
        return self._sendRequest(http_method='POST', url='/actions/generate_csr', args=args, response_type='json')

    def getEventsSummaryReport(self, args):
        """ getEventsSummaryReport :
        Return a End-Of-Day report by name or a comparison report between two different End-Of-Day reports.
        If report name is specified, event summary report is returned.
        If two report names are specified, a new report is generated holding the differences between the two EOD reports.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_ae_events_report_action', args=args, response_type='none')

    def getAeEventsReportHistory(self):
        """ getAeEventsReportHistory :
        Return either a list of the latest 8 End-Of-Day reports run on the system or a comparison between
        two different End-Of-Day reports. If no report dates are specified, the latest 8 End-Of-Day reports
        are returned (the maximum number of EOD reports retained by the system). If two dates are specified
        (representing the end date of two different EOD reports), a new report is generated holding the
        differences between the two EOD reports. Note that the end dates must be from any of the latest 8
        EOD reports run.
        
        TBD: Deprecated
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_ae_events_report_history_action', args={}, response_type='json')

    def getAllEodReportsInfo(self, args=None):
        """ getAllEodReportsInfo :
        Returns the list of all Eod events summary Report for all AEs in a TradeVision.
        TBD: Does it take args or not? ae_events_report_info_request es defined as {}
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        if args is None:
            args = {}
        return self._sendRequest(http_method='POST', url='/actions/get_ae_events_report_info', args=args, response_type='json')

    def getAeEventsSummaryReport(self, args):
        """ getAeEventsSummaryReport :
        Return events summary report for all the AEs in a TradeVision.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_ae_events_summary_report_action', args=args, response_type='none')

    def getAggregatorResourceInternalInfo(self, args):
        """ getAggregatorResourceInternalInfo :
        This command is used to get the internal information mapping of a resource.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_aggregator_resource_internal_info', args=args, response_type='json')

    def getAvailableFilterCriteria(self, args):
        """ getAvailableFilterCriteria :
        Return a list of filter criteria which can be used given an already
        present set of filter criteria.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.getAvailableFilterCriteria({'filter_object_type': 'FILTER'})
        []
        """
        return self._sendRequest(http_method='POST', url='/actions/get_available_filter_criteria', args=args, response_type='json')

    def getCertInfo(self):
        """ getCertInfo :
        Return information helpful for certificates.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/actions/get_cert_info', args={}, response_type='json')

    def getChannelBurstStats(self, args):
        """ getChannelBurstStats :
        This command is used to get the Channel Burst statisics for a given channel id and VLAN Match type per Analysis Engine.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_channel_burst_stats', args=args, response_type='json')

    def getChannelLatencyStats(self, args):
        """ getChannelLatencyStats :
        This command is used to get the latency/jitter statisics for a given channel id and VLAN Match type per Analysis Engine.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_channel_latency_stats', args=args, response_type='json')

    def getDtspChannelInfo(self, args):
        """ getDtspChannelInfo :
        This command is used to get the channel info based on a given list of channel IP:Port.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision Edge 400S

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_dtsp_channel_info', args=args, response_type='json')

    def getEarlyClassificationCriteria(self):
        """ getEarlyClassificationCriteria :
        Get a list of valid early classification criteria for Intersection filtering.
        This method is allowed only on the following models: 7816, 8000, E100.
        Platforms:
            Vision 7816, Vision Edge 100, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_early_classification_criteria', args={}, response_type='json')

    def getFabricPorts(self, args):
        """ getFabricPorts :
        Return fabric ports information for one or more members. This
        information can be used as input to the update_fabric_ports action.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.getFabricPorts()
        """
        return self._sendRequest(http_method='POST', url='/actions/get_fabric_ports', args=args, response_type='json')

    def getFnoodLicensePublicInfo(self):
        """ getFnoodLicensePublicInfo :
        Read the publicly available information about the installed FNOOD license for the current system.
        Platforms:
            Vision Edge OS 5812, Vision Edge OS 7712

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_fnood_license_public_info', args=None, response_type='json')

    def getHaCliConfig(self):
        """ getHaCliConfig :
        Returns the HA config needed by CLI.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_ha_config_for_cli', args={}, response_type='json')

    def getNetserviceConfigHashValue(self, args):
        """ getNetserviceConfigHashValue :
        This command is used to get the hash of a configuration from a netservice.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_hash_of_netservice_config', args=args, response_type='json')

    def getLfdLocalPorts(self):
        """ getLfdLocalPorts :
        Get a list of local ports valid for LFD.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_local_ports_valid_for_lfd', args={}, response_type='none')

    def getLoginInfo(self):
        """ getLoginInfo :
        Returns last login session details plus hardware info and sensor readings for the device
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
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
        return self._sendRequest(http_method='POST', url='/actions/get_login_info', args={}, response_type='json')

    def getMemoryMeters(self):
        """ getMemoryMeters :
        Return the filter memory meters showing memory allocation and percentage used.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.getMemoryMeters()
        [{u'unit_name': u'LC1', u'memory_meters': [{u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 89, u'avail_pcnt': 100, u'meter_name': u'FILTER_ETHERTYPE_VLAN_L3_L4'}, {u'alloc_pcnt': 89, u'avail_pcnt': 100, u'meter_name': u'FILTER_L2_L3_L4'}], u'memory_type': u'DYNAMIC_FILTER_NON_IP'}, {u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 50, u'avail_pcnt': 100, u'meter_name': u'DYNAMIC_SIP_IPV4'}, {u'alloc_pcnt': 50, u'avail_pcnt': 100, u'meter_name': u'DYNAMIC_DIP'}], u'memory_type': u'DYNAMIC_FILTER_IP'}, {u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 100, u'avail_pcnt': 100, u'meter_name': u'NETWORK_PORT_L2_L3_IPV4'}], u'memory_type': u'NETWORK_PORT_FILTER'}, {u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 100, u'avail_pcnt': 100, u'meter_name': u'TOOL_PORT_L2_L3_IPV4'}], u'memory_type': u'TOOL_PORT_FILTER'}]}, ...
        """
        return self._sendRequest(http_method='POST', url='/actions/get_memory_meters', args={}, response_type='json')

    def getMemoryMetersPreview(self, args):
        """ getMemoryMetersPreview :
        Accepts a memory allocation configuration and return what the filter memory
        meters would be for that allocation.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_memory_meters_preview', args=args, response_type='json')

    def getNeighborsV1(self, args=None):
        """ getNeighborsV1 :
        Call the original get_neighbors action. The Web API documents an empty response;
        use getNeighbors or getAllNeighbors for the v2 action that returns neighbor data.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_neighbors', args={} if args is None else args, response_type='none')

    def getAllNeighbors(self):
        """ getAllNeighbors :
        Fetch a list containing summaries for all the neigbors the system learned by snooping on LLDP messages.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        >>> nto.getAllNeighbors()
        {u'P50': [{u'system_name': u'Ixia Vision One (Neo10 project)', u'port_description': u'', u'system_description': u'', u'expired': False, u'age': 1, u'chassis_id': u'00:1b:6e:04:8d:44', u'custom_tlvs': [], u'ttl': 120, u'port_id': u'P49', u'system_capabilities': u'', u'management_addresses': [], u'last_seen': 1577241872}], u'P49': [{u'system_name': u'Ixia Vision One (Neo10 project)', u'port_description': u'', u'system_description': u'', u'expired': False, u'age': 3, u'chassis_id': u'00:1b:6e:04:8d:44', u'custom_tlvs': [], u'ttl': 120, u'port_id': u'P50', u'system_capabilities': u'', u'management_addresses': [], u'last_seen': 1577241870}]}
        """
        return self._sendRequest(http_method='POST', url='/actions/get_neighbors_v2', args={}, response_type='json')

    def getNeighbors(self, args):
        """ getNeighbors :
        Get neighbors of a list of ports given as parameter. If the list given is empty or is not given at all, it will return
        all neighbors for all ports that are valid for LLDP and have valid neighbors registrations.
        This method is allowed only on the following models: E40, TradeVision
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        >>> nto.getNeighbors({'port_id_list': [8]})
        {u'P49': [{u'system_name': u'Ixia Vision One (Neo10 project)', u'port_description': u'', u'system_description': u'', u'expired': False, u'age': 1, u'chassis_id': u'00:1b:6e:04:8d:44', u'custom_tlvs': [], u'ttl': 120, u'port_id': u'P50', u'system_capabilities': u'', u'management_addresses': [], u'last_seen': 1577241420}]}
        """
        return self._sendRequest(http_method='POST', url='/actions/get_neighbors_v2', args=args, response_type='json')

    def getPortListNeighbors(self, args):
        """ getNeighbors :
        Get neighbors of a list of ports given as parameter. If the list given is empty or is
        not given at all, it will return all neighbors for all ports that are valid for LLDP
        and have valid neighbors registrations.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_neighbors_v2', args=args, response_type='json')

    def getNetserviceConfig(self, args):
        """ getNetserviceConfig :
        This command is used to get the configuration from a netservice.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_netservice_config', args=args, response_type='json')

    def getObjectType(self, args):
        """ getObjectType :
        Return the object type for an internal id.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getObjectType({'id':238})
        {u'object_type': u'PORT'}
        """
        return self._sendRequest(http_method='POST', url='/actions/get_object_type', args=args, response_type='json')

    def getOfflineToken(self, args):
        """ getOfflineToken :
        This action allows user to retrieve an offline token from the Keyclaok
        server set in the KVO config.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_offline_token', args=args, response_type='json')

    def getLfdPeerPorts(self):
        """ getLfdPeerPorts :
        Get a list of peer ports valid for LFD.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_peer_ports_valid_for_lfd', args={}, response_type='none')

    def getPodsStatus(self):
        """ getPodsStatus :
        Get pods status for all namespaces.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_pods_status', args={}, response_type='json')

    def getProperties(self, args):
        """ getProperties :
        Return a list of the properties that are available for a particular type of object.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getProperties({'object_type' : 'monitor'})
        {u'properties': [u'actions', u'created', u'description', u'history', u'id', u'mod_count', u'name', u'trigger']}
        """
        return self._sendRequest(http_method='POST', url='/actions/get_props', args=args, response_type='json')

    def getSoftwareVersion(self, args):
        """ getSoftwareVersion :
        Get the version of software installed in the NTO repository.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/actions/get_software_version', args=args, response_type='json')

    def getTransceiverInfo(self):
        """ getTransceiverInfo :
        Return the transceiver information.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.getTransceiverInfo()
        [{'lanes': 1, 'port_default_name': 'P01', 'port_id': '16', 'port_name': 'P01', 'transceiver_info': [{'cable': 'N/A', 'compliance': '100G AOC or 25GAUI C2M AOC', 'connector': 'No separable connector', 'diag_calibration': 'Not Applicable', 'identifier': 'QSFP28', 'length_comment': 'OM4 50um', 'length_mode': 'Unspecified', 'max_length': '6 meters', 'present': 'true', 'rx_input_power1': '1.3392', 'rx_input_power1_dbm': '1.27', 'rx_input_power2': '1.3545', 'rx_input_power2_dbm': '1.32', 'rx_input_power3': '1.3764', 'rx_input_power3_dbm': '1.39', 'rx_input_power4': '1.352', 'rx_input_power4_dbm': '1.31', 'rx_input_power_high_alert_threshold': '3.4673', 'rx_input_power_high_alert_threshold_dbm': '5.40', 'rx_input_power_high_warning_threshold': '1.7378', 'rx_input_power_high_warning_threshold_dbm': '2.40', 'rx_input_power_low_alert_threshold': '0.0467', 'rx_input_power_low_alert_threshold_dbm': '-13.31', 'rx_input_power_low_warning_threshold': '0.0933', 'rx_input_power_low_warning_threshold_dbm': '-10.30', 'rx_input_power_status1': 'Normal', 'rx_input_power_status2': 'Normal', 'rx_input_power_status3': 'Normal', 'rx_input_power_status4': 'Normal', 'temperature': '35', 'temperature_high_alert_threshold': '80', 'temperature_high_warning_threshold': '70', 'temperature_low_alert_threshold': '-10', 'temperature_low_warning_threshold': '0', 'temperature_status': 'Normal', 'tx_bias1': '6.75', 'tx_bias2': '6.75', 'tx_bias3': '6.75', 'tx_bias4': '6.75', 'tx_bias_high_alert_threshold': '8.5', 'tx_bias_high_warning_threshold': '8.0', 'tx_bias_low_alert_threshold': '5.492', 'tx_bias_low_warning_threshold': '6.0', 'tx_bias_status1': 'Normal', 'tx_bias_status2': 'Normal', 'tx_bias_status3': 'Normal', 'tx_bias_status4': 'Normal', 'tx_output_power1': '1.6412', 'tx_output_power1_dbm': '2.15', 'tx_output_power2': '1.6222', 'tx_output_power2_dbm': '2.10', 'tx_output_power3': '1.5521', 'tx_output_power3_dbm': '1.91', 'tx_output_power4': '1.5447', 'tx_output_power4_dbm': '1.89', 'tx_output_power_high_alert_threshold': '3.4673', 'tx_output_power_high_alert_threshold_dbm': '5.40', 'tx_output_power_high_warning_threshold': '1.7378', 'tx_output_power_high_warning_threshold_dbm': '2.40', 'tx_output_power_low_alert_threshold': '0.0724', 'tx_output_power_low_alert_threshold_dbm': '-11.40', 'tx_output_power_low_warning_threshold': '0.1445', 'tx_output_power_low_warning_threshold_dbm': '-8.40', 'tx_output_power_status1': 'Normal', 'tx_output_power_status2': 'Normal', 'tx_output_power_status3': 'Normal', 'tx_output_power_status4': 'Normal', 'vendor_date_code': '05-07-2018', 'vendor_lot_code': '  ', 'vendor_name': 'Mellanox', 'vendor_oui': '0002c9', 'vendor_part_number': 'MFA1A00-C003', 'vendor_rev': 'B1', 'vendor_serial_number': 'MT1823FT00529', 'voltage': '3.2691', 'voltage_high_alert_threshold': '3.5', 'voltage_high_warning_threshold': '3.465', 'voltage_low_alert_threshold': '3.1', 'voltage_low_warning_threshold': '3.135', 'voltage_status': 'Normal', 'wavelength': '8500'}]},
            <snip>
        """
        return self._sendRequest(http_method='POST', url='/actions/get_transceiver_info', args={}, response_type='json')

    def getTradeVisionEvents(self):
        """ getTradeVisionEvents :
        This command is used to get TradeVision-only events from the server database.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_tv_events', response_type='json')

    def getTradeVisionEventsValuesRanges(self):
        """ getTradeVisionEventsValuesRanges :
        This command is used to get TradeVision events from the server database.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/get_tv_events_value_range', response_type='json')

    def getPropertyValues(self, args):
        """ getPropertyValues :
        Return a list of the properties that are available for a particular type of object.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getPropertyValues({'object_type': 'port', 'prop_name': 'force_link_up'})
        {u'value': [u'DISABLED', u'ENABLED', u'MIXED', u'NOT_SUPPORTED']}
        """
        return self._sendRequest(http_method='POST', url='/actions/get_values', args=args, response_type='json')

    def getProbeHeartbeat(self):
        """ getProbeHeartbeat:
        The Heartbeat action is used to receive the "alive" signal from probes.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/heartbeat', args={}, response_type='none')

    def importConfig(self, args):
        """ importConfig :
        Copy configuration settings from a file to an NTO.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.importConfig({'boundary': 'INCLUDE', 'import_type': 'CUSTOM', 'file_name': '/Users/fmota/Desktop/snmp+user.ata', 'system' : 'snmp_config'})
        '{"message": "Configuration imported from /Users/fmota/Desktop/snmp+user.ata."}'
        """
        file_name = args['file_name']
        import_request = {key: value for key, value in args.items() if key != 'file_name'}
        with open(file_name, 'rb') as file_handle:
            multipart_form_data = {
                'import_req_spec': (None, json.dumps(import_request), 'application/json'),
                'file': (file_name, file_handle, 'application/octet-stream')
            }
            return self._sendRequest(
                http_method='POST',
                url='/actions/import',
                args=None,
                file_info=multipart_form_data,
                response_type='json'
            )

    def importFlowStackIpFlowsList(self, args):
        """ importFlowStackIpFlowsList :
        Import IP entries into the FlowStack IP Flows List.
        args must contain file_name and may contain replace.
        Platforms:
            Vision 400, Vision 400XT

        """
        file_name = args['file_name']
        properties = {key: value for key, value in args.items() if key != 'file_name'}
        with open(file_name, 'rb') as file_handle:
            multipart_form_data = {
                'file': (file_name, file_handle, 'application/octet-stream')
            }
            if properties:
                multipart_form_data['import_ip_list_properties'] = (
                    None, json.dumps(properties), 'application/json'
                )
            return self._sendRequest(http_method='POST', url='/actions/import_ipflows_ip_list', args=None, file_info=multipart_form_data, response_type='json')

    def importRecoveryApplianceConfig(self, args):
        """ importRecoveryApplianceConfig :
        Import Recovery Appliance configuration from an input file.
        Platforms:
            GSC 7400

        Example:
        """

        file_name = args['file_name']
        f = {'file': (file_name, open(file_name ,'rb'), 'application/octet-stream')}
        return self._sendRequest(http_method='POST', url='/actions/import_recovery_appliance_config', args=args, file_info=f, response_type='json')

    def installRecoveryApplianceSoftware(self, args):
        """ installRecoveryApplianceSoftware :
        Install software on Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        """

        file_name = args['file_name']
        f = {'file': (file_name, open(file_name ,'rb'), 'application/octet-stream')}
        return self._sendRequest(http_method='POST', url='/actions/install_appliance_software', args=args, file_info=f, response_type='json')

    def installDtsp(self, args):
        """ installDtsp :
        This command installs a DTSP on a Trade Vision.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision Edge 400S

        Example:
        """
        file_name = args['file_name']
        with open(file_name, 'rb') as file_handle:
            multipart_form_data = {
                'file': (file_name, file_handle, 'application/octet-stream')
            }
            return self._sendRequest(
                http_method='POST',
                url='/actions/install_dtsp',
                args=None,
                file_info=multipart_form_data,
                response_type='json'
            )

    def installLicense(self, args):
        """ installLicense :
        This command installs a license file on a NTO, a union, or a member.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.installLicense({'file_name': '/Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt'})
        '{"message": "License installed from /Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt."}'
        """
        file_name = args['file_name']
        entity = {key: value for key, value in args.items() if key != 'file_name'}
        with open(file_name, 'rb') as file_handle:
            multipart_form_data = {
                'file': (file_name, file_handle, 'application/octet-stream')
            }
            if entity:
                multipart_form_data['entity'] = (
                    None,
                    json.dumps(entity),
                    'application/json'
                )
            return self._sendRequest(
                http_method='POST',
                url='/actions/install_license',
                args=None,
                file_info=multipart_form_data,
                response_type='json'
            )

    def installLicense_old(self, args):
        """ installLicense :
        This command installs a license file on a NTO, a union, or a member.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.installLicense({'file_name': '/Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt'})
        '{"message": "License installed from /Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt."}'
        """
        return self.installLicense(args)

    def installMakoOs(self, args):
        """ installMakoOs :
        This command installs a Mako OS software upgrade file on Marshall cards.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge OS 9516, Vision One, Vision
            X, Vision X 400G

        Example:
        """
        file_name = args['file_name']
        with open(file_name, 'rb') as file_handle:
            multipart_form_data = {
                'file': (file_name, file_handle, 'application/octet-stream')
            }
            return self._sendRequest(
                http_method='POST',
                url='/actions/install_mako',
                args=None,
                file_info=multipart_form_data,
                response_type='json'
            )

    def installNetservice(self, args):
        """ installNetservice :
        This command installs a netservice upgrade file on an NTO.
        This method is allowed only on the following models: 8000
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        file_name = args['file_name']
        with open(file_name, 'rb') as file_handle:
            multipart_form_data = {
                'file': (file_name, file_handle, 'application/octet-stream')
            }
            return self._sendRequest(
                http_method='POST',
                url='/actions/install_netservice',
                args=None,
                file_info=multipart_form_data,
                response_type='json'
            )

    def installSoftware(self, args):
        """ installSoftware :
        This command installs a software upgrade file on an NTO. When installing
        software on a supervisor in a union, all members in the union will be
        upgraded to the same software level automatically.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.installSoftware({'file_name': '/Users/fmota/Desktop/NVOS-4.3.1.1-52xx-141844-20150722-174244.zip'})
        '{"message": "Software installation complete. The system will be restarted. Visit the 5288 launch page in your browser to obtain the updated client software."}'
        """
        file_name = args.get('file_name')
        install_request = {
            key: value for key, value in args.items()
            if key != 'file_name'
        }

        stage = install_request.get('stage')

        # No stage means FULL_INSTALL. FULL_INSTALL and UPLOAD require a file.
        if file_name is None and stage in (None, 'FULL_INSTALL', 'UPLOAD'):
            raise ValueError(
                "file_name is required for FULL_INSTALL and UPLOAD"
            )

        # Fileless staged actions operate on an image already on the device.
        # Device validation confirmed INSTALL and FINALIZE use ordinary JSON.
        if file_name is None:
            return self._sendRequest(
                http_method='POST',
                url='/actions/install_software',
                args=install_request,
                response_type='json'
            )

        # File-bearing actions use multipart/form-data.
        multipart_form_data = {
            'install_software_req_spec': (
                None,
                json.dumps(install_request),
                'application/json'
            )
        }

        with open(file_name, 'rb') as file_handle:
            multipart_form_data['file'] = (
                file_name,
                file_handle,
                'application/octet-stream'
            )
            return self._sendRequest(
                http_method='POST',
                url='/actions/install_software',
                args=None,
                file_info=multipart_form_data,
                response_type='json'
            )

    def installSoftwareFromFtp(self, args):
        """ installSoftwareFromFtp :
        Download a software image from an FTP server and install it.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/actions/install_software_from_ftp', args=args, response_type='json')

    def interruptAeTraffic(self, args=None):
        """ interruptAeTraffic :
        Interrupt traffic for a given analysis engine (AE).
        This will temporarily (10 sec) turn off traffic to AE.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/interrupt_ae_traffic', args={} if args is None else args, response_type='json')

    def backupGscConfigFromKvo(self, args):
        """ backupGscConfigFromKvo:
        Backup GSC configuration from KVO.
        Platforms:
            Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/kvo_backup_gsc_config', args=args, response_type='json')

    def restoreGscConfigFromKvo(self, args):
        """ restoreGscConfigFromKvo :
        Restore a GSC configuration backup from KVO.
        Platforms:
            Vision X

        """
        return self._sendRequest(http_method='POST', url='/actions/kvo_restore_gsc_config', args=args, response_type='json')

    def getLdapMultiCertificates(self, args):
        """ getLdapMultiCertificates :
        Display the LDAP certificates present on the system.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/actions/ldap_multi_cert', args=args, response_type='json')

    def markEodReportAsGolden(self, args=None):
        """ markEodReportAsGolden :
        Marks a completed End-Of-Day Report as a Golden Report.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/mark_ae_eod_report_golden', args={} if args is None else args, response_type='json')

    def mtuQuery(self, args=None):
        """ mtuQuery :
        This commands returns the port, linecard and AFM MTUs based on the board type.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        >>> nto.mtuQuery({'port_id': 59})
        {u'port_mtu': 12284, u'port_id': 59, u'fabric_mtu': 12268, u'afmr_mtu': 0}
        >>> nto.mtuQuery({'filter_id': 96})
        {u'port_mtu': 0, u'fabric_mtu': 0, u'afmr_mtu': 0, u'filter_id': 96}
        """
        return self._sendRequest(http_method='POST', url='/actions/mtu_query', args={} if args is None else args, response_type='json')

    def netcat(self, args):
        """ netcat :
        Run the nc (netcat) utility on the server to test TCP connectivity to a host and port.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/netcat', args=args, response_type='json')

    def ping(self, args):
        """ ping :
        Run the ping utility on the server and return its output.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/ping', args=args, response_type='json')

    def pairRecoveryAppliance(self, args):
        """ pairRecoveryAppliance:
        Pair a GSC with a Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/pair_recovery_appliance', args=args, response_type='json')

    def powerDown(self, args=None):
        """ powerDown :
        This command safely shuts down an NTO, a union or a member.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.powerDown()
        {u'message': u'System shutdown requested.'}
        """
        return self._sendRequest(http_method='POST', url='/actions/power_down', args={} if args is None else args, response_type='json')

    def processKsmLicenseUpdates(self):
        """ processKsmLicenseUpdates :
        Process and install KSM licenses that are activated on this system.
        Platforms:
            Vision 400, Vision 400XT, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge
            50, Vision Edge OS 9516, Vision X 400G

        Example:
        >>> nto.processKsmLicenseUpdates()
        """
        return self._sendRequest(http_method='POST', url='/actions/process_ksm_license_updates', args={}, response_type='json')

    def pullConfigFromHaPeer(self):
        """ pullConfigFromHaPeer :
        Pulls the configuration from the HA peer machine.
        Platforms:
            7300/7303, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge
            400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS
            9516, Vision Edge OS 5812, Vision One, Vision X, Vision X 400G

        Example:
        *** TO BE TESTED ***
        >>> nto.pullConfigFromHaPeer()
        """
        return self._sendRequest(http_method='POST', url='/actions/pull_config_from_ha_peer', args=None, response_type='json')

    def pushConfigToHaPeer(self):
        """ pushConfigToHaPeer :
        Pushes the local configuration to the HA peer machine.
        Platforms:
            7300/7303, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge
            400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS
            9516, Vision Edge OS 5812, Vision One, Vision X, Vision X 400G

        Example:
        *** TO BE TESTED ***
        >>> nto.pushConfigToHaPeer()
        """
        return self._sendRequest(http_method='POST', url='/actions/push_config_to_ha_peer', args=None, response_type='json')

    def queryImsi(self, args):
        """ queryImsi :
        Query an IMSI and return the associated GSC filter/tool-port information.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        """
        return self._sendRequest(http_method='POST', url='/actions/query_imsi', args=args, response_type='json')

    def queryImsiV2(self, args):
        """ queryImsiV2 :
        Query an IMSI using the v2 Query IMSI action.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/query_imsi_v2', args=args, response_type='json')

    def recoverBackup(self):
        """ recoverBackup:
        Triggers a GSC restart, which will then start recovering the backup data from the Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/recover_backup', args={}, response_type='json')

    def relocatePortModuleLicenses(self, args):
        """ relocatePortModuleLicenses:
        Allocates the licenses for port modules as specified in the map.
        When licensed with FNE license, for port modules KAHANA_SFPP_16,
        MOKOLII_CX4, MOKOLII_SFPPLUS, MOKOLII_XFP and WAIKIKI_SFPPLUS
        the user can change the license allocation between modules.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/relocate_port_module_license', args=args, response_type='json')

    def removeLicense(self):
        """ removeLicense :
        This command will remove the license and power down the NTO.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.removeLicense()
        """
        return self._sendRequest(http_method='POST', url='/actions/remove_license', args={}, response_type='json')

    def removeLineCard(self, args):
        """ removeLineCard :
        This command will remove the line card based on the given line card id.
        Platforms:
            7300/7303

        Example:
        >>> nto.removeLineCard({'line_card_id': 1})
        {u'message': u'System restart requested.'}
        """
        return self._sendRequest(http_method='POST', url='/actions/remove_line_card', args=args, response_type='json')

    def removeNetservice(self, args):
        """ removeNetservice :
        This command will remove (uninstall) a netservice based on the given service id.
        This method is allowed only on the following models: 8000.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/remove_netservice', args=args, response_type='json')

    def removePlugin(self, args):
        """ removePlugin :
        This command will remove (uninstall) a plugin based on the given plugin type.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/remove_plugin', args=args, response_type='json')

    def removePortModuleConfiguration(self, args):
        """ removePortModuleConfiguration :
        This command will remove the port module configuration based on the given module location.
        This method is allowed only on the following models: 8000.
        Platforms:
            Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/remove_port_module_config', args=args, response_type='json')

    def requestFanStatus(self):
        """ requestFanStatus:
        This command will return a mapping of fan module locations to fan module status information.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/request_fan_status', args={}, response_type='json')

    def requestKvoCertificate(self, args):
        """ requestKvoCertificate :
        This action requests the certificate from the KVO at the address specified to be downloaded
        to the NTO and stored there.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/request_kvo_certificate', args=args, response_type='json')

    def requestLicenseUsageInfo(self):
        """ requestLicenseUsageInfo :
        This command will return a mapping of KSM feature names to usage counts for licenses
        checked out from both the local and remote servers.
        Platforms:
            Vision 400, Vision 400XT, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge
            50, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/request_license_usage_info', args={}, response_type='json')

    def requestLocalLicenseAvailability(self):
        """ requestLocalLicenseAvailability :
        This command will return a mapping of KSM feature names to installed counts for licenses
        installed on the local license server.
        Platforms:
            Vision 400, Vision 400XT, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge
            50, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/request_local_license_availability', args={}, response_type='json')

    def requestPortLicenseConfiguration(self, args=None):
        """ requestPortLicenseConfiguration :
        This command will attempt to license and configure ports in the desired breakout configuration.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/request_port_license_configuration', args={} if args is None else args, response_type='json')

    def requestPowerSupplyStatus(self):
        """ requestPowerSupplyStatus:
        This command will return a mapping of power supply locations to power supply status information.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/request_power_supply_status', args={}, response_type='json')

    def requestSystemLicenseCheckout(self, args=None):
        """ requestSystemLicenseCheckout :
        This command will attempt to checkout licenses for the desired system features.
        Platforms:
            Vision 400, Vision 400XT, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge
            50

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/request_system_license_checkout', args={} if args is None else args, response_type='json')

    def resetEventRateLimiterStatus(self, args=None):
        """ resetEventRateLimiterStatus :
        Reset the event rate limiter status for the given event type.
        Event type can be for gap, health or burst.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/reset_event_rate_limiter_status', args={} if args is None else args, response_type='json')

    def resetFactoryDefaultsVAM(self, args=None):
        """ resetFactoryDefaultsVAM :
        This command resets to factory defaults the expansion board.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/reset_factory_defaults_vam', args={} if args is None else args, response_type='json')

    def resetPacketFragmentation(self, args):
        """ resetPacketFragmentation:
        Reset packet Fragmentation on one or more GSC network port groups.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/reset_packet_fragmentation', args=args, response_type='json')

    def restart(self, args=None):
        """ restart :
        This command safely restarts an NTO, a union, or a member.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.restart()
        {u'message': u'System restart requested.'}
        """
        return self._sendRequest(http_method='POST', url='/actions/restart', args={} if args is None else args, response_type='json')

    def restartRecoveryAppliance(self):
        """ restartRecoveryAppliance:
        Initiate a restart on the Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/restart_recovery_appliance', args={}, response_type='json')

    def restoreFirewall(self):
        """ restoreFirewall :
        This command will restore the default firewall rules to allow all servers to access NTO.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/restore_firewall', args={}, response_type='json')

    def restoreGscConfig(self):
        """ backupGscConfig :
        Restore GSC configuration.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/restore_gsc_config', args={}, response_type='json')

    def resumeItrTraffic(self, args):
        """ resumeItrTraffic :
        This command will resume traffic on ITR based on ITR id.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/resume_itr_traffic', args=args, response_type='json')

    def revertSoftware(self):
        """ revertSoftware :
        This command revert software to it's previous version.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.revertSoftware()
        {u'message': u'Software revert requested. The system will be restarted. Visit the 7300 launch page in your browser to obtain the reverted client software.'}
        """
        return self._sendRequest(http_method='POST', url='/actions/revert_software', args={}, response_type='json')

    def getLogs(self, args):
        """ getLogs :
        Get the current system log files for subsequent delivery to Anue Support.
        Platforms:
            GSC 7400, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.getLogs({'file_name': 'logs.zip'})
        b'PK\x03\x04 ...'
        """
        return self._sendRequest(http_method='POST', url='/actions/save_logs', args=args, response_type='bytes')

    def saveLogs(self, args):
        """ saveLogs :
        Save the current system log files for subsequent delivery to Anue Support.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.saveLogs({'file_name': '/Users/fmota/Desktop/NTO-log.zip'})
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest(http_method='POST', url='/actions/save_logs', args=args, response_type='bytes')
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def saveNetserviceConfig(self, args):
        """ saveNetserviceConfig :
        This command is used to apply the configuration on a netservice.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/save_netservice_config', args=args, response_type='json')

    def saveServerLogs(self, args):
        """ saveServerLogs :
        Save the current system log file(s) for subsequent download and delivery to Keysight Support.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/save_server_logs', args=args, response_type='bytes')

    def searchSubscribersByFTeid(self, args):
        """ searchSubscribersByFTeid:
        Searches whether a given subscriber (that is identified by a TEID and an
        IPv4 or IPv6) has an active session and if so which port has been allocated
        to that subscriber's active session(s). If the given subscriber has an
        active session then it returns all the pairs of {source port groups,
        allocated tool port default name}.
        Platforms:
            GSC 7400

        Example:
        gsc.searchSubscribersByFTeid({'subscriber_ip': '10.10.10.10', 'subscriber_ip_type': 'IPv4', 'subscriber_teid': '12345678'})
        TBD
        """
        return self._sendRequest(http_method='POST', url='/actions/search_subscriber_by_fteid', args=args, response_type='json')

    def searchSubscribersByImsi(self, args):
        """ searchSubscribersByImsi:
        Searches whether a given subscriber (that is identified by IMSI) has an
        active session and if so which port has been allocated to that
        subscriber's active session(s). If the given subscriber has an active
        session then it returns all the pairs of {source port groups, allocated
        tool port default name}.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.searchSubscribersByImsi({'subscriber_imsi': '123456789012345'})
        {u'subscribers': [{u'subscriber_source_port_groups': [u'PG1', u'PG2', u'PG3', u'PG4'], u'subscriber_destination_tool_port': u'PC01'}]}
        """
        return self._sendRequest(http_method='POST', url='/actions/search_subscriber_by_imsi', args=args, response_type='json')

    def sendSyntheticPackets(self, args):
        """ sendSyntheticPackets :
        Send synthetic packet to the destination addresses configured under TradeStream->Synthetic
        Mesh Latency Settings. If no destination addresses are specified, then user will not be
        allowed to send synthetic packets.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/send_synthetic_packets', args=args, response_type='json')

    def setHaSyncPort(self, args):
        """ setHaSyncPort :
        Set the HA sync port.
        This action will set the High Availability sync port used to communicate with the peer machine.
        The request dictionary must contain the port to use for HA synchronization.
        Platforms:
            7300/7303, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge
            400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS
            9516, Vision Edge OS 5812, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.setHaSyncPort({'port': 'P1'})
        """
        return self._sendRequest(http_method='POST', url='/actions/set_ha_sync_port', args=args, response_type='json')

    def setIpConfig(self, args):
        """ setIpConfig :
        Changes the IP configuration of a system.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.setIPConfig({'ipv4_address': '192.168.2.149', 'ipv4_enabled': True, 'ipv4_gateway': '192.168.2.2', 'ipv4_netmask': '255.255.255.0', 'ipv6_address': 'fe80::5daa:83ed:42f8:6c08%11', 'ipv6_enabled': False, 'ipv6_prefix_length': 64})
        {u'message': u'The new IP configuration has been submitted.'}
        """
        return self._sendRequest(http_method='POST', url='/actions/set_ip_config', args=args, response_type='json')

    def setKvoState(self, args):
        """ setKvoState :
        Prepare system for entering full KVO mode.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/set_kvo_state', args=args, response_type='none')

    def setStackMode(self, args):
        """ setStackMode :
        Set the Stack mode of a switch.
        This action will set the Stack mode for a switch. Warning: The switch will be restarted.
        Platforms:
            Vision Edge 10S, Vision One

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/set_stack_mode', args=args, response_type='json')

    def shutdownRecoveryAppliance(self):
        """ shutdownRecoveryAppliance:
        Initiate a shutdown of the Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/shutdown_recovery_appliance', args={}, response_type='json')

    def startBackup(self):
        """ startBackup:
        Starts a backup of GSC info on the Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/start_backup', args={}, response_type='json')

    def stopBackup(self):
        """ stopBackup:
        Stops a backup of GSC info on the Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/stop_backup', args={}, response_type='json')

    def stopMirroring(self, args):
        """ stopMirroring:
        Stops mirroring on a GSC session port group.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.stopMirroring({'port_group_id': 100})
        {u'message': u'Stop GSC mirroring completed successfully.'}
        """
        return self._sendRequest(http_method='POST', url='/actions/stop_gsc_mirroring', args=args, response_type='json')

    def swapPortLicenses(self, args):
        """ swapPortLicenses :
        Swaps port licenses.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/swap_port_licenses', args=args, response_type='none')

    def unpairRecoveryAppliance(self, args):
        """ unpairRecoveryAppliance:
        Pair a GSC with a Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/unpair_recovery_appliance', args=args, response_type='json')

    def modifyFabricPorts(self, args):
        """ modifyFabricPorts :
        Changes the fabric ports configuration for the specified member switch.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/update_fabric_ports', args=args, response_type='json')

    def traceroute(self, args):
        """ traceroute :
        Run the traceroute utility on the server and return its output.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/traceroute', args=args, response_type='json')

    def getTrapMessages(self, args):
        """ getTrapMessages :
        Retrieve decoded SNMP trap messages received by the system.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/trap_messages', args=args, response_type='json')

    def updateSingleIpAddress(self, args):
        """ updateSingleIpAddress :
        This action allows a single IP address to be added to or removed from a filter
        with an existing IP address criterion.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/update_single_ip_addr', args=args, response_type='json')

    def wipeAllNetserviceData(self):
        """ wipeAllNetserviceData :
        Wipe all netservice data from the NPB.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/wipe_all_netservice_data', args=None, response_type='none')

    def validateAuthCalls(self):
        """ validateAuthCalls :
        This command checks auth for rest calls.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/actions/validate_auth', args={}, response_type='json')

    def validateBandwidthOption(self, args):
        """ validateBandwidthOption :
        Check whether a requested netservice bandwidth option can be satisfied.
        Platforms:
            Vision 400, Vision 400XT

        """
        return self._sendRequest(http_method='POST', url='/actions/validate_bandwidth_option', args=args, response_type='json')


    # /ae_resources

    def getAllAnalysisEngines(self):
        """ getAllAnalysisEngines :
        Fetch a list containing the summaries for all the AE resources in the system.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='GET', url='/ae_resources', args=None, response_type='json')

    def captureAnalysisEngineInfo(self):
        """ captureAnalysisEngineInfo :
        Get capture info for all the AEs.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/ae_resources/capture_info', args=None, response_type='json')

    def clearAnalysisEngineAnalytics(self, ae_id):
        """ clearAnalysisEngineAnalytics :
        Clear analytics configuration for an Analysis Engine resource.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/ae_resources/{ae_id}/clear', args=None, response_type='none')

    def clearAllAnalysisEngineAnalytics(self):
        """ clearAllAnalysisEngineAnalytics :
        Clear analytics configuration for all Analysis Engine resources.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/ae_resources/clear_all', args=None, response_type='none')

    def getAnalysisEnginesDetails(self, ids=None):
        """ getAnalysisEnginesDetails :
        Fetch detailed properties for all or selected AE resources.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        """
        return self._sendRequest(http_method='POST', url='/ae_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def relearnAnalysisEngineMuxStreams(self, args):
        """ relearnAnalysisEngineMuxStreams :
        Re-learn mux streams on one or more AE resources. If no AE resource ids are passed in,
        mux streams will be re-learned on all AEs.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/ae_resources/relearn_mux_streams', args=args, response_type='json')

    def searchAnalysisEngines(self, args):
        """ searchAnalysisEngines :
        Search for a specific AE resource in the system by certain properties.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url='/ae_resources/search', args=args, response_type='json')

    def getAnalysisEngineWritableProperties(self):
        """ getAnalysisEngineWritableProperties :
        Return the names of writable AE resource properties.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        """
        return self._sendRequest(http_method='POST', url='/ae_resources/writable_props', args=None, response_type='json')

    def getAnalysisEngine(self, ae_id, properties=None):
        """ getAnalysisEngine :
        Fetch the properties of an AE resource.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/ae_resources/{ae_id}', params=params, response_type='json')

    def modifyAnalysisEngine(self, ae_id, args):
        """ modifyAnalysisEngine :
        Update the properties of an existing AE resource.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/ae_resources/{ae_id}', args=args, response_type='none')

    def applyAnalysisEngineTemplate(self, ae_id, args):
        """ applyAnalysisEngineTemplate :
        Apply an object template to an AE resource.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        """
        return self._sendRequest(http_method='PUT', url=f'/ae_resources/{ae_id}/apply_template', args=args, response_type='none')

    def createAnalysisEngineTemplate(self, ae_id, args):
        """ createAnalysisEngineTemplate :
        Create an object template from an AE resource.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        """
        return self._sendRequest(http_method='PUT', url=f'/ae_resources/{ae_id}/create_template', args=args, response_type='json')

    def deleteAnalysisEnginePcapFiles(self, ae_id, args):
        """ deleteAnalysisEnginePcapFiles :
        Deletes one or more PCAP files from an Analysis Engine resource.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/ae_resources/{ae_id}/delete_pcap_files', args=args, response_type='json')

    def disableAnalysisEngine(self, ae_id):
        """ disableAnalysisEngine :
        Detaches an AE by disconnecting the attached filter.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/ae_resources/{ae_id}/disable', args=None, response_type='none')

    def downloadAnalysisEnginePcapFiles(self, ae_id, args):
        """ downloadAnalysisEnginePcapFiles :
        Download one or more PCAP files for an AE resource.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/ae_resources/{ae_id}/download_pcap_files', args=args, response_type='bytes')

    def enableAnalysisEngine(self, ae_id, args):
        """ enableAnalysisEngine :
        Attaches an AE to a filter.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/ae_resources/{ae_id}/enable', args=args, response_type='none')

    def getAnalysisEnginePcapFileList(self, ae_id, args):
        """ getAnalysisEnginePcapFileList :
        Get a list of all PCAP files available for an Analysis Engine resource.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/ae_resources/{ae_id}/get_pcap_file_list', args=args, response_type='json')

    def startAnalysisEngineCapture(self, ae_id, args=None):
        """ startAnalysisEngineCapture :
        Starts capture on AE resource to capture packets via the attached filter.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/ae_resources/{ae_id}/start_capture', args=args, response_type='none')

    def stopAnalysisEngineCapture(self, ae_id, args=None):
        """ stopAnalysisEngineCapture :
        Stops capturing packets on AE resource.
        Platforms:
            TradeVision, Vision 400, Vision 400XT

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/ae_resources/{ae_id}/stop_capture', args=args, response_type='none')


    # /aggregator_resources

    def getAllAggregators(self):
        """ getAllAggregators :
        Fetch a list containing the summaries for all the Aggregator resources in the system.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/aggregator_resources', response_type='json')

    def getAggregatorsDetails(self, ids=None):
        """ getAggregatorsDetails :
        Fetch detailed properties for all or selected Aggregator resources.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        """
        return self._sendRequest(http_method='POST', url='/aggregator_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchAggregators(self, args):
        """ searchAggregators :
        Search for a specific Aggregator resource in the system by certain properties.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/aggregator_resources/search', args=args, response_type='json')

    def getAggregator(self, resource, properties=None):
        """ getAggregator :
        Fetch the properties of an Aggregator resource object.
        To request only select properties (partial response), append to the URL the query
        parameter '?properties=value', where value is comma-separated list to select
        multiple fields for ex- /resource_type/{object-id}?properties=description,name.
        Query Parameter is optional.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/aggregator_resources/{resource}', params=params, response_type='json')

    def modifyAggregator(self, resource, args):
        """ modifyAggregator:
        Update the properties of an existing Aggregator resource.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/aggregator_resources/{resource}', args=args, response_type='none')

    def disableAggregator(self, resource, args):
        """ disableAggregator :
        Disables an Aggregator resource by disconnecting the attached port group.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/aggregator_resources/{resource}/disable', args=args, response_type='none')

    def enableAggregator(self, resource, args):
        """ enableAggregator :
        Enables an Aggregator resource by attaching a port group to it.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/aggregator_resources/{resource}/enable', args=args, response_type='none')


    # /atip_resources

    def getAllAtips(self):
        """ getAllAtips :
        Fetch a list containing the summaries for all the ATIP resources in the system.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getAllAtips()
        [{u'id': 179, u'name': u'L2-ATIP'}]
        """
        return self._sendRequest(http_method='GET', url='/atip_resources', response_type='json')

    def getAtipsDetails(self, ids=None):
        """ getAtipsDetails :
        Fetch detailed properties for all or selected ATIP resources.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/atip_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchAtips(self, args):
        """ searchAtips :
        Search for a specific ATIP resource in the system by certain properties.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.searchAtips({'resource_status': 'READY'})
        [{u'id': 179, u'name': u'L2-ATIP'}]
        """
        return self._sendRequest(http_method='POST', url='/atip_resources/search', args=args, response_type='json')

    def getAtip(self, resource, properties=None):
        """ getAtip :
        Fetch the properties of an ATIP resource.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getAtip('L2-ATIP')
        {u'fill_to_trigger_position': False, u'description': None, u'capture_source': 304, u'lineboard_id': 173, u'default_name': u'L2-ATIP', u'resource_status': u'READY', u'name': u'L2-ATIP', u'mod_count': 5, u'license_status': u'VALID', u'modify_access_settings': {u'policy': u'REQUIRE_ADMIN', u'groups': []}, u'id': 179, u'connect_disconnect_access_settings': {u'policy': u'REQUIRE_ADMIN', u'groups': []}, u'history': [{u'type': u'MODIFY', u'time': 1442009546622, u'caused_by': u'admin', u'details': None, u'props': [u'NETFLOW_ENABLED']}]}
        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/atip_resources/{resource}', params=params, response_type='json')

    def modifyAtip(self, resource, args):
        """ modifyAtip:
        Update the properties of an existing ATIP resource.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.modifyAtip('L2-ATIP', {'description': 'ATIP at slot #2'})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/atip_resources/{resource}', args=args, response_type='none')

    def disableAtip(self, resource):
        """ disableAtip :
        Disables an ATIP by disconnecting the attached filter.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.disableAtip('319')
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/atip_resources/{resource}/disable', args=None, response_type='none')

    def enableAtip(self, resource, args):
        """ enableAtip :
        Enables a capture by attaching a filter to it.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.enableAtip('319', {'filter_id': 'F1'})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/atip_resources/{resource}/enable', args=args, response_type='none')


    # /auth

    def logout(self):
        """ logout :
        This call is used to invalidate any token returned from other calls to the web API.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.logout()
        'User -admin- has logged out.'
        """
        try:
            # New API
            data = self._sendRequest(http_method='POST', url='/auth/logout', args=None, response_type='json')
        except:
            # Old API
            data = self._sendRequest(http_method='GET', url='/auth/logout', args={}, response_type='none')
        return data

    def logoutByVersion(self):
        """ logoutByVersion :
        This call is used to invalidate any token returned from other calls to the web API.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.logoutByVersion()
        'User -admin- has logged out.'
        """
        self._set_sw_version()
        if self.sw_major_version <= 3 or (self.sw_major_version == 4 and self.sw_minor_version < 5):
            return ''
        elif self.sw_major_version == 4 and self.sw_minor_version >= 5:
            return self._sendRequest(http_method='GET', url='/auth/logout', args={}, response_type='none')
        else:
            return self._sendRequest(http_method='POST', url='/auth/logout', args=None, response_type='json')


    # /boards

    def getAllBoards(self):
        """ getAllBoards :
        Fetch a list containing the summaries for all the boards in the system.
        Platforms:
            Vision X, Vision X 400G

        Example:
        >>> nto.getAllBoards()
        [{'id': 74, 'management_port_enabled': False, 'name': 'Board: 1', 'number': None, 'port_module_mode': 'NONE', 'slot': 'A', 'smart_blank_present': False, 'state': 'READY', 'type': 'NETSTACK_16_QSFP'}, {'id': 75, 'management_port_enabled': False, 'name': 'Board: 3', 'number': None, 'port_module_mode': 'GSC_FD', 'slot': 'C', 'smart_blank_present': False, 'state': 'READY', 'type': 'PACKETSTACK_400_QSFP28'}, {'id': 76, 'management_port_enabled': False, 'name': 'Board: 5', 'number': None, 'port_module_mode': 'PACKETSTACK', 'slot': 'R', 'smart_blank_present': False, 'state': 'READY', 'type': 'PACKETSTACK_400_REAR'}, {'id': 77, 'management_port_enabled': False, 'name': 'Board: 2', 'number': None, 'port_module_mode': 'PACKETSTACK', 'slot': 'B', 'smart_blank_present': False, 'state': 'READY', 'type': 'PACKETSTACK_400_QSFP28'}, {'id': 78, 'management_port_enabled': False, 'name': 'Board: 4', 'number': None, 'port_module_mode': 'NONE', 'slot': 'D', 'smart_blank_present': False, 'state': 'READY', 'type': 'NETSERVICE_4_QSFP28'}]
        """
        return self._sendRequest(http_method='GET', url='/boards', response_type='json')

    def getBoardsDetails(self, ids=None):
        """ getBoardsDetails :
        Fetch detailed properties for all or selected boards.
        Platforms:
            Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/boards/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchBoards(self, args):
        """ searchBoards :
        Fetch a list containing the summaries for all the boards in the system.
        Platforms:
            Vision X, Vision X 400G

        Example:
        >>> nto.searchBoards({'slot': 'C'})
        [{'default_name': 'Board: 3', 'id': 75, 'management_port_enabled': False, 'mod_count': 6, 'modify_access_settings': {'groups': [], 'policy': 'ALLOW_ALL'}, 'name': 'Board: 3', 'number': None, 'port_module_mode': 'GSC_FD', 'slot': 'C', 'smart_blank_present': False, 'state': 'READY', 'type': 'PACKETSTACK_400_QSFP28'}]
        """
        return self._sendRequest(http_method='POST', url='/boards/search', args=args, response_type='json')

    def getBoard(self, board):
        """ getBoard :
        Fetch the properties of a board object.
        Platforms:
            Vision X, Vision X 400G

        Example:
        >>> nto.getBoard('Board: 1')
        {'default_name': 'Board: 1', 'id': 74, 'management_port_enabled': False, 'mod_count': 4, 'modify_access_settings': {'groups': [], 'policy': 'ALLOW_ALL'}, 'name': 'Board: 1', 'number': None, 'port_module_mode': 'NONE', 'slot': 'A', 'smart_blank_present': False, 'state': 'READY', 'type': 'NETSTACK_16_QSFP'}
        """
        return self._sendRequest(http_method='GET', url=f'/boards/{board}', response_type='json')

    def modifyBoard(self, board, args):
        """ modifyBoard :
        Update the properties of an existing board.
        Platforms:
            Vision X, Vision X 400G

        Example:
        >>> nto.modifyBoard('75', {'port_module_mode': 'PACKETSTACK'})
        b''
        """
        return self._sendRequest(http_method='PUT', url=f'/boards/{board}', args=args, response_type='none')


    # /bypass_connectors

    def getAllInlineBypassConnectors(self):
        """ getAllInlineBypassConnectors :
        Fetch a list containing the summaries for all the Inline Bypass Connectors in the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getAllInlineBypassConnectors()
        [{'id': 117, 'name': 'test bypass'}]
        """
        return self._sendRequest(http_method='GET', url='/bypass_connectors', response_type='json')

    def createInlineBypassConnector(self, args):
        """ createInlineBypassConnector :
        Create a new Inline Bypass Connector in the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.createInlineBypassConnector({"criteria": {"logical_operation": "AND"}, "filter_mode": "PASS_ALL", "name": "test bypass", "side_a_ports": [12], "side_b_ports": [13], "description": ""})
        {'default_name': 'BPP1', 'id': 117, 'name': 'test bypass'}
        """
        return self._sendRequest(http_method='POST', url='/bypass_connectors', args=args, response_type='json')

    def getInlineBypassConnectorsDetails(self, ids=None):
        """ getInlineBypassConnectorsDetails :
        Fetch detailed properties for all or selected Inline Bypass Connectors.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/bypass_connectors/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchInlineBypassConnectors(self, args):
        """ searchInlineBypassConnectors :
        Search for a specific Inline Bypass Connector in the system by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.searchInlineBypassConnectors({"filter_mode": "PASS_ALL"})
        [{'connect_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'created': {'caused_by': 'admin', 'details': None, 'time': 1605730853970, 'type': 'CREATE'}, 'criteria': {'logical_operation': 'AND'}, 'default_name': 'BPP1', 'description': '', 'filter_mode': 'PASS_ALL', 'history': None, 'id': 117, 'inline_service_chain_list': [], 'inline_service_chain_priority_list': [], 'lfd_enabled': False, 'local_lfd_ports': [], 'misc': {'access_map': {'CONNECT_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Connect Service Chains', 'operation_phrase': 'connect service chains to', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}, 'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS', 'CONNECT_ACCESS_SETTINGS']}, 'mod_count': 1, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'test bypass', 'peer_lfd_ports': [], 'side_a_port_group': 115, 'side_a_ports': [12], 'side_b_port_group': 116, 'side_b_ports': [13], 'vlan': 2001, 'vlan_translation_setting': {'translation_map': []}}]
        """
        return self._sendRequest(http_method='POST', url='/bypass_connectors/search', args=args, response_type='json')

    def getInlineBypassConnector(self, bypass_id, properties=None):
        """ getInlineBypassConnector :
        Fetch the properties of an Inline Bypass Connector.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getInlineBypassConnector('test bypass')
        {'connect_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'created': {'caused_by': 'admin', 'details': None, 'time': 1605730853970, 'type': 'CREATE'}, 'criteria': {'logical_operation': 'AND'}, 'default_name': 'BPP1', 'description': '', 'filter_mode': 'PASS_ALL', 'history': None, 'id': 117, 'inline_service_chain_list': [], 'inline_service_chain_priority_list': [], 'lfd_enabled': False, 'local_lfd_ports': [], 'misc': {'access_map': {'CONNECT_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Connect Service Chains', 'operation_phrase': 'connect service chains to', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}, 'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS', 'CONNECT_ACCESS_SETTINGS']}, 'mod_count': 1, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'test bypass', 'peer_lfd_ports': [], 'side_a_port_group': 115, 'side_a_ports': [12], 'side_b_port_group': 116, 'side_b_ports': [13], 'vlan': 2001, 'vlan_translation_setting': {'translation_map': []}}
        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/bypass_connectors/{bypass_id}', params=params, response_type='json')

    def modifyInlineBypassConnector(self, bypass_id, args):
        """ modifyInlineBypassConnector:
        Update the properties of an existing Inline Bypass Connector.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.modifyInlineBypassConnector('117', {"side_b_ports": [14]})
        b''
        """
        return self._sendRequest(http_method='PUT', url=f'/bypass_connectors/{bypass_id}', args=args, response_type='none')

    def deleteInlineBypassConnector(self, bypass_id):
        """ deleteInlineBypassConnector :
        Remove an existing inline Tool Bypass from the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.deleteInlineBypassConnector('117')
        b''
        """
        return self._sendRequest(http_method='DELETE', url=f'/bypass_connectors/{bypass_id}', args=None, response_type='none')


    # /cache

    def getCacheStamp(self):
        """ getCacheStamp :
        Retrieve the latest cache stamp.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url='/cache/stamp', response_type='json')

    def getCacheUpdates(self, stamp):
        """ getCacheUpdates :
        Retrieve cache updates that occurred after the supplied stamp.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url=f'/cache/updates/{stamp}', response_type='json')


    # /capture_resources

    def getAllCaptures(self):
        """ getAllCaptures :
        Fetch a list containing the summaries for all the captures in the system.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.getAllCaptures()
        [{u'id': 546, u'name': u'L4-CAP'}]
        """
        return self._sendRequest(http_method='GET', url='/capture_resources', response_type='json')

    def searchCaptures(self, args):
        """ searchCaptures :
        Search for a specific capture in the system by certain properties.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.searchCaptures({'status': 'IDLE_WITH_DATA'})
        [{u'id': 177, u'name': u'L1-CAP'}]
        """
        return self._sendRequest(http_method='POST', url='/capture_resources/search', args=args, response_type='json')

    def getCapture(self, resource):
        """ getCapture :
        Fetch the properties of a capture object.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.getCapture('177')
        {u'trailer_stripping_mode': u'USE_LOCAL_TIME', u'capture_count_unit': u'PACKETS', u'id': 177, u'has_dropped_packets': False, u'max_buffer_capacity': 14680063, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'connect_disconnect_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'status': u'IDLE_WITH_DATA', u'fill_to_trigger_position': False, u'description': None, u'trigger_position': 25, u'resource_status': u'READY', u'license_status': u'NOT_PRESENT', u'trailer_stripping_enabled': False, u'buffer_size': 200, u'trigger_criteria': {u'logical_operation': u'AND'}, u'name': u'L1-CAP', u'buffer_type': u'LINEAR', u'capture_source': 307, u'lineboard_id': 175, u'default_name': u'L1-CAP', u'trigger_mode': u'MANUAL', u'mod_count': 3, u'history': [{u'type': u'MODIFY', u'time': 1442009546427, u'caused_by': u'admin', u'details': None, u'props': [u'CAPTURE_SOURCE', u'BUFFER_SIZE']}]}
        """
        return self._sendRequest(http_method='GET', url=f'/capture_resources/{resource}', response_type='json')

    def modifyCapture(self, resource, args):
        """ modifyCapture :
        Update the properties of an existing capture resource.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.modifyCapture('L1-CAP', {'buffer_size': 100})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/capture_resources/{resource}', args=args, response_type='none')

    def deleteCaptureFile(self, resource, args):
        """ deleteCaptureFile :
        Deletes a capture file from a capture resource.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.deleteFileCapture('546', {'file_name': 'File 1.pcap'})
        ''
        """
        return self._sendRequest(http_method='DELETE', url=f'/capture_resources/{resource}/delete_file', args=args, response_type='none')

    def disableCapture(self, resource):
        """ disableCapture :
        Disables a capture resource by disconnecting the attached filter.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.disableCapture('L1-CAP')
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/capture_resources/{resource}/disable', args=None, response_type='none')

    def downloadCaptureFile(self, resource, args, local_file_name=None):
        """ downloadCaptureFile :
        Downloads a capture file of capture resource.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.downloadFileCapture('L1-CAP', {'file_name': 'Suspicious Netflow export.pcap'})
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest(http_method='POST', url=f'/capture_resources/{resource}/download_file', args=args, response_type='bytes')
        if local_file_name is None:
            local_file_name = file_name
        f = open(local_file_name, 'wb')
        f.write(file)
        f.close()

    def enableCapture(self, resource, args):
        """ enableCapture :
        Enables a capture by attaching a filter to it.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.enableCapture('546', {'filter_id': '524'})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/capture_resources/{resource}/enable', args=args, response_type='none')

    def listCaptureFiles(self, resource):
        """ listCaptureFiles :
        Fetch a list containing the summaries for all the captures in the system.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.listFilesCapture('546')
        [{u'access_settings': {u'policy': u'REQUIRE_MEMBER', u'groups': [u'group1', u'group2']}, u'description': u'Capture file description', u'capture_date': 1440119146145, u'name': u'File 2.pcap', u'packet_count': 32, u'duration': 12, u'size': 262144, u'access_policy_id': u'7300-demodemo'}]
        """
        return self._sendRequest(http_method='GET', url=f'/capture_resources/{resource}/files', args=None, response_type='json')

    def ftpTransferCapture(self, resource, args):
        """ ftpTransferCapture :
        Transfers via FTP a capture file or the buffer of a capture resource.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.ftpTransferCapture('317', {'address': '10.218.6.43', 'file_name': '150604_085131.pcap', 'password': '****', 'range_type': 'ALL_PACKETS', 'remote_file_name': 'fred-api.pcap', 'user': 'fredmota', 'port': 21})
        '{\n        "id": 2,\n        "progress": 0,\n        "state": "PENDING"\n}'
        """
        return self._sendRequest(http_method='POST', url=f'/capture_resources/{resource}/ftp_file', args=args, response_type='json')

    def resetCaptureBuffer(self, resource):
        """ resetCaptureBuffer :
        Resets / clears the capture resource buffer.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/capture_resources/{resource}/reset_buffer', args=None, response_type='none')

    def saveBufferCapture(self, resource, args):
        """ saveBufferCapture :
        Saves the buffer of a capture resource to a new capture file.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.saveBufferCapture('L1-CAP', {'file_name': 'wep_api_test.pcap', 'description': 'Web API Saved File', 'range' : '1-10', 'range_type': 'RANGE'})
        {u'progress': 0, u'state': u'PENDING', u'id': 1}
        """
        return self._sendRequest(http_method='POST', url=f'/capture_resources/{resource}/save_buffer', args=args, response_type='json')

    def scpTransferCapture(self, resource, args):
        """ scpTransferCapture :
        Transfers via SCP a capture file or the buffer of a capture resource.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.scpTransferCapture('317', {'address': '10.218.30.1', 'file_name': '150604_085131.pcap', 'password': 'Anue', 'port': 22, 'range_type': 'ALL_PACKETS', 'remote_file_name': 'fred-api.pcap', 'user': 'support'})
        '{\n        "id": 3,\n        "progress": 0,\n        "state": "PENDING"\n}'
        """
        return self._sendRequest(http_method='POST', url=f'/capture_resources/{resource}/scp_file', args=args, response_type='json')

    def startCapture(self, resource):
        """ startCapture :
        Starts a capture resource to capture packets via the attached filter.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.startCapture('L1-CAP')
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/capture_resources/{resource}/start', args=None, response_type='none')

    def stopCapture(self, resource):
        """ stopCapture :
        Stops a capture resource to capture packets via the attached filter.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.stopCapture('L1-CAP')
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/capture_resources/{resource}/stop', args=None, response_type='none')

    def getTriggerPacketCapture(self, resource):
        """ getTriggerPacketCapture :
        Gets the number of the packet that triggered the capture.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto1.getTriggerPacketCapture('546')
        {u'triggerPacketNumber': 1025}
        """
        return self._sendRequest(http_method='GET', url=f'/capture_resources/{resource}/trigger_packet', response_type='json')


    # /cte_ae_resources

    def getAllIfcAnalysisEngines(self):
        """ getAllIfcAnalysisEngines :
        Fetch a list containing the summaries for all IFC Analysis Engine resources.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_ae_resources', response_type='json')

    def searchIfcAnalysisEngines(self, args):
        """ searchIfcAnalysisEngines :
        Search a specific IFC Analysis Engine resource by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_ae_resources/search', args=args, response_type='json')

    def getIfcAnalysisEngineWritableProperties(self):
        """ getIfcAnalysisEngineWritableProperties :
        List writable property names for IFC Analysis Engine resources.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url='/cte_ae_resources/writable_props', args=None, response_type='json')

    def getIfcAnalysisEngine(self, ae_id):
        """ getIfcAnalysisEngine :
        Fetch the properties of an IFC Analysis Engine resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_ae_resources/{ae_id}', response_type='json')

    def modifyIfcAnalysisEngine(self, ae_id, args):
        """ modifyIfcAnalysisEngine :
        Update the properties of an existing IFC Analysis Engine Resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_ae_resources/{ae_id}', args=args, response_type='none')

    def applyTemplateToIfcAnalysisEngine(self, ae_id, args):
        """ applyTemplateToIfcAnalysisEngine :
        Apply an object template to an IFC Analysis Engine resource.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_ae_resources/{ae_id}/apply_template', args=args, response_type='none')

    def createTemplateFromIfcAnalysisEngine(self, ae_id, args):
        """ createTemplateFromIfcAnalysisEngine :
        Create an object template from an IFC Analysis Engine resource.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_ae_resources/{ae_id}/create_template', args=args, response_type='json')

    def disableIfcAnalysisEngine(self, ae_id):
        """ disableIfcAnalysisEngine :
        Detaches an IFC Analysis Engine resource from a filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_ae_resources/{ae_id}/disable', args=None, response_type='none')

    def enableIfcAnalysisEngine(self, ae_id, args):
        """ enableIfcAnalysisEngine :
        Attaches an IFC Analysis Engine resource to a filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_ae_resources/{ae_id}/enable', args=args, response_type='none')


    # /cte_atip_resources

    def getAllIfcAppStacks(self):
        """ getAllIfcAppStacks :
        Fetch summaries for all IFC AppStack resources.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(http_method='GET', url='/cte_atip_resources', response_type='json')

    def searchIfcAppStacks(self, args):
        """ searchIfcAppStacks :
        Search IFC AppStack resources by supported properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url='/cte_atip_resources/search', args=args, response_type='json')

    def getIfcAppStack(self, appstack_id):
        """ getIfcAppStack :
        Fetch the properties of an IFC AppStack resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(http_method='GET', url=f'/cte_atip_resources/{appstack_id}', response_type='json')

    def modifyIfcAppStack(self, appstack_id, args):
        """ modifyIfcAppStack :
        Update an IFC AppStack resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_atip_resources/{appstack_id}', args=args, response_type='none')

    def deleteIfcAppStack(self, appstack_id):
        """ deleteIfcAppStack :
        Remove an IFC AppStack resource.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='DELETE', url=f'/cte_atip_resources/{appstack_id}', args=None, response_type='none')

    def disableIfcAppStack(self, appstack_id):
        """ disableIfcAppStack :
        Disable an IFC AppStack resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_atip_resources/{appstack_id}/disable', args=None, response_type='none')

    def enableIfcAppStack(self, appstack_id, args):
        """ enableIfcAppStack :
        Enable an IFC AppStack resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_atip_resources/{appstack_id}/enable', args=args, response_type='none')


    # /cte_capture_resources

    def getAllCteCaptures(self):
        """ getAllCteCaptures :
        Fetch a list containing the summaries for all the captures in the system.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_capture_resources', response_type='json')

    def searchCteCaptures(self, args):
        """ searchCteCaptures :
        Search for a specific capture in the system by certain properties.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_capture_resources/search', args=args, response_type='json')

    def getCteCapture(self, resource):
        """ getCteCapture :
        Fetch the properties of a capture object.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_capture_resources/{resource}', response_type='json')

    def modifyCteCapture(self, resource, args):
        """ modifyCteCapture :
        Update the properties of an existing capture resource.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_capture_resources/{resource}', args=args, response_type='none')

    def deleteCteCaptureFile(self, resource, args):
        """ deleteCteCaptureFile :
        Deletes a capture file from a capture resource.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_capture_resources/{resource}/delete_file', args=args, response_type='none')

    def disableCteCapture(self, resource):
        """ disableCteCapture :
        Detaches an IFC Capture resource from a filter.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_capture_resources/{resource}/disable', args=None, response_type='none')

    def downloadCteCaptureFile(self, resource, args, local_file_name=None):
        """ downloadCteCaptureFile :
        Downloads a capture file of capture resource.
        Platforms:
            7300/7303

        Example:
        """

        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest(http_method='POST', url=f'/cte_capture_resources/{resource}/download_file', args=args, response_type='bytes')
        if local_file_name is None:
            local_file_name = file_name
        f = open(local_file_name, 'wb')
        f.write(file)
        f.close()

    def enableCteCapture(self, resource, args):
        """ enableCteCapture :
        Attaches an IFC Capture resource to a filter.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_capture_resources/{resource}/enable', args=args, response_type='none')

    def listCteCaptureFiles(self, resource):
        """ listCteCaptureFiles :
        Fetch a list containing the summaries for all the captures in the system.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_capture_resources/{resource}/files', args=None, response_type='json')

    def resetCteCaptureBuffer(self, resource):
        """ resetCteCaptureBuffer :
        Resets / clears the capture resource buffer.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_capture_resources/{resource}/reset_buffer', args=None, response_type='none')

    def saveCteBufferCaptures(self, resource, args):
        """ saveCteBufferCaptures :
        Search for a specific capture in the system by certain properties.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/cte_capture_resources/{resource}/save_buffer', args=args, response_type='json')

    def startCteCapture(self, resource):
        """ startCteCapture :
        Starts a capture resource to capture packets via the attached filter.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_capture_resources/{resource}/start', args=None, response_type='none')

    def stopCteCapture(self, resource):
        """ stopCteCapture :
        Stops a capture resource to capture packets via the attached filter.
        Platforms:
            7300/7303

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_capture_resources/{resource}/stop', args=None, response_type='none')


    # /cte_cluster

    def getCteCluster(self):
        """ getCteCluster :
        Retrieve the properties of the IFC cluster.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(http_method='GET', url='/cte_cluster', response_type='json')

    def modifyCteCluster(self, args):
        """ modifyCteCapture :
        Update the properties of the IFC cluster.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url='/cte_cluster', args=args, response_type='none')


    # /cte_connections

    def getAllCteConnections(self):
        """ getAllCteConnections :
        Fetch a list containing the summaries for all the CTE connections.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_connections', response_type='json')

    def createCteConnection(self, args):
        """ createCteConnection :
        Create a new CTE connection in the system.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_connections', args=args, response_type='json')

    def searchCteConnections(self, args):
        """ searchCteConnections :
        Search a specific CTE connection by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_connections/search', args=args, response_type='json')

    def getCteConnection(self, cte_id):
        """ getCteConnection :
        Fetch the properties of a CTE connection.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_connections/{cte_id}', response_type='json')

    def modifyCteConnection(self, cte_id, args):
        """ modifyCteConnection :
        Update the properties of an existing CTE connection.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_connections/{cte_id}', args=args, response_type='none')

    def deleteCteConnection(self, cte_id):
        """ deleteCteConnection :
        Remove a CTE connection.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/cte_connections/{cte_id}', args=None, response_type='none')


    # /cte_custom_icons

    def getAllIfcIcons(self):
        """ getAllIfcIcons :
        Fetch a list containing the summaries for all IFC Custom Icons.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_custom_icons', response_type='json')

    def createIfcIcon(self, args, file_name):
        """ createIfcIcon:
        Create a new IFC Custom Icon.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """

        f = {'file': (file_name, open(file_name ,'rb'), 'application/octet-stream')}
        return self._sendRequest(http_method='POST', url='/cte_custom_icons', args=args, file_info=f, response_type='json')

    def searchIfcIcons(self, args):
        """ searchIfcIcons :
        Search a specific IFC Custom Icon by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url='/cte_custom_icons/search', args=args, response_type='json')

    def getIfcIcon(self, icon_id):
        """ getIfcIcon :
        Fetch the properties of an IFC Custom Icon.
        Example:
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(http_method='GET', url=f'/cte_custom_icons/{icon_id}', response_type='json')

    def modifyIfcIcon(self, icon_id, args):
        """ modifyIfcIcon :
        Update the properties of an existing IFC Custom Icon.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_custom_icons/{icon_id}', args=args, response_type='none')

    def deleteIfcIcon(self, icon_id):
        """ deleteIfcIcon :
        Remove an IFC Custom Icon.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/cte_custom_icons/{icon_id}', args=None, response_type='none')


    # /cte_dual_home_tools

    def getAllIfcDualHomeTools(self):
        """ getAllIfcDualHomeTools :
        Fetch a list containing the summaries for all IFC dual home tools.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_dual_home_tools', response_type='json')

    def createIfcDualHomeTool(self, args):
        """ createIfcDualHomeTool :
        Create a new IFC dual home tool in the system.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_dual_home_tools', args=args, response_type='json')

    def searchIfcDualHomes(self, args):
        """ searchIfcDualHomes :
        Search a specific IFC dual home tool by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_dual_home_tools/search', args=args, response_type='json')

    def getIfcDualHomeTool(self, dual_home_id):
        """ getIfcDualHomeTool :
        Fetch the properties of an IFC dual home tool.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_dual_home_tools/{dual_home_id}', response_type='json')

    def modifyIfcDualHome(self, dual_home_id, args):
        """ modifyIfcDualHome :
        Update the properties of an existing IFC dual home tool.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_dual_home_tools/{dual_home_id}', args=args, response_type='none')

    def deleteIfcDualHomeTool(self, dual_home_id):
        """ deleteIfcDualHomeTool :
        Remove an IFC dual home tool.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/cte_dual_home_tools/{dual_home_id}', args=None, response_type='none')


    # /cte_filters

    def getAllCteFilters(self):
        """ getAllCteFilters :
        Fetch a list containing the summaries for all the CTE filters.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_filters', response_type='json')

    def createCteFilter(self, args, allowTemporaryDataLoss=False):
        """ createCteFilter :
        Create a new CTE filter in the system.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(
            http_method='POST',
            url='/cte_filters',
            args=args,
            params={'allowTemporaryDataLoss': allowTemporaryDataLoss},
            response_type='json'
        )

    def searchCteFilters(self, args):
        """ searchCteFilters :
        Search a specific CTE filter by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_filters/search', args=args, response_type='json')

    def getCteFilterWritableProperties(self):
        """ getCteFilterWritableProperties :
        List writable property names for IFC filters.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url='/cte_filters/writable_props', args=None, response_type='json')

    def getCteFilter(self, cte_filter_id):
        """ getCteFilter :
        Fetch the properties of a CTE filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_filters/{cte_filter_id}', response_type='json')

    def modifyCteFilter(self, cte_filter_id, args, allowTemporaryDataLoss=False):
        """ modifyCteFilter :
        Update the properties of an existing CTE filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(
            http_method='PUT',
            url=f'/cte_filters/{cte_filter_id}',
            args=args,
            params={'allowTemporaryDataLoss': allowTemporaryDataLoss},
            response_type='none'
        )

    def deleteCteFilter(self, cte_filter_id, allowTemporaryDataLoss=False):
        """ deleteCteFilter :
        Remove a CTE filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(
            http_method='DELETE',
            url=f'/cte_filters/{cte_filter_id}',
            args=None,
            params={'allowTemporaryDataLoss': allowTemporaryDataLoss},
            response_type='none'
        )

    def applyTemplateToCteFilter(self, cte_filter_id, args):
        """ applyTemplateToCteFilter :
        Apply an object template to an IFC filter.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_filters/{cte_filter_id}/apply_template', args=args, response_type='none')

    def createTemplateFromCteFilter(self, cte_filter_id, args):
        """ createTemplateFromCteFilter :
        Create an object template from an IFC filter.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_filters/{cte_filter_id}/create_template', args=args, response_type='json')


    # /cte_members

    def getAllCteMembers(self):
        """ getAllCteMembers :
        Fetch a list containing the summaries for all the CTE members.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        >>> nto.getAllCteMembers()
	[{'cte_id': 'S2', 'ip_address': '192.168.214.12', 'uuid': 'b9eeaf6a-16ca-39f3-bdf5-7620aed91b62'}, {'cte_id': 'S3', 'ip_address': '192.168.214.13', 'uuid': 'e2ab7c65-b21e-38cc-9c3b-642b5e36429e'}, {'cte_id': 'S1', 'ip_address': '192.168.214.11', 'uuid': '67f6274e-0ac0-3d89-af9b-1ec09a2253fc'}]
        """
        return self._sendRequest(http_method='GET', url='/cte_members', response_type='json')

    def getCteMembersDetails(self, ids=None):
        """ getCteMembersDetails :
        Fetch detailed properties for all or selected IFC members.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url='/cte_members/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchCteMembers(self, args):
        """ searchCteMembers :
        Search a specific CTE member by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_members/search', args=args, response_type='json')

    def getCteMember(self, cte_member_id):
        """ getCteMember :
        Fetch the properties of a CTE member.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        >>> nto.getCteMember('S1')
	{'cluster_role': 'CONTROLLER_NODE', 'cte_id': 'S1', 'dtsp_version': None, 'fips_mode_enabled': False, 'history': None, 'ip_address': '192.168.214.11', 'license_feature_list': [{'comment': '7300-demodemo', 'creation_time': 1671468910190, 'description': 'Maintenance Contract', 'expiration_days': 90, 'expiration_time': 1685941199052, 'feature_type': 'MAINTENANCE', 'generic_netservice_sub_features': [], 'serial_number': 'demo', 'sub_features': []}, {'comment': 'exp-card', 'creation_time': 16
        """
        return self._sendRequest(http_method='GET', url=f'/cte_members/{cte_member_id}', response_type='json')

    def modifyCteMember(self, cte_member_id, args):
        """ modifyCteMember :
        Update the properties of an existing IFC Member.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_members/{cte_member_id}', args=args, response_type='none')


    # /cte_monitors

    def getAllCteMonitors(self):
        """ getAllCteMonitors :
        Fetch a list containing the summaries for all IFC monitors.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_monitors', response_type='json')

    def createCteMonitor(self, args):
        """ createCteMonitor :
        The IFC monitors resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_monitors', args=args, response_type='json')

    def searchCteMonitors(self, args):
        """ searchCteMonitors :
        Search a specific IFC monitor by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_monitors/search', args=args, response_type='json')

    def getCteMonitor(self, cte_monitor_id):
        """ getCteMonitor :
        Fetch the properties of an IFC monitor.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_monitors/{cte_monitor_id}', response_type='json')

    def modifyCteMonitor(self, cte_monitor_id, args):
        """ modifyCteMonitor :
        Update the properties of an existing IFC monitor.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_monitors/{cte_monitor_id}', args=args, response_type='none')

    def deleteCteMonitor(self, cte_monitor_id):
        """ deleteCteMonitor :
        Remove an IFC monitor.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/cte_monitors/{cte_monitor_id}', args=None, response_type='none')


    # /cte_netflow_resources

    def getAllCteNetflowResources(self):
        """ getAllCteNetflowResources :
        Fetch a list containing the summaries for all IFC Netflow resources.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_netflow_resources', response_type='json')

    def searchCteNetflowResources(self, args):
        """ searchCteNetflowResources :
        Search a specific IFC Netflow resource by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_netflow_resources/search', args=args, response_type='json')

    def getCteNetflowResource(self, cte_netflow_resource_id):
        """ getCteNetflowResource :
        Fetch the properties of an IFC Netflow resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_netflow_resources/{cte_netflow_resource_id}', response_type='json')

    def modifyCteNetflowResource(self, cte_netflow_resource_id, args):
        """ modifyCteNetflowResource :
        Update the properties of an existing IFC Netflow resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_netflow_resources/{cte_netflow_resource_id}', args=args, response_type='none')

    def disableCteNetflowResource(self, cte_netflow_resource_id, args):
        """ disableCteNetflowResource :
        Detaches an IFC Netflow resource from an IFC filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_netflow_resources/{cte_netflow_resource_id}/disable', args=args, response_type='none')

    def enableCteNetflowResource(self, cte_netflow_resource_id, args):
        """ enableCteNetflowResource :
        Attaches an IFC Netflow to an IFC filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_netflow_resources/{cte_netflow_resource_id}/enable', args=args, response_type='none')

    def getCteNetflowResourceBandwidth(self, cte_netflow_resource_id):
        """ getCteNetflowResourceBandwidth :
        Gets the bandwidth details for the IFC Netflow resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(
            http_method='GET',
            url=f'/cte_netflow_resources/{cte_netflow_resource_id}/get_bandwidth_details',
            response_type='json'
        )


    # /cte_one_port_ns_resources

    def getAllIfcNetservices(self):
        """ getAllIfcNetservices :
        Fetch a list containing the summaries for all IFC Netservice resources.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_one_port_ns_resources', response_type='json')

    def searchIfcNetservices(self, args):
        """ searchIfcNetservices :
        Search a specific IFC Netservice resource by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_one_port_ns_resources/search', args=args, response_type='json')

    def getIfcNetservice(self, netservice_id):
        """ getIfcNetservice :
        Fetch the properties of an IFC Netservice resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_one_port_ns_resources/{netservice_id}', response_type='json')

    def modifyIfcNetservice(self, netservice_id, args):
        """ modifyIfcNetservice :
        Update the properties of an existing IFC Netservice Resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_one_port_ns_resources/{netservice_id}', args=args, response_type='none')

    def disableIfcNetservice(self, netservice_id):
        """ disableIfcNetservice :
        Dettaches an IFC Netservice resource from a filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_one_port_ns_resources/{netservice_id}/disable', args=None, response_type='none')

    def enableIfcNetservice(self, netservice_id, args):
        """ enableIfcNetservice :
        Attaches an IFC Netservice resource to a filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_one_port_ns_resources/{netservice_id}/enable', args=args, response_type='none')


    # /cte_operations

    def changeClusterRole(self, args):
        """ changeClusterRole :
        This action will change the role of a node in the cluster. If the node is
        CONTROLLER, then it will become FABRIC. IF the node is FABRIC, then it will
        become CONTROLLER.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/change_role', args=args, response_type='json')

    def createCteTopology(self, args):
        """ createCteTopology :
        Create a CTE topology.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/create_topology', args=args, response_type='json')

    def autoDetectCteChannels(self, args):
        """ autoDetectCteChannels :
        Start, stop, or view automatic channel detection for IFC Analysis Engines.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_auto_detect_channels', args=args, response_type='json')

    def changeCteSpeedConfiguration(self, args):
        """ changeCteSpeedConfiguration :
        Change speed configuration.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_change_speed_configuration', args=args, response_type='json')

    def clearCteAeChannelStatsHistory(self, args):
        """ clearCteAeChannelStatsHistory :
        Clears the Burst and/or Latency & Jitter Stats History Files from the Disk per AE.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_clear_ae_channel_statistics_history', args=args, response_type='json')

    def clearCteConfig(self):
        """ clearCteConfig :
        Create a CTE topology.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_clear_config', args={}, response_type='json')

    def clearCteFiltersAndPort(self):
        """ clearCteFiltersAndPort :
        This command deletes all filters and port groups and sets all ports to default values..
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_clear_filters_and_ports', args={}, response_type='json')

    def getCteAvailableFilterCriteria(self, args=None):
        """ getCteAvailableFilterCriteria :
        Return a list of filter criteria which can be used given an already present set of filter criteria.
        This action is useful for a user interface which defines a filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_get_available_filter_criteria', args={} if args is None else args, response_type='json')

    def getCteNeighbors(self, args=None):
        """ getCteNeighbors :
        Get discovered LLDP neighbors from cluster for specified list of members and specified lisf of ports.
        If both lists of members and ports given are empty or not given at all, then will return all discovered
        LLDP neighbors for all ports from members of cluster, that are valid for LLDP and have valid neighbors
        records. If only a list of members is specified, then will return all discovered LLDP neighbors for all
        ports from these members. If only a list of ports is specified, then will return all discovered LLDP
        neighbors for specified ports.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_get_neighbors', args={} if args is None else args, response_type='none')

    def getPortTunnelingInfo(self):
        """ getPortTunnelingInfo :
        Get the tunnel termination and origination settings.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_get_port_tunneling_info', args={}, response_type='json')

    def getTransceiverInfoForMembersInCluster(self, args=None):
        """ getTransceiverInfoForMembersInCluster :
        Get transceiver info for specified list of members. If list of members is empty or not given at all,
        then will return tranceiver info for all members in the cluster. If a list of members is specified,
        then will return tranceiver info for the members specified in the list.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_get_transceiver_info', args={} if args is None else args, response_type='json')

    def installCteDtsp(self, args):
        """ installCteDtsp :
        Install TradeVision DTSP to all the TradeVision boxes in the IFC.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """

        file_name = args['file_name']
        f = {'file': (file_name, open(file_name ,'rb'), 'application/octet-stream')}
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_install_dtsp', args=args, file_info=f, response_type='json')

    def interruptCteAnalysisEngineTraffic(self, args):
        """ interruptCteAnalysisEngineTraffic :
        Interrupt traffic for a given analysis engine (AE).
        This will temporarily (10 sec) turn off traffic to AE.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_interrupt_ae_traffic', args=args, response_type='json')

    def resetCteEventRateLimiterStatus(self, args):
        """ resetCteEventRateLimiterStatus :
        Reset the event rate limiter status for the given event type.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_reset_event_rate_limiter_status', args=args, response_type='json')

    def setCteStackMode(self, args):
        """ setCteStackMode :
        Set the Stack mode of a switch while in IFC/CTE mode.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_set_stack_mode', args=args, response_type='json')

    def updateCteUpdateSingleIpAddress(self, args):
        """ updateCteUpdateSingleIpAddress :
        This action allows a single IP address to be added to or removed
        from a filter with an existing IP address criterion.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/cte_update_single_ip_addr', args=args, response_type='json')

    def disbandCteTopology(self):
        """ disbandCteTopology :
        Disband the CTE topology. The local device and all other members
        that can be notified will be forced out of the topology. Manual
        disband on unreachable devices is required to recover them.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/disband_topology', args={}, response_type='json')

    def discoverCteConnections(self):
        """ discoverCteConnections :
        Discover and create direct connections between members in IFC topology.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/discover_connections', args={}, response_type='json')

    def exportCteTopology(self, args):
        """ exportCteTopology :
        Export topology configuration to a file.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/export', args=args, response_type='bytes')

    def forceRemoveFromCteTopology(self, args):
        """ forceRemoveFromCteTopology :
        Given a failed member of a CTE topology by its IPv4 address, force
        remove it from the topology.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/force_remove', args=args, response_type='json')

    def importCteTopology(self, args):
        """ importCteTopology :
        Import topology configuration from a file.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/import', args=args, response_type='json')

    def joinCteTopology(self, args):
        """ joinCteTopology :
        Join the current stack to a CTE topology.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/join_topology', args=args, response_type='json')

    def leaveCteTopology(self, args):
        """ leaveCteTopology :
        Given a member of a CTE topology by its IPv4 address, this action will
        disconnect it from the topology.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/leave_topology', args=args, response_type='json')

    def optimizeCteRoutes(self):
        """ optimizeCteRoutes :
        This command will perform route reconfiguration to ensure maximum filter coverage and
        better traffic load balancing across the cluster.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_operations/optimize_routes', args={}, response_type='json')

    def setGlobalNetStackTunnelTermination(self, args):
        """ setGlobalNetStackTunnelTermination :
        Set global NetStack tunnel termination settings for a given node in the IFC cluster.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(
            http_method='POST',
            url='/cte_operations/set_member_netstack_tunnel_termination_system_settings',
            args=args,
            response_type='json'
        )


    # /cte_port_groups

    def getAllCtePortGroups(self):
        """ getAllCtePortGroups :
        Fetch a list containing the summaries for all the CTE port groups.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_port_groups', response_type='json')

    def createCtePortGroup(self, args):
        """ createCtePortGroup :
        Create a new IFC port group in the system.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_port_groups', args=args, response_type='json')

    def searchCtePortGroups(self, args):
        """ searchCtePortGroups :
        Search a specific CTE port group by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_port_groups/search', args=args, response_type='json')

    def getCtePortGroupWritableProperties(self):
        """ getCtePortGroupWritableProperties :
        List writable property names for IFC port groups.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url='/cte_port_groups/writable_props', args=None, response_type='json')

    def getCtePortGroup(self, cte_port_group_id):
        """ getCtePortGroup :
        Fetch the properties of a CTE port group.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_port_groups/{cte_port_group_id}', response_type='json')

    def modifyCtePortGroup(self, cte_port_group_id, args):
        """ modifyCtePortGroup :
        Update the properties of an existing IFC port group.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_port_groups/{cte_port_group_id}', args=args, response_type='none')

    def deleteCtePortGroup(self, cte_port_group_id):
        """ deleteCtePortGroup :
        Remove an IFC port group.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/cte_port_groups/{cte_port_group_id}', args=None, response_type='none')

    def applyTemplateToCtePortGroup(self, cte_port_group_id, args):
        """ applyTemplateToCtePortGroup :
        Apply an object template to an IFC port group.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_port_groups/{cte_port_group_id}/apply_template', args=args, response_type='none')

    def createTemplateFromCtePortGroup(self, cte_port_group_id, args):
        """ createTemplateFromCtePortGroup :
        Create an object template from an IFC port group.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_port_groups/{cte_port_group_id}/create_template', args=args, response_type='json')

    def disableCtePortGroup(self, cte_port_group_id):
        """ disableCtePortGroup :
        Disables an IFC port group by disabling all contained IFC ports.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_port_groups/{cte_port_group_id}/disable', args=None, response_type='none')

    def enableCtePortGroup(self, cte_port_group_id):
        """ enableCtePortGroup :
        Enables an IFC port group by enabling all contained IFC ports.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_port_groups/{cte_port_group_id}/enable', args=None, response_type='none')


    # /cte_ports

    def getAllCtePorts(self):
        """ getAllCtePorts :
        Fetch a list containing the summaries for all the CTE ports.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_ports', response_type='json')

    def createCtePort(self, args):
        """ createCtePort :
        Create a new CTE port on the system. This can be used only to
        create virtual ports for GRE origination on a Vision 7300 system.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_ports', args=args, response_type='json')

    def searchCtePorts(self, args):
        """ searchCtePorts :
        Search a specific CTE port by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_ports/search', args=args, response_type='json')

    def getCtePortWritableProperties(self):
        """ getCtePortWritableProperties :
        List writable property names for IFC ports.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url='/cte_ports/writable_props', args=None, response_type='json')

    def getCtePort(self, cte_port_id):
        """ getCtePort :
        Fetch the properties of a CTE port.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_ports/{cte_port_id}', response_type='json')

    def modifyCtePort(self, cte_port_id, args):
        """ modifyCtePort :
        Update the properties of an existing IFC port.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_ports/{cte_port_id}', args=args, response_type='none')

    def deleteCtePort(self, cte_port_id):
        """ deleteCtePort :
        Remove a CTE port from the system. This can be used only to
        remove virtual ports for GRE origination on a Vision 7300 system.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/cte_ports/{cte_port_id}', args=None, response_type='none')

    def applyTemplateToCtePort(self, cte_port_id, args):
        """ applyTemplateToCtePort :
        Apply an object template to an IFC port.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_ports/{cte_port_id}/apply_template', args=args, response_type='none')

    def clearCtePort(self, cte_port):
        """ clearCtePort :
        Resets an IFC port to default configuration. No properties are required in the HTTP Body.

        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_ports/{cte_port}/clear', args=None, response_type='none')

    def createTemplateFromCtePort(self, cte_port_id, args):
        """ createTemplateFromCtePort :
        Create an object template from an IFC port.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/cte_ports/{cte_port_id}/create_template', args=args, response_type='json')

    def deleteCtePortPcapFiles(self, cte_port_id, args):
        """ deleteCtePortPcapFiles :
        Delete one or more PCAP files from an IFC port.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='DELETE', url=f'/cte_ports/{cte_port_id}/delete_pcap_files', args=args, response_type='json')

    def downloadCtePortPcapFiles(self, cte_port_id, args):
        """ downloadCtePortPcapFiles :
        Download one or more PCAP files from an IFC port.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url=f'/cte_ports/{cte_port_id}/download_pcap_files', args=args, response_type='bytes')

    def getCtePortPcapFileList(self, cte_port_id):
        """ getCtePortPcapFileList :
        Get the list of PCAP files available for an IFC port.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        return self._sendRequest(http_method='GET', url=f'/cte_ports/{cte_port_id}/get_pcap_file_list', response_type='json')

    def startCtePortCapture(self, cte_port_id, args=None):
        """ startCtePortCapture :
        Start packet capture on an IFC port.
        Platforms:
            TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision Edge 50,
            Vision One, Vision X

        """
        if args is None:
            args = {}
        return self._sendRequest(http_method='PUT', url=f'/cte_ports/{cte_port_id}/start_capture', args=args, response_type='none')


    # /cte_recirculated_afm_resources

    def getAllIfcPacketStacks(self):
        """ getAllIfcPacketStacks :
        Fetch a list containing the summaries for all IFC PacketStack resources.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_recirculated_afm_resources', response_type='json')

    def searchIfcPacketStacks(self, args):
        """ searchIfcPacketStacks :
        Search a specific IFC PacketStack resource by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_recirculated_afm_resources/search', args=args, response_type='json')

    def getIfcPacketStack(self, packet_stack_id):
        """ getIfcPacketStack :
        Fetch the properties of an IFC PacketStack resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_recirculated_afm_resources/{packet_stack_id}', response_type='json')

    def modifyIfcPacketStack(self, packet_stack_id, args):
        """ modifyIfcPacketStack :
        Update the properties of an existing IFC PacketStack resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_recirculated_afm_resources/{packet_stack_id}', args=args, response_type='none')

    def disableIfcPacketStack(self, packet_stack_id, args):
        """ disableIfcPacketStack :
        Dettaches an IFC PacketStack resource from an IFC port, an IFC port group, or an IFC filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_recirculated_afm_resources/{packet_stack_id}/disable', args=args, response_type='none')

    def enableIfcPacketStack(self, packet_stack_id, args):
        """ enableIfcPacketStack :
        Attaches an IFC PacketStack to an IFC port, an IFC port group, or an IFC filter.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_recirculated_afm_resources/{packet_stack_id}/enable', args=args, response_type='none')

    def getIfcPacketStackBandwidth(self, packet_stack_id):
        """ getIfcPacketStackBandwidth :
        Gets the bandwidth details for the IFC PacketStack resource.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(
            http_method='PUT',
            url=f'/cte_recirculated_afm_resources/{packet_stack_id}/get_bandwidth_details',
            response_type='json'
        )

    def setIfcPacketStackLoadBalance(self, packet_stack_id, args):
        """ setIfcPacketStackLoadBalance :
        Set load balance weights on PacketStack data lanes( internal ports).
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        """
        return self._sendRequest(
            http_method='PUT',
            url=f'/cte_recirculated_afm_resources/{packet_stack_id}/set_load_balance',
            args=args,
            response_type='none'
        )


    # /cte_remote_system

    def getAllCtes(self):
        """ getAllCtes :
        Fetch a list containing the summaries for all the CTE remote
        systems available on this device.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_remote_system', response_type='json')

    def connectCte(self, args):
        """ connectCte :
        Make a new CTE remote system available on the local device.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_remote_system', args=args, response_type='json')

    def searchCtes(self, args):
        """ searchCtes :
        Search by certain properties for a specific CTE remote systems available on this device.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_remote_system/search', args=args, response_type='json')

    def getCte(self, cte_id):
        """ getCte :
        Fetch the properties of a CTE remote system available on the local device.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_remote_system/{cte_id}', response_type='json')

    def modifyCte(self, cte_id, args):
        """ modifyCte :
        Update the connection details of a CTE remote system available on the local device.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/cte_remote_system/{cte_id}', args=args, response_type='none')

    def disconnectCte(self, cte_id):
        """ disconnectCte :
        Remove a CTE remote system from the local device.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/cte_remote_system/{cte_id}', args={}, response_type='none')


    # /cte_routes

    def getAllIfcRoutes(self):
        """ getAllIfcRoutes :
        Fetch a list containing the summaries for all IFC routes.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/cte_routes', response_type='json')

    def searchIfcRoutes(self, args):
        """ searchIfcRoutes :
        Search a specific IFC route by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/cte_routes/search', args=args, response_type='json')

    def getIfcRoute(self, ifc_route_id):
        """ getIfcRoute :
        Fetch the properties of an IFC route.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/cte_routes/{ifc_route_id}', response_type='json')


    # /cte_stats

    def getCteStats(self, args):
        """ getCteStats:
        Retrieves a stats snapshot. The snapshot may be customized to include stats
        only for a specific set of NTO objects: ports, port groups, filters. By
        default all the stats are included in a snapshot, but if the user desires
        only a set of specific stats then the snapshot can be tweaked to include
        only these stats.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        >>> nto.getCteStats({'stat_name': ['tp_current_tx_rate_bits'], 'port': ['P1-02'], 'remote_system': {'address': '127.0.0.11', 'port': 9011}})
	{'stats_snapshot': [{'default_name': 'P1-02', 'id': '108', 'reset_by': 'admin', 'reset_time': 1679426489803, 'stats_time': 1679426644483, 'tp_current_tx_rate_bits': 1284805946, 'type': 'Port'}]}

        """
        return self._sendRequest(http_method='POST', url='/cte_stats', args=args, response_type='json')

    def resetCteDropsStats(self, args):
        """ resetCteDropsStats :
        Reset the overflow drop counts for a set of specific tool ports and/or
        output port groups.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        >>> nto.resetCteDropsStats({"cte_port":['e34a65e4-d78b-451d-8388-43cf6a0dceaf']})
	    b'{}'
        """
        return self._sendRequest(http_method='POST', url='/cte_stats/reset_drops', args=args, response_type='none')

    def resetCteStats(self, args):
        """ resetCteStats:
        Reset the stats for a set of specific ports, port groups, and/or filters.
        Platforms:
            7300/7303, TradeVision, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 40, Vision
            Edge 50, Vision One, Vision X

        Example:
        >>> nto.resetCteStats({"cte_port":['e34a65e4-d78b-451d-8388-43cf6a0dceaf']})
        b'{}'
        """
        return self._sendRequest(http_method='POST', url='/cte_stats/reset_stats', args=args, response_type='none')


    # /custom_icons

    def getAllIcons(self):
        """ getAllIcons :
        Fetch a list containing summaries for all custom icons in the system.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getAllIcons()
        [{u'id': 71, u'name': u'JuniperLogoLarge'}, {u'id': 70, u'name': u'Tektronix'}, {u'id': 69, u'name': u'JDSU'}, {u'id': 68, u'name': u'Cisco'}, {u'id': 75, u'name': u'A Big Bomb!'}]
        """
        return self._sendRequest(http_method='GET', url='/custom_icons', response_type='json')

    def createIcon(self, args):
        """ createIcon :
        Create a new custom icon.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.createIcon({'description': 'A bomb!', 'file_name': '/Users/fmota/Desktop/bomb.jpeg', 'name' : 'Bomb'})
        {u'id': u'75'}
        """

        multipart_form_data = {}

        if 'description' in args:
            multipart_form_data['description'] = (None, args['description'])

        if 'name' in args:
            multipart_form_data['name'] = (None, args['name'])

        if 'file_name' in args:
            multipart_form_data['file'] = (args['file_name'], open(args['file_name'], 'rb'))

        return self._sendRequest(http_method='POST', url='/custom_icons', args=None, file_info=multipart_form_data, response_type='json')

    def searchIcons(self, args):
        """ searchIcons :
        Search for a specific custom icon in the system by certain properties.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.searchIcon({'name' : 'A Big Bomb!'})
        [{u'id': 75, u'name': u'A Big Bomb!'}]
        """
        return self._sendRequest(http_method='POST', url='/custom_icons/search', args=args, response_type='json')

    def getIcon(self, icon_id):
        """ getIcon :
        Fetch the properties of a custom icon which is specified by its custom_icon_id_or_name.
        Example:
        >>> nto.getIcon('75')
        {u'description': u'A bomb!', u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1440623340772}, u'name': u'A Big Bomb!', u'mod_count': 2, u'id': 75, u'history': [{u'type': u'MODIFY', u'time': 1440623518301, u'caused_by': u'admin', u'details': None, u'props': [u'NAME']}]}
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url=f'/custom_icons/{icon_id}', response_type='json')

    def modifyIcon(self, icon_id, args):
        """ modifyIcon :
        Update properties of a custom icon.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.modifyIcon('75', {'name' : 'A Big Bomb!'})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/custom_icons/{icon_id}', args=args, response_type='none')

    def deleteIcon(self, icon_id):
        """ deleteIcon :
        Remove a custom icon from the system.
        The custom icon is specified by a custom_icon_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>>.deleteIcon('75')
        ''
        """
        return self._sendRequest(http_method='DELETE', url=f'/custom_icons/{icon_id}', args=None, response_type='none')


    # /filter_template_collections

    def getAllFilterTemplateCollections(self):
        """ getAllFilterTemplateCollections :
        Fetch a list containing summaries for all the filter template collections in the system.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.getAllFilterTemplateCollections()
        [{u'id': 467, u'name': u'NET_TROUBLESHOOTING'}, {u'id': 57, u'name': u'Public'}]
        """
        return self._sendRequest(http_method='GET', url='/filter_template_collections', response_type='json')

    def createFilterTemplateCollection(self, args):
        """ createFilterTemplateCollection :
        Create a new filter template collection.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.createFilterTemplateCollection({'description': 'My filter collection', 'name': 'Private Filter Collection'})
        {u'id': u'50'}
        """
        return self._sendRequest(http_method='POST', url='/filter_template_collections', args=args, response_type='json')

    def getFilterTemplateCollectionsDetails(self, ids=None):
        """ getFilterTemplateCollectionsDetails :
        Fetch detailed properties for all or selected filter template collections.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(
            http_method='POST',
            url='/filter_template_collections/detail',
            args=None,
            params=self._buildIdsParams(ids),
            response_type='json'
        )

    def searchFilterTemplateCollections(self, args):
        """ searchFilterTemplateCollections :
        Search for a specific filter template collection in the system by certain properties.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.searchFilterTemplateCollections({'name': 'Private Filter Collection'})
        [{u'id': 50, u'name': u'Private Filter Collection'}]
        """
        return self._sendRequest(http_method='POST', url='/filter_template_collections/search', args=args, response_type='json')

    def getFilterTemplateCollection(self, filter_template_collection_id):
        """ getFilterTemplateCollection :
        Fetch the properties of a filter template collection object which is specified by its
        filter_template_collection_id_or_name.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.getFilterTemplateCollection('467')
        {u'description': None, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1429303086082}, u'name': u'NET_TROUBLESHOOTING', u'mod_count': 2, u'id': 467, u'history': []}
        """
        return self._sendRequest(http_method='GET', url=f'/filter_template_collections/{filter_template_collection_id}', response_type='json')

    def modifyFilterTemplateCollection(self, filter_template_collection_id, args):
        """ modifyFilterTemplateCollection :
        Update properties of a filter template collection.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.modifyFilterTemplateCollection('50', {'description': 'My private filter collection'})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/filter_template_collections/{filter_template_collection_id}', args=args, response_type='none')

    def deleteFilterTemplateCollection(self, filter_template_collection_id):
        """ deleteFilterTemplate :
        Remove a filter template collection from the system. The filter is specified by a
        filter_template_collection_id_or_name.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.deleteFilterTemplateCollection('50')
        ''
        """
        return self._sendRequest(
            http_method='DELETE',
            url=f'/filter_template_collections/{filter_template_collection_id}',
            args=None,
            response_type='none'
        )


    # /filter_templates

    def getAllFilterTemplates(self):
        """ getAllFilterTemplates :
        Fetch a list containing summaries for all the filter templates in the system.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.getAllFilterTemplates()
        [{u'id': 468, u'name': u'Too Much Overhead'}, {u'id': 469, u'name': u'Syn Attack'}, {u'id': 470, u'name': u'ARP Storm'}, {u'id': 51, u'name': u'VLAN Gold'}]
        """
        return self._sendRequest(http_method='GET', url='/filter_templates', response_type='json')

    def createFilterTemplate(self, args):
        """ createFilterTemplate :
        Create a new filter template.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.createFilterTemplate({'collection': 'Public', 'name': 'Virtual Traffic', 'criteria': {'vlan': {'vlan_id': '100'}, 'logical_operation': 'AND'}})
        {u'id': u'52'}
        """
        return self._sendRequest(http_method='POST', url='/filter_templates', args=args, response_type='json')

    def getFilterTemplatesDetails(self, ids=None):
        """ getFilterTemplatesDetails :
        Fetch detailed properties for all or selected filter templates.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/filter_templates/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchFilterTemplates(self, args):
        """ searchFilterTemplates :
        Search for a specific filter template in the system by certain properties.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.searchFilterTemplates({'collection': 'Public'})
        [{u'id': 51, u'name': u'VLAN Gold'}, {u'id': 52, u'name': u'Virtual Traffic'}]
        """
        return self._sendRequest(http_method='POST', url='/filter_templates/search', args=args, response_type='json')

    def getFilterTemplate(self, filter_template_id):
        """ getFilterTemplate :
        Fetch the properties of a filter templates object which is specified by its filter_template_id.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.getFilterTemplate('468')
        {u'description': u'Use for base line tools.  Checks ICMP and SNMP traffic.', u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1429303123112}, u'collection': u'NET_TROUBLESHOOTING', u'name': u'Too Much Overhead', u'mod_count': 5, u'criteria': {u'logical_operation': u'AND', u'ip_protocol': {u'value': u'1'}, u'layer4_src_or_dst_port': {u'port': u'161-162'}}, u'id': 468, u'history': []}
        """
        return self._sendRequest(http_method='GET', url=f'/filter_templates/{filter_template_id}', response_type='json')

    def modifyFilterTemplate(self, filter_template_id, args):
        """ modifyFilterTemplate :
        Update properties of a filter template.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.modifyFilterTemplate('52', {'criteria': {'vlan': {'vlan_id': '200'}, 'logical_operation': 'AND'}})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/filter_templates/{filter_template_id}', args=args, response_type='none')

    def deleteFilterTemplate(self, filter_template_id):
        """ deleteFilterTemplate :
        Remove a filter template from the system. The filter template is specified by a filter_template_id.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.deleteFilterTemplate('52')
        ''
        """
        return self._sendRequest(http_method='DELETE', url=f'/filter_templates/{filter_template_id}', args=None, response_type='none')


    # /filters

    def getAllFilters(self):
        """ getAllFilters :
        Fetch a list containing summaries for all the filters in the system.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getAllFilters()
        [{u'id': 460, u'name': u'TCP, UDP, HTTP'}, {u'id': 461, u'name': u'Voice VLANs'}, {u'id': 462, u'name': u'ARP Storm'}, {u'id': 463, u'name': u'Syn Attack'}, {u'id': 464, u'name': u'DENY HTTPS'}, {u'id': 465, u'name': u'Too Much Overhead'}, {u'id': 466, u'name': u'F4'}]
        """
        return self._sendRequest(http_method='GET', url='/filters', response_type='json')

    def createFilter(self, args, allowTemporaryDataLoss=False):
        """ createFilter :
        Create a new filter.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.createFilter({'source_port_list': ['218', '220'], 'dest_port_list': ['219'], 'mode': 'PASS_ALL'})
        {u'id': u'466'}
        """
        return self._sendRequest(http_method='POST', url='/filters', args=args, params={'allowTemporaryDataLoss': allowTemporaryDataLoss}, response_type='json')

    def getFiltersDetails(self, ids=None):
        """ getFiltersDetails :
        Fetch detailed properties for all or selected filters.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/filters/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchFilters(self, args):
        """ searchFilters :
        Search for a specific port group in the system by certain properties.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.searchFilters({'mode' : 'PASS_BY_CRITERIA'})
        [{u'id': 463, u'name': u'Syn Attack'}, {u'id': 465, u'name': u'Too Much Overhead'}, {u'id': 466, u'name': u'F8'}, {u'id': 55, u'name': u'F4'}, {u'id': 460, u'name': u'TCP, UDP, HTTP'}, {u'id': 462, u'name': u'ARP Storm'}, {u'id': 461, u'name': u'Voice VLANs'}]
        """
        return self._sendRequest(http_method='POST', url='/filters/search', args=args, response_type='json')

    def getFilterWritableProperties(self):
        """ getFilterWritableProperties :
        List writable property names for filters.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/filters/writable_props', args=None, response_type='json')

    def partiallyDeleteFilter(self, filter_id, args):
        """ partiallyDeleteFilter :
        Partially delete a filter from the system.
        Platforms:
            GSC 7400, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> gsc.partiallyDeleteFilter('F1', {'gsc_session_filter_settings': {'imsi_list': ['************9**']}})
        ''
        OR
        >>> gsc.partiallyDeleteFilter('F1', {'file_name': '/Users/fedemota/Desktop/IMSI-List.csv'})
        ''
        """
        if 'gsc_session_filter_settings' in args:
            args['gsc_session_filter_settings']['imsi_list'] = list(set(args['gsc_session_filter_settings']['imsi_list']))
            return self._sendRequest(http_method='DELETE', url=f'/filters/{filter_id}', args=args, response_type='none')
        else:
            file_name = args['file_name']
            f = {'file': (file_name, open(file_name ,'rb'), 'application/octet-stream')}
            return self._sendRequest(http_method='POST', url=f'/filters/{filter_id}', args=args, file_info=f, response_type='json')

    def partiallyModifyFilter(self, filter_id, args):
        """ partiallyModifyFilter :
        Partially update properties of a filter.
        Platforms:
            GSC 7400, 7300/7303, Vision 400, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge
            400P, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516, Vision Edge OS
            5812, Vision Edge OS 7712, Vision One, Vision X

        Example:
        >>> gsc.partiallyModifyFilter('F1', {'gsc_session_filter_settings': {'imsi_list': ['************9**']}})
        ''
        OR
        >>> gsc.partiallyModifyFilter('F1', {'file_name': '/Users/fedemota/Desktop/IMSI-List.csv'})
        ''
        """
        if 'gsc_session_filter_settings' in args:
            args['gsc_session_filter_settings']['imsi_list'] = list(set(args['gsc_session_filter_settings']['imsi_list']))
            return self._sendRequest(http_method='PATCH', url=f'/filters/{filter_id}', args=args, response_type='none')
        else:
            file_name = args['file_name']
            f = {'file': (file_name, open(file_name ,'rb'), 'application/octet-stream')}
            return self._sendRequest(http_method='POST', url=f'/filters/{filter_id}', args=args, file_info=f, response_type='json')

    def modifyFilter(self, filter_id, args, allowTemporaryDataLoss=False):
        """ modifyFilter :
        Update properties of a filter.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.modifyFilter('F4', {'mode' : 'PASS_BY_CRITERIA', 'criteria' : {'logical_operation': 'AND', 'ipv4_session_flow': {'session_sets': [{'a_sessions': ['10.0.0.0/24:1', '12.0.0.0/24:1'], 'b_sessions': ['14.0.0.0/24:1', '16.0.0.0/24:1']}], 'flow_type': 'UNI'}}})
        ''
        """
        return self._sendRequest(
            http_method='PUT',
            url=f'/filters/{filter_id}',
            args=args,
            params={'allowTemporaryDataLoss': allowTemporaryDataLoss},
            response_type='none'
        )

    def deleteFilter(self, filter_id, allowTemporaryDataLoss=False):
        """ deleteFilter :
        Remove a filter from the system. The filter is specified by a filter_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.deleteFilter('F4')
        """
        return self._sendRequest(
            http_method='DELETE',
            url=f'/filters/{filter_id}',
            args=None,
            params={'allowTemporaryDataLoss': allowTemporaryDataLoss},
            response_type='none'
        )

    def applyTemplateToFilter(self, filter_id, args):
        """ applyTemplateToFilter :
        Apply an object template to a filter.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/filters/{filter_id}/apply_template', args=args, response_type='none')

    def createTemplateFromFilter(self, filter_id, args):
        """ createTemplateFromFilter :
        Create an object template from a filter.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/filters/{filter_id}/create_template', args=args, response_type='json')

    def getImsiCsvFile(self, filter_id, args):
        """ getImsiCsvFile :
        All IMSIs configured for the filter object is returned in a CSV file.
        The file is returned as an application/octet-stream.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.getImsiCsvFile('F1', {'file_name': '/Users/fedemota/Desktop/IMSI-List1.csv'})
        """
        file_name = ''
        if 'file_name' in args:
            file_name = args['file_name']

        file = self._sendRequest(http_method='GET', url=f'/filters/{filter_id}/get_imsi_csv_file', args=args, response_type='bytes')
        f = open(file_name, 'w')
        f.write(file)
        f.close()

    def getFilter(self, filter, properties=None):
        """ getFilter :
        Fetch the properties of a filter object which is specified by its filter_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getFilter('461')
        {u'dynamic_filter_type': u'TWO_STAGE', u'connect_in_access_settings': {u'policy': u'INHERITED'}, u'dest_port_list': [], u'match_count_unit': u'PACKETS', u'description': None, u'resource_access_settings': {u'policy': u'INHERITED'}, u'created': None, u'modify_access_settings': {u'policy': u'INHERITED'}, u'default_name': u'F3', u'dest_port_group_list': [], u'name': u'Voice VLANs', u'mod_count': 6, u'snmp_tag': None, u'mode': u'PASS_BY_CRITERIA', u'criteria': {u'vlan': {u'priority': None, u'vlan_id': u'1000'}, u'logical_operation': u'AND'}, u'keywords': [], u'source_port_group_list': [], u'source_port_list': [410, 428], u'connect_out_access_settings': {u'policy': u'INHERITED'}, u'id': 461, u'history': [{u'type': u'MODIFY', u'time': 1442251734144, u'caused_by': u'internal', u'details': None, u'props': [u'SOURCE_PORT_LIST', u'DEST_PORT_LIST']}]}
        """
        params = None
        if properties:
            params = {'properties': ''.join(properties.split())}

        return self._sendRequest(http_method='GET', url=f'/filters/{filter}', params=params, response_type='json')

    def getFilterProperties(self, filter, properties):
        """ getFilterProperties :
        Fetch a list of properties of a filter object which is specified by its
        filter_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getFilterProperties('F1', 'mode,name')
        {u'mode': u'PASS_ALL', u'name': u'L2-Resoure-Akamai'}
        """
        return self.getFilter(filter, properties)

    def getFilterProperty(self, filter, property):
        """ getFilterProperty :
        Fetch a property of a filter object which is specified by its
        filter_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getFilterProperty('F1', 'keywords')
        [u'TIME']
        """
        return self.getFilter(filter, property)[property]


    # /flowstack_resources

    def getAllFlowStackResources(self):
        """ getAllFlowStackResources :
        Fetch a list containing the summaries for all the FlowStack resources in the system.
        Platforms:
            Vision 400, Vision 400XT, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='GET', url='/flowstack_resources', response_type='json')

    def getFlowStackResourcesDetails(self, ids=None):
        """ getFlowStackResourcesDetails :
        Fetch detailed properties for all or selected FlowStack resources.
        Platforms:
            Vision 400, Vision 400XT, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/flowstack_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchFlowStacks(self, args):
        """ searchFlowStacks :
        Search for a specific FlowStack resource in the system by certain properties.
        Platforms:
            Vision 400, Vision 400XT, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/flowstack_resources/search', args=args, response_type='json')

    def modifyFlowStack(self, flowstack_id, args):
        """ modifyFlowStack :
        Update the properties of an existing FlowStack resource.
        Platforms:
            Vision 400, Vision 400XT, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/flowstack_resources/{flowstack_id}', args=args, response_type='none')

    def disableFlowStack(self, flowstack_id, args):
        """ disableFlowStack :
        Disables a FlowStack resource by disconnecting the attached port, port group or filter.
        Platforms:
            Vision 400, Vision 400XT, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/flowstack_resources/{flowstack_id}/disable', args=args, response_type='none')

    def enableFlowStack(self, flowstack_id, args):
        """ enableFlowStack :
        Enables a FlowStack resource by attaching a port, port group or filter to it.
        Platforms:
            Vision 400, Vision 400XT, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/flowstack_resources/{flowstack_id}/enable', args=args, response_type='none')

    def getFlowStackBandwidthDetails(self, flowstack_id):
        """ getFlowStackBandwidthDetails :
        Gets the bandwidth details for the FlowStack resource.
        Platforms:
            Vision 400, Vision 400XT, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/flowstack_resources/{flowstack_id}/get_bandwidth_details', args=None, response_type='json')

    def getFlowStackResource(self, flowstack, properties=None):
        """ getFlowStackResource :
        Fetch the properties of a FlowStack resource object.
        Platforms:
            Vision 400, Vision 400XT, Vision X, Vision X 400G

        Example:
        """
        params = None
        if properties:
            params = {'properties': ''.join(properties.split())}

        return self._sendRequest(http_method='GET', url=f'/flowstack_resources/{flowstack}', params=params, response_type='json')


    # /groups

    def getAllGroups(self):
        """ getAllGroups :
        Fetch a list containing the summaries for all the user groups in the system.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getAllGroups()
        [{u'id': 369, u'name': u'Security Mgmt'}, {u'id': 367, u'name': u'Network Mgmt'}, {u'id': 368, u'name': u'Security Engineering'}, {u'id': 365, u'name': u'group2'}, {u'id': 366, u'name': u'Network Operations'}, {u'id': 364, u'name': u'group1'}]
        """
        return self._sendRequest(http_method='GET', url='/groups', response_type='json')

    def createGroup(self, args):
        """ createGroup :
        Create a new user group.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.createGroup({'name' : 'Automation', 'members': ['bbrother', 'jfixit']})
        {u'id': u'477'}
        """
        return self._sendRequest(http_method='POST', url='/groups', args=args, response_type='json')

    def getGroupsDetails(self, ids=None):
        """ getGroupsDetails :
        Fetch detailed properties for all or selected groups.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/groups/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchGroups(self, args):
        """ searchGroups :
        Search for a specific user group in the system by certain properties.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.searchGroups({'members': ['netopsguy']})
        [{u'id': 367, u'name': u'Network Mgmt'}]
        """
        return self._sendRequest(http_method='POST', url='/groups/search', args=args, response_type='json')

    def getGroup(self, group):
        """ getGroup :
        Fetch the properties of an user group object which is specified by its
        group_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getGroup('369')
        {u'owners': [], u'auto_created': False, u'description': None, u'name': u'Security Mgmt', u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1256831414761}, u'accessible_ports': [], u'mod_count': 2, u'members': [u'bbrother', u'securityguy'], u'accessible_filters': [], u'id': 369, u'history': [{u'type': u'MODIFY', u'time': 1316645263611, u'caused_by': u'internal', u'details': None, u'props': [u'ACCESSIBLE_PORTS']}]}
        """
        return self._sendRequest(http_method='GET', url=f'/groups/{group}', response_type='json')

    def modifyGroup(self, group_id, args):
        """ modifyGroup :
        Update the properties of an existing user group.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.modifyGroup('Automation', {'members': ['jfixit']})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/groups/{group_id}', args=args, response_type='none')

    def deleteGroup(self, group_id):
        """ deleteGroup :
        Remove a user from the system. The user is specified by a group_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.deleteGroup('477')
        ''
        """
        return self._sendRequest(http_method='DELETE', url=f'/groups/{group_id}', args=None, response_type='none')


    # /gsc-filters-config

    def getGscFilterConfig(self, filter_name):
        """ getGscFilterConfig :
        Find GSC filter configuration by GSC filter default name.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.getGscFilterConfig('GSC1')
        {'filterDefaultName': 'GSC1', 'imsiLists': [], 'filterRuleList': [{'imsiConfig': {'useFilterImsiLists': False, 'wildcardValues': ['2222**********'], 'not': False}, 'ratConfig': {'values': []}, 'qciConfig': {'values': []}, 'uliConfig': {'values': []}, 'apnConfig': {'values': [], 'not': False}}]}
        """
        return self._sendRequest(http_method='GET', url=f'/gsc-filters-config/{filter_name}', response_type='json')

    def modifyGscFilterConfig(self, filter_name, args):
        """ modifyGscFilterConfig :
        Applies the GSC filter configuration to the GSC Filter referenced by the given ID.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.modifyGscFilterConfig('GSC1', {'imsiLists': [], 'filterRuleList': [{'imsiConfig': {'useFilterImsiLists': False, 'wildcardValues': ['2222**********'], 'not': False}, 'ratConfig': {'values': ["UTRAN"]}, 'qciConfig': {'values': []}, 'uliConfig': {'values': []}, 'apnConfig': {'values': [], 'not': False}}]})
        b''
        """
        return self._sendRequest(http_method='PUT', url=f'/gsc-filters-config/{filter_name}', args=args, response_type='none')


    # /gsc-imsi-lists

    def getAllGscImsiLists(self):
        """ getAllGscImsiLists :
        Return a summary of the current IMSI lists.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.getAllGscImsiLists()
        [{'id': 'f6aa896d-1c2e-43c8-b223-448396c2c398', 'name': 'Gold', 'size': 1, 'usedByFilters': []}]
        """
        return self._sendRequest(http_method='GET', url='/gsc-imsi-lists', response_type='json')

    def createGscImsiList(self):
        """ createGscImsiList :
        Create a new empty IMSI list with a default name.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.createGscImsiList()
        {'id': '5e399236-d589-4c90-afd2-d537e74ac1d3', 'name': 'IMSI list 2021-06-28 13-41-00', 'size': 0, 'usedByFilters': []}
        """
        return self._sendRequest(http_method='POST', url='/gsc-imsi-lists', response_type='json')

    def getGscImsiList(self, imsi_list_id, start_index=1, wildcard_pattern=None):
        """ getGscFilter :
        Get a subset of values inside an IMSI list.
        Returns a maximum of 1000 values based on the given filter options
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.getGscImsiList('f6aa896d-1c2e-43c8-b223-448396c2c398', 2, "*555")
        [{'index': 2, 'value': '111222333444555'}]
        """
        params = {}
        if start_index:
            params['startIndex'] = start_index
        if wildcard_pattern:
            params['wildcardPattern'] = wildcard_pattern

        return self._sendRequest(http_method='GET', url=f'/gsc-imsi-lists/{imsi_list_id}', params=params, response_type='json')

    def importGscImsiList(self, imsi_list_id, file_name, upload_type='overwrite'):
        """ importGscImsiList :
        Append or overwrite an IMSI list with values from the given file.
        File needs to be in text format, with one value per line.

        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.importGscImsiList('f6aa896d-1c2e-43c8-b223-448396c2c398', 'imsis.txt')
        b'{\r\n  "success" : true,\r\n  "error" : ""\r\n}'
        """

        with open(file_name, 'rb') as file_handle:
            f = {'file': (file_name, file_handle, 'application/octet-stream')}
            return self._sendRequest(
                http_method='POST',
                url=f'/gsc-imsi-lists/{imsi_list_id}',
                args={},
                params={'uploadType': upload_type},
                file_info=f,
                response_type='json'
            )

    def modifyGscImsiList(self, imsi_list_id, args):
        """ modifyGscImsiList :
        Updates parameters for the given IMSI list id.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.modifyGscImsiList('f6aa896d-1c2e-43c8-b223-448396c2c398', {'name': 'Silver'})
        b''
        """
        return self._sendRequest(http_method='PUT', url=f'/gsc-imsi-lists/{imsi_list_id}', args=args, response_type='bytes')

    def deleteGscImsiList(self, imsi_list_id):
        """ deleteGscImsiList :
        Delete the list corresponding to the given IMSI list id.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.deleteGscImsiList('288816cf-6e9f-47e8-9265-b4b17c4cfef7')
        b''
        """
        return self._sendRequest(http_method='DELETE', url=f'/gsc-imsi-lists/{imsi_list_id}', args=None, response_type='bytes')

    def cloneGscImsiList(self, imsi_list_id):
        """ cloneGscImsiList :
        Create a new IMSI list with same values as the original imsi list.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.cloneGscImsiList('f6aa896d-1c2e-43c8-b223-448396c2c398')
        {'id': '288816cf-6e9f-47e8-9265-b4b17c4cfef7', 'name': 'IMSI list 2021-06-28 15-04-19', 'size': 5, 'usedByFilters': []}
        """
        return self._sendRequest(http_method='POST', url=f'/gsc-imsi-lists/{imsi_list_id}/clone', response_type='json')

    def exportGscImsiList(self, imsi_list_id, file_name):
        """ exportGscImsiList :
        Download a text file with all the IMSI list values, one value per line.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.exportGscImsiList('f6aa896d-1c2e-43c8-b223-448396c2c398', 'test.txt')
        """

        file = self._sendRequest(http_method='POST', url=f'/gsc-imsi-lists/{imsi_list_id}/file', args={}, response_type='bytes')
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def deleteGscImsiListValues(self, imsi_list_id, args):
        """ deleteGscImsiListValues :
        Delete a set of IMSI values at the specified indices.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.deleteGscImsiListValues('f6aa896d-1c2e-43c8-b223-448396c2c398', [1])
        b''
        """
        return self._sendRequest(http_method='DELETE', url=f'/gsc-imsi-lists/{imsi_list_id}/subset', args=args, response_type='bytes')

    def addGscImsiListValues(self, imsi_list_id, args, imsi_list_index=0):
        """ addGscImsiListValues :
        Insert a set of IMSI values at the specified index.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        >>> nto.addGscImsiListValues('f6aa896d-1c2e-43c8-b223-448396c2c398', ['777777777777777', '999999999999999'])
        b''
        """
        return self._sendRequest(
            http_method='POST',
            url=f'/gsc-imsi-lists/{imsi_list_id}/subset/{imsi_list_index}',
            args=args,
            response_type='bytes'
        )


    # /gsc_afm_resources

    def getAllGscResources(self):
        """ getAllGscResources :
        Fetch a list containing the summaries for all the GSC-FD resources in the system.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/gsc_afm_resources', response_type='json')

    def clearGscFragmentationAlarm(self):
        """ clearGscFragmentationAlarm :
        Clear the GSC fragmentation alarm.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        """
        return self._sendRequest(http_method='POST', url='/gsc_afm_resources/clear_gsc_fragmentation_alarm', args={}, response_type='json')

    def clearMobileStackNetserviceAutoRecoveryAlarm(self):
        """ clearMobileStackNetserviceAutoRecoveryAlarm :
        Clear the MobileStack Netservice Auto Recovery alarm.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(
            http_method='POST',
            url='/gsc_afm_resources/clear_mobilestack_netservice_auto_recovery_alarm',
            args={},
            response_type='json'
        )

    def getGscResourcesDetails(self, ids=None):
        """ getGscResourcesDetails :
        Fetch detailed properties for all or selected GSC resources.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        """
        return self._sendRequest(http_method='POST', url='/gsc_afm_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def resetGscFragmentationEngine(self):
        """ resetGscFragmentationEngine :
        Reset the GSC fragmentation engine.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        """
        return self._sendRequest(http_method='POST', url='/gsc_afm_resources/reset_gsc_fragmentation_engine', args={}, response_type='json')

    def searchGscResources(self, args):
        """ searchGscResources :
        Search for a specific GSC resource in the system by certain properties.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/gsc_afm_resources/search', args=args, response_type='json')

    def getGscResource(self, gsc_resource_id, properties=None):
        """ getGscResource :
        Fetch the properties of an GSC-FD resource object.
        To request only select properties (partial response), append to the URL the query
        parameter '?properties=value', where value is comma-separated list to select
        multiple fields for example: /resource_type/{object-id}?properties=description,name.
        Query Parameter is optional.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/gsc_afm_resources/{gsc_resource_id}', params=params, response_type='json')

    def modifyGscResource(self, gsc_resource_id, args):
        """ modifyGscResource :
        Update the properties of an existing GSC resource.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/gsc_afm_resources/{gsc_resource_id}', args=args, response_type='none')

    def disableGscResource(self, gsc_resource_id, args):
        """ disableGscResource :
        Disables an AFM resource by disconnecting the attached port, port group or filter.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/gsc_afm_resources/{gsc_resource_id}/disable', args=args, response_type='none')

    def enableGscResource(self, gsc_resource_id, args):
        """ enableGscResource :
        Enables an AFM resource by attaching a port, port group or filter to it.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/gsc_afm_resources/{gsc_resource_id}/enable', args=args, response_type='none')

    def getGscResourceBandwidth(self, gsc_resource_id):
        """ getGscResourceBandwidth :
        Gets the bandwidth details for the GSC AFM resource.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/gsc_afm_resources/{gsc_resource_id}/get_bandwidth_details', response_type='json')


    # /gsc_cpp_resources

    def getAllGscCppResources(self):
        """ getAllGscCppResources :
        Fetch a list containing the summaries for all the GSC CPP resources in the system.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/gsc_cpp_resources', response_type='json')

    def getGscCppResourcesDetails(self, ids=None):
        """ getGscCppResourcesDetails :
        Fetch detailed properties for all or selected GSC CPP resources.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        """
        return self._sendRequest(http_method='POST', url='/gsc_cpp_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchGscCppResources(self, args):
        """ searchGscCppResources :
        Search for a specific ATIP resource in the system by certain properties.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/gsc_cpp_resources/search', args=args, response_type='json')

    def modifyGscCppResource(self, resource_id, args):
        """ modifyGscFilter :
        Update the properties of an existing ATIP resource.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/gsc_cpp_resources/{resource_id}', args=args, response_type='none')

    def getGscCppResource(self, resource, properties=None):
        """ getGscCppResource :
        Fetch the properties of an ATIP resource.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        params = None
        if properties:
            params = {'properties': ''.join(properties.split())}

        return self._sendRequest(http_method='GET', url=f'/gsc_cpp_resources/{resource}', params=params, response_type='json')

    def getGscCppResourceProperties(self, filter, properties):
        """ getGscCppResourceProperties :
        Fetch a list of properties of a GSC CPP resource object which is specified by its resource_id_or_name.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self.getGscCppResource(filter, properties)

    def getGscCppResourceProperty(self, resource, property):
        """ getGscCppResourceProperty :
        Fetch a property of a GSC CPP resource object which is specified by its resource_id_or_name.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        """
        return self.getGscCppResource(resource, property)[property]


    # /gsc_filters

    def getAllGscFilters(self):
        """ getAllGscFilters :
        Fetch a list containing the summaries for all the filters in the system.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        >>> nto.getAllGscFilters()
        [{'id': 77, 'name': 'GSC1'}, {'id': 78, 'name': 'GSC2'}]
        """
        return self._sendRequest(http_method='GET', url='/gsc_filters', response_type='json')

    def createGscFilter(self, args):
        """ createGscFilter :
        Create a new filter in the system.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        >>> nto.createGscFilter({'source_port_list': ['218', '220'], 'dest_port_list': ['219'], 'mode': 'PASS_ALL'})
        {u'id': u'466'}
        """
        return self._sendRequest(http_method='POST', url='/gsc_filters', args=args, response_type='json')

    def getGscFiltersDetails(self, ids=None):
        """ getGscFiltersDetails :
        Fetch detailed properties for all or selected GSC filters.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        """
        return self._sendRequest(http_method='POST', url='/gsc_filters/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchGscFilters(self, args):
        """ searchGscFilters :
        Search for a specific filter in the system by certain properties.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        >>> nto.searchFilters({'mode' : 'PASS_BY_CRITERIA'})
        [{u'id': 463, u'name': u'Syn Attack'}, {u'id': 465, u'name': u'Too Much Overhead'}, {u'id': 466, u'name': u'F8'}, {u'id': 55, u'name': u'F4'}, {u'id': 460, u'name': u'TCP, UDP, HTTP'}, {u'id': 462, u'name': u'ARP Storm'}, {u'id': 461, u'name': u'Voice VLANs'}]
        """
        return self._sendRequest(http_method='POST', url='/gsc_filters/search', args=args, response_type='json')

    def modifyGscFilter(self, filter_id, args):
        """ modifyGscFilter :
        Update the properties of an existing gsc filter.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        >>> nto.modifyFilter('F4', {'mode' : 'PASS_BY_CRITERIA', 'criteria' : {'logical_operation': 'AND', 'ipv4_session_flow': {'session_sets': [{'a_sessions': ['10.0.0.0/24:1', '12.0.0.0/24:1'], 'b_sessions': ['14.0.0.0/24:1', '16.0.0.0/24:1']}], 'flow_type': 'UNI'}}})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/gsc_filters/{filter_id}', args=args, response_type='none')

    def deleteGscFilter(self, filter_id):
        """ deleteGscFilter :
        Remove a filter from the system.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        >>> nto.deleteGscFilter('F4')
        ''
        """
        return self._sendRequest(http_method='DELETE', url=f'/gsc_filters/{filter_id}', args=None, response_type='none')

    def getGscFilter(self, filter, properties=None):
        """ getGscFilter :
        Fetch the properties of a filter object.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        >>> nto.getGscFilter('461')
        {u'dynamic_filter_type': u'TWO_STAGE', u'connect_in_access_settings': {u'policy': u'INHERITED'}, u'dest_port_list': [], u'match_count_unit': u'PACKETS', u'description': None, u'resource_access_settings': {u'policy': u'INHERITED'}, u'created': None, u'modify_access_settings': {u'policy': u'INHERITED'}, u'default_name': u'F3', u'dest_port_group_list': [], u'name': u'Voice VLANs', u'mod_count': 6, u'snmp_tag': None, u'mode': u'PASS_BY_CRITERIA', u'criteria': {u'vlan': {u'priority': None, u'vlan_id': u'1000'}, u'logical_operation': u'AND'}, u'keywords': [], u'source_port_group_list': [], u'source_port_list': [410, 428], u'connect_out_access_settings': {u'policy': u'INHERITED'}, u'id': 461, u'history': [{u'type': u'MODIFY', u'time': 1442251734144, u'caused_by': u'internal', u'details': None, u'props': [u'SOURCE_PORT_LIST', u'DEST_PORT_LIST']}]}
        """
        params = None
        if properties:
            params = {'properties': ''.join(properties.split())}

        return self._sendRequest(http_method='GET', url=f'/gsc_filters/{filter}', params=params, response_type='json')

    def getGscFilterProperties(self, filter, properties):
        """ getGscFilterProperties :
        Fetch a list of properties of a filter object which is specified by its filter_id_or_name.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        >>> nto.getFilterProperties('F1', 'mode,name')
        {u'mode': u'PASS_ALL', u'name': u'L2-Resoure-Akamai'}
        """
        return self.getGscFilter(filter, properties)

    def getGscFilterProperty(self, filter, property):
        """ getGscFilterProperty :
        Fetch a property of a filter object which is specified by its filter_id_or_name.
        Platforms:
            Vision 400, Vision 400XT, Vision X

        Example:
        >>> nto.getFilterProperty('F1', 'keywords')
        [u'TIME']
        """
        return self.getGscFilter(filter, property)[property]


    # /gtp_fd_afm_resources

    def getAllGtpFdResources(self):
        """ getAllGtpFdResources :
        Fetch a list containing the summaries for all the GTP-FD resources in the system.
        Platforms:
            Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/gtp_fd_afm_resources', response_type='json')

    def searchGtpFdResources(self, args):
        """ searchGtpFdResources :
        Search for a specific AFM resource in the system by certain properties.
        Platforms:
            Vision X

        Example:
        """
        return self._sendRequest(http_method='POST', url='/gtp_fd_afm_resources/search', args=args, response_type='json')

    def getGtpFdResource(self, gtp_fd_resource_id, properties=None):
        """ getGtpFdResource :
        Fetch the properties of an GTP-FD resource object.
        Platforms:
            Vision X

        Example:
        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/gtp_fd_afm_resources/{gtp_fd_resource_id}', params=params, response_type='json')

    def modifyGtpFdResource(self, gtp_fd_resource_id, args):
        """ modifyGtpFdResource :
        Update the properties of an existing AFM resource.
        Platforms:
            Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/gtp_fd_afm_resources/{gtp_fd_resource_id}', args=args, response_type='none')

    def disableGtpFdResource(self, gtp_fd_resource_id, args):
        """ disableGtpFdResource :
        Disables an AFM resource by disconnecting the attached port, port group or filter.
        Platforms:
            Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/gtp_fd_afm_resources/{gtp_fd_resource_id}/disable', args=args, response_type='none')

    def enableGtpFdResource(self, gtp_fd_resource_id, args):
        """ enableGtpFdResource :
        Enables an AFM resource by attaching a port, port group or filter to it.
        Platforms:
            Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/gtp_fd_afm_resources/{gtp_fd_resource_id}/enable', args=args, response_type='none')

    def getGtpFdResourceBandwidth(self, gtp_fd_resource_id):
        """ getGtpFdResourceBandwidth :
        Gets the bandwidth details for the Recirculated AFMresource.
        Platforms:
            Vision X

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/gtp_fd_afm_resources/{gtp_fd_resource_id}/get_bandwidth_details', response_type='json')


    # /heartbeats

    def getAllHeartbeats(self):
        """ getAllHeartbeats :
        Fetch a list containing the summaries for all the tool heartbeats in the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getAllHeartbeats()
        [{'id': 80, 'name': 'IXIA ThreatARMOR'}, {'id': 81, 'name': 'Cisco FirePOWER'}, {'id': 82, 'name': 'FireEye NX'}, {'id': 83, 'name': 'Imperva WAF'}, {'id': 84, 'name': 'Trend Micro'}]
        """
        return self._sendRequest(http_method='GET', url='/heartbeats', response_type='json')

    def createHeartbeat(self, args):
        """ createHeartbeat :
        Create a new tool heartbeat in the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.createHeartbeat({'name': 'Test'})
        {'default_name': 'HB7', 'id': 353, 'name': 'Test'}
        """
        return self._sendRequest(http_method='POST', url='/heartbeats', args=args, response_type='json')

    def getHeartbeatsDetails(self, ids=None):
        """ getHeartbeatsDetails :
        Fetch detailed properties for all or selected tool heartbeats.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/heartbeats/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchHeartbeats(self, args):
        """ searchHeartbeats :
        Search for a specific tool heartbeat in the system by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.searchHeartbeats({'name': 'Trend Micro'})
        [{'created': None, 'default_name': 'HB5', 'description': 'A read-only default heartbeat format appropriate for use with Trend Micro devices', 'destination_mac': {'mac_address': '00-1B-6E-01-4F-28'}, 'history': [], 'id': 84, 'interval': 1000, 'is_default': True, 'misc': {'access_map': {'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'ALLOW_ALL'}, 'affecting_ports': {}, 'affecting_resource': {}, 'current_value': 'All users.', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Allow All', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS']}, 'mod_count': 0, 'modify_access_settings': {'groups': [], 'policy': 'ALLOW_ALL'}, 'name': 'Trend Micro', 'payload': {'hex_value': '8B0000000000178C0000000000000000000000000005293D00D5A31081A6D0800000001900000010000E000F000000000000000000000020000E000F000000000000000000000030000E000F000000000000000000000001000E0010000000000000000000000002000E0010000000000000000000000003000E0010000000000000000000000004'}, 'retry_count': 3, 'source_mac': {'mac_address': '00-1B-6E-01-4F-27'}, 'timeout': 500, 'type': 'POSITIVE_HB', 'vlan_id': 4095, 'vlan_priority': 0}]
        """
        return self._sendRequest(http_method='POST', url='/heartbeats/search', args=args, response_type='json')

    def getHeartbeat(self, heartbeat_id):
        """ getHeartbeat :
        Fetch the properties of a tool heartbeat object.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getHeartbeat('IXIA ThreatARMOR')
        {'created': None, 'default_name': 'HB1', 'description': 'A read-only default heartbeat format appropriate for use with IXIA ThreatARMOR devices', 'destination_mac': {'mac_address': '00-1B-6E-01-4F-28'}, 'history': [], 'id': 80, 'interval': 1000, 'is_default': True, 'misc': {'access_map': {'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'ALLOW_ALL'}, 'affecting_ports': {}, 'affecting_resource': {}, 'current_value': 'All users.', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Allow All', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS']}, 'mod_count': 0, 'modify_access_settings': {'groups': [], 'policy': 'ALLOW_ALL'}, 'name': 'IXIA ThreatARMOR', 'payload': {'hex_value': '86DD60000000003C3B402001480000000000000000000000000120014800000000000000000000000002000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B'}, 'retry_count': 3, 'source_mac': {'mac_address': '00-1B-6E-01-4F-27'}, 'timeout': 500, 'type': 'POSITIVE_HB', 'vlan_id': 4095, 'vlan_priority': 0}
        """
        return self._sendRequest(http_method='GET', url=f'/heartbeats/{heartbeat_id}', response_type='json')

    def modifyHeartbeat(self, heartbeat_id, args):
        """ modifyHeartbeat:
        Update the properties of an existing tool heartbeat.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.modifyHeartbeat('HB6', {'vlan_id': 300})
        b''
        """
        return self._sendRequest(http_method='PUT', url=f'/heartbeats/{heartbeat_id}', args=args, response_type='none')

    def deleteHeartbeat(self, heartbeat_id):
        """ deleteHeartbeat :
        Remove an existing tool heartbeat from the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.deleteHeartbeat('HB7')
        b''
        """
        return self._sendRequest(http_method='DELETE', url=f'/heartbeats/{heartbeat_id}', args=None, response_type='none')


    # /inline_service_chains

    def getAllInlineServiceChains(self):
        """ getAllInlineServiceChains :
        Fetch a list containing the summaries for all the inline service chains in the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getAllInlineServiceChains()
        [{'id': 126, 'name': 'Secure SC Python'}]
        """
        return self._sendRequest(http_method='GET', url='/inline_service_chains', response_type='json')

    def createInlineServiceChain(self, args):
        """ createInlineServiceChain :
        Create a new inline service chain in the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.createInlineServiceChain({"bypass_connector_list": [120], "criteria": {"logical_operation": "AND", "vlan": [{"priority": None, "vlan_id": "100" }]}, "direction": "BIDI", "filter_mode": "PASS_BY_CRITERIA", "name": "Secure SC Python", "tool_resource_map": [{"tool_resource_failure_action": "FAIL_CLOSED", "tool_resource_id": 114}], "tool_sharing_enable": False, "vlan_translation_enabled": False})
        {'default_name': 'SC1', 'id': 121, 'name': 'Secure SC Python'}
        """
        return self._sendRequest(http_method='POST', url='/inline_service_chains', args=args, response_type='json')

    def searchInlineServiceChains(self, args):
        """ searchInlineServiceChains :
        Search for a specific inline service chain in the system by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.searchInlineServiceChains({"direction": "BIDI"})
        [{'bypass_connector_list': [120], 'connect_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'created': {'caused_by': 'admin', 'details': None, 'time': 1605732093043, 'type': 'CREATE'}, 'criteria': {'logical_operation': 'AND', 'vlan': [{'priority': None, 'vlan_id': '100'}]}, 'default_name': 'SC1', 'description': None, 'direction': 'BIDI', 'filter_list': [127, 128, 129, 130], 'filter_mode': 'PASS_BY_CRITERIA', 'history': [{'caused_by': 'admin', 'details': None, 'props': ['INLINE_TOOL_RESOURCE_MAP'], 'time': 1605732093110, 'type': 'MODIFY'}], 'id': 126, 'misc': {'access_map': {'CONNECT_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *BPP1: Inherited *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Connect Bypass Port Pairs', 'operation_phrase': 'connect bypass port pairs to', 'tooltip': 'Inherit from BPPs', 'user_names': '', 'users_statement': 'Anyone can perform'}, 'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *BPP1: Inherited *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from BPPs', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS', 'CONNECT_ACCESS_SETTINGS'], 'warning': None}, 'mod_count': 1, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'Secure SC Python', 'tool_resource_map': [{'tool_resource_failure_action': 'FAIL_CLOSED', 'tool_resource_id': '114'}], 'tool_sharing_enable': False, 'vlan_translation_enabled': False}]
        """
        return self._sendRequest(http_method='POST', url='/inline_service_chains/search', args=args, response_type='json')

    def getInlineServiceChain(self, inline_id):
        """ getInlineServiceChain :
        Fetch the properties of a inline service chain object.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getInlineServiceChain('126')
        {'bypass_connector_list': [120], 'connect_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'created': {'caused_by': 'admin', 'details': None, 'time': 1605732093043, 'type': 'CREATE'}, 'criteria': {'logical_operation': 'AND', 'vlan': [{'priority': None, 'vlan_id': '100'}]}, 'default_name': 'SC1', 'description': None, 'direction': 'BIDI', 'filter_list': [127, 128, 129, 130], 'filter_mode': 'PASS_BY_CRITERIA', 'history': [{'caused_by': 'admin', 'details': None, 'props': ['INLINE_TOOL_RESOURCE_MAP'], 'time': 1605732093110, 'type': 'MODIFY'}], 'id': 126, 'misc': {'access_map': {'CONNECT_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *BPP1: Inherited *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Connect Bypass Port Pairs', 'operation_phrase': 'connect bypass port pairs to', 'tooltip': 'Inherit from BPPs', 'user_names': '', 'users_statement': 'Anyone can perform'}, 'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'12': 'Allow All', '13': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *BPP1: Inherited *P10 (in BPP1), P11 (in BPP1): Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from BPPs', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS', 'CONNECT_ACCESS_SETTINGS'], 'warning': None}, 'mod_count': 1, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'Secure SC Python', 'tool_resource_map': [{'tool_resource_failure_action': 'FAIL_CLOSED', 'tool_resource_id': '114'}], 'tool_sharing_enable': False, 'vlan_translation_enabled': False}
        """
        return self._sendRequest(http_method='GET', url=f'/inline_service_chains/{inline_id}', response_type='json')

    def modifyInlineServiceChain(self, inline_id, args):
        """ modifyInlineServiceChain:
        Update the properties of an existing inline service chain.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.modifyInlineServiceChain('126', {"description": "Chain Descr"})
        b''
        """
        return self._sendRequest(http_method='PUT', url=f'/inline_service_chains/{inline_id}', args=args, response_type='none')

    def deleteInlineServiceChain(self, inline_id):
        """ deleteInlineServiceChain :
        Remove an existing inline service chain from the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.deleteInlineServiceChain('121')
        b''
        """
        return self._sendRequest(http_method='DELETE', url=f'/inline_service_chains/{inline_id}', args=None, response_type='none')

    def applyToolSharingMapInline(self, inline_id, args):
        """ applyToolSharingMapInline :
        Applies the tool sharing data received to all the BPPs associated with the
        service chain key received as argument.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/inline_service_chains/{inline_id}/applyToolSharingMap', args=args, response_type='none')

    def applyVlanTranslationMapInline(self, inline_id, args):
        """ applyVlanTranslationMapInline :
        Applies the vlan translation data received to all BPPs associated with the
        service chain key received as argument.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/inline_service_chains/{inline_id}/applyVlanTranslationMap', args=args, response_type='none')


    # /internal

    def getAllInternalFilters(self):
        """ getAllInternalFilters :
        Fetch summaries for all internal filters.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url='/internal/filters', response_type='json')

    def createInternalFilter(self, args, allowTemporaryDataLoss=False):
        """ createInternalFilter :
        Create an internal filter.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(
            http_method='POST',
            url='/internal/filters',
            args=args,
            params={'allowTemporaryDataLoss': allowTemporaryDataLoss},
            response_type='json'
        )

    def getInternalFiltersDetails(self, ids=None):
        """ getInternalFiltersDetails :
        Fetch detailed properties for all or selected internal filters.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/internal/filters/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchInternalFilters(self, args):
        """ searchInternalFilters :
        Search internal filters by supported properties.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/internal/filters/search', args=args, response_type='json')

    def getInternalFilter(self, internal_filter_id):
        """ getInternalFilter :
        Fetch the properties of an internal filter.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url=f'/internal/filters/{internal_filter_id}', response_type='json')

    def modifyInternalFilter(self, internal_filter_id, args, allowTemporaryDataLoss=False):
        """ modifyInternalFilter :
        Update an internal filter.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(
            http_method='PUT',
            url=f'/internal/filters/{internal_filter_id}',
            args=args,
            params={'allowTemporaryDataLoss': allowTemporaryDataLoss},
            response_type='none'
        )

    def deleteInternalFilter(self, internal_filter_id, allowTemporaryDataLoss=False):
        """ deleteInternalFilter :
        Delete an internal filter.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(
            http_method='DELETE',
            url=f'/internal/filters/{internal_filter_id}',
            args=None,
            params={'allowTemporaryDataLoss': allowTemporaryDataLoss},
            response_type='none'
        )

    def getAllInternalPortGroups(self):
        """ getAllInternalPortGroups :
        Fetch summaries for all internal port groups.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url='/internal/port_groups', response_type='json')

    def createInternalPortGroup(self, args):
        """ createInternalPortGroup :
        Create an internal port group.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/internal/port_groups', args=args, response_type='json')

    def getInternalPortGroupsDetails(self, ids=None):
        """ getInternalPortGroupsDetails :
        Fetch detailed properties for all or selected internal port groups.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/internal/port_groups/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchInternalPortGroups(self, args):
        """ searchInternalPortGroups :
        Search internal port groups by supported properties.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/internal/port_groups/search', args=args, response_type='json')

    def getInternalPortGroup(self, internal_port_group_id):
        """ getInternalPortGroup :
        Fetch the properties of an internal port group.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url=f'/internal/port_groups/{internal_port_group_id}', response_type='json')

    def modifyInternalPortGroup(self, internal_port_group_id, args):
        """ modifyInternalPortGroup :
        Update an internal port group.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/internal/port_groups/{internal_port_group_id}', args=args, response_type='none')

    def deleteInternalPortGroup(self, internal_port_group_id):
        """ deleteInternalPortGroup :
        Delete an internal port group.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='DELETE', url=f'/internal/port_groups/{internal_port_group_id}', args=None, response_type='none')

    def disableInternalPortGroup(self, internal_port_group_id):
        """ disableInternalPortGroup :
        Disable an internal port group.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/internal/port_groups/{internal_port_group_id}/disable', args=None, response_type='none')

    def enableInternalPortGroup(self, internal_port_group_id):
        """ enableInternalPortGroup :
        Enable an internal port group.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/internal/port_groups/{internal_port_group_id}/enable', args=None, response_type='none')

    def getAllInternalPorts(self):
        """ getAllInternalPorts :
        Fetch summaries for all internal ports.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url='/internal/ports', response_type='json')

    def createInternalPort(self, args):
        """ createInternalPort :
        Create an internal port.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/internal/ports', args=args, response_type='json')

    def getInternalPortsDetails(self, ids=None):
        """ getInternalPortsDetails :
        Fetch detailed properties for all or selected internal ports.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/internal/ports/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchInternalPorts(self, args):
        """ searchInternalPorts :
        Search internal ports by supported properties.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/internal/ports/search', args=args, response_type='json')

    def deleteInternalPort(self, internal_port_id):
        """ deleteInternalPort :
        Delete an internal port.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='DELETE', url=f'/internal/ports/{internal_port_id}', args=None, response_type='none')

    def clearInternalPort(self, internal_port_id):
        """ clearInternalPort :
        Reset an internal port to its default configuration.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/internal/ports/{internal_port_id}/clear', args=None, response_type='none')

    def deleteInternalPortPcapFiles(self, internal_port_id, args):
        """ deleteInternalPortPcapFiles :
        Delete one or more PCAP files from an internal port.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='DELETE', url=f'/internal/ports/{internal_port_id}/delete_pcap_files', args=args, response_type='json')

    def downloadInternalPortPcapFiles(self, internal_port_id, args):
        """ downloadInternalPortPcapFiles :
        Download one or more PCAP files from an internal port.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url=f'/internal/ports/{internal_port_id}/download_pcap_files', args=args, response_type='bytes')

    def getInternalPortPcapFileList(self, internal_port_id):
        """ getInternalPortPcapFileList :
        Get the list of PCAP files available for an internal port.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url=f'/internal/ports/{internal_port_id}/get_pcap_file_list', response_type='json')

    def startInternalPortCapture(self, internal_port_id, args=None):
        """ startInternalPortCapture :
        Start packet capture on an internal port.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        if args is None:
            args = {}
        return self._sendRequest(http_method='PUT', url=f'/internal/ports/{internal_port_id}/start_capture', args=args, response_type='none')

    def getInternalPort(self, internal_port_id, side=None):
        """ getInternalPort :
        Fetch the properties of an internal port.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        params = None if side is None else {'side': side}
        return self._sendRequest(http_method='GET', url=f'/internal/ports/{internal_port_id}', params=params, response_type='json')

    def modifyInternalPort(self, internal_port_id, args, side=None):
        """ modifyInternalPort :
        Update an internal port.
        Platforms:
            Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge 400P,
            Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516,
            Vision One, Vision X, Vision X 400G

        """
        params = None if side is None else {'side': side}
        return self._sendRequest(http_method='PUT', url=f'/internal/ports/{internal_port_id}', args=args, params=params, response_type='none')

    def getInternalLanesForAfmResource(self, resource_id, filter_default_name=None):
        """ getInternalLanesForAfmResource :
        Get the internal lane configuration for an AFM resource attached to a filter.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X

        """
        params = None
        if filter_default_name is not None:
            params = {'filterDefaultName': filter_default_name}
        return self._sendRequest(http_method='GET', url=f'/internal/resource/afm/{resource_id}', params=params, response_type='json')

    def getInternalPortsForResource(self, resource_id, netservice=None):
        """ getInternalPortsForResource :
        Get the internal ports associated with a resource.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X

        """
        params = None
        if netservice is not None:
            value = str(netservice).lower() if isinstance(netservice, bool) else str(netservice)
            params = {'netservice': value}
        return self._sendRequest(http_method='GET', url=f'/internal/resource/{resource_id}', params=params, response_type='json')


    # /kubernetes_nodes

    def getAllKubernetesNodes(self):
        """ getAllKubernetesNodes :
        Fetch a list containing the summaries for all the kubernetes nodes in the system.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='GET', url='/kubernetes_nodes', response_type='json')

    def getKubernetesNodesDetails(self, ids=None):
        """ getKubernetesNodesDetails :
        Fetch detailed properties for all or selected kubernetes nodes.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/kubernetes_nodes/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def getKubernetesNode(self, kubernetes_nodes_id):
        """ getKubernetesNode :
        Fetch the properties of a kubernetes node object.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/kubernetes_nodes/{kubernetes_nodes_id}', response_type='json')

    def resetFactoryDefaultKubernetesNode(self, kubernetes_nodes_id):
        """ resetFactoryDefaultKubernetesNode :
        Reset to factory default a specific kubernetes node from the Mako card.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/kubernetes_nodes/{kubernetes_nodes_id}/reset_factory', args=None, response_type='none')


    # /line_boards

    def getAllLineBoards(self):
        """ getAllLineBoards :
        Fetch a list containing the summaries for all the line boards in the system.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.getAllLineBoards()
        [{u'id': 471, u'name': u'LC6'}, {u'id': 476, u'name': u'LC1'}, {u'id': 474, u'name': u'LC5'}, {u'id': 475, u'name': u'LC3'}, {u'id': 472, u'name': u'LC2'}, {u'id': 473, u'name': u'LC4'}]
        """
        return self._sendRequest(http_method='GET', url='/line_boards', response_type='json')

    def searchLineBoards(self, args):
        """ searchLineBoards :
        Search for a specific capture in the system by certain properties.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.searchLineBoards({'name': 'LC6'})
        [{u'id': 471, u'name': u'LC6'}]
        """
        return self._sendRequest(http_method='POST', url='/line_boards/search', args=args, response_type='json')

    def getLineBoard(self, line_board):
        """ getLineBoard :
        Fetch the properties of a line board.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.getLineBoard('LC6')
        {u'name': u'LC6', u'qsfp_card_mode': u'MODE_QSFP', u'default_name': u'LC6', u'mod_count': 9, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'id': 471}
        """
        return self._sendRequest(http_method='GET', url=f'/line_boards/{line_board}', response_type='json')

    def modifyLineBoard(self, line_board, args):
        """ modifyLineBoard :
        Update the properties of an existing line board.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.modifyLineBoard('LC6', {'name' : 'Test LC'})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/line_boards/{line_board}', args=args, response_type='none')

    def switchModeLineBoard(self, line_board):
        """ switchModeLineBoard :
        Switches the card mode to QSFP if in SFP mode and to SFP if in QSFP mode.
        Platforms:
            NTO 5200, 7300/7303

        Example:
        >>> nto.switchModeLineBoard('LC6')
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/line_boards/{line_board}/switch_mode', args=None, response_type='none')


    # /monitors

    def getAllMonitors(self):
        """ getAllMonitors :
        Fetch a list containing the summaries for all the monitors in the system.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getAllMonitors()
        [{u'id': 572, u'name': u'Low Traffic'}]
        """
        return self._sendRequest(http_method='GET', url='/monitors', response_type='json')

    def createMonitor(self, args):
        """ createMonitor :
        Create a new monitor.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.createMonitor({'actions': [{'min_interval': {'value': 15, 'unit': 'SEC'}, 'type': 'TRAP', 'enabled': True}], 'name': 'Drop Packets', 'trigger': {'stat': 'TP_TOTAL_DROP_COUNT_PACKETS', 'window_size': 1, 'min_change': 10, 'window_count': 1, 'type': 'COUNT_STAT', 'ports': [59]}})
        '{"id": "574"}'
        """
        return self._sendRequest(http_method='POST', url='/monitors', args=args, response_type='json')

    def getMonitorsDetails(self, ids=None):
        """ getMonitorsDetails :
        Fetch detailed properties for all or selected monitors.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/monitors/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchMonitors(self, args):
        """ searchMonitors :
        Search for a specific port group in the system by certain properties.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.searchMonitors({'name': 'Drop Packets'})
        [{u'id': 574, u'name': u'Drop Packets'}]
        """
        return self._sendRequest(http_method='POST', url='/monitors/search', args=args, response_type='json')

    def getMonitor(self, monitor):
        """ getMonitor :
        Fetch the properties of a monitor object which is specified by its
        monitor_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getMonitor('572')
        {u'description': None, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1442432114344}, u'actions': [{u'min_interval': {u'value': 15, u'unit': u'SEC'}, u'type': u'TRAP', u'enabled': True}], u'name': u'Low Traffic', u'mod_count': 0, u'trigger': {u'stat': u'NP_CURRENT_RX_UTILIZATION', u'window_size': 1, u'window_count': 1, u'down_threshold_enabled': True, u'up_threshold': 99, u'up_threshold_enabled': False, u'down_threshold': 10, u'type': u'PERCENT_STAT', u'ports': [58]}, u'id': 572, u'history': []}
        """
        return self._sendRequest(http_method='GET', url=f'/monitors/{monitor}', response_type='json')

    def modifyMonitor(self, monitor_id, args):
        """ modifyMonitor :
        Update properties of a monitor.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.modifyMonitor('574', {'trigger': {'stat': 'TP_TOTAL_DROP_COUNT_PACKETS', 'window_size': 1, 'min_change': 20, 'window_count': 1, 'type': 'COUNT_STAT', 'ports': [59]}})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/monitors/{monitor_id}', args=args, response_type='none')

    def deleteMonitor(self, monitor_id):
        """ deleteMonitor :
        Remove a monitor from the system. The monitor is specified by a monitor_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.deleteMonitor('572')
        ''
        """
        return self._sendRequest(http_method='DELETE', url=f'/monitors/{monitor_id}', args=None, response_type='none')


    # /netflow_resources

    def getAllNetflowResources(self):
        """ getAllNetflowResources :
        Fetch a list containing the summaries for all Netflow resources.
        Platforms:
            Vision Edge 10S

        Example:
        """
        return self._sendRequest(http_method='GET', url='/netflow_resources', response_type='json')

    def getNetflowResourcesDetails(self, ids=None):
        """ getNetflowResourcesDetails :
        Fetch detailed properties for all or selected Netflow resources.
        Platforms:
            Vision Edge 10S

        """
        return self._sendRequest(http_method='POST', url='/netflow_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchNetflowResources(self, args):
        """ searchNetflowResources :
        Search for Netflow resources by searchable properties.
        Platforms:
            Vision Edge 10S

        Example:
        """
        return self._sendRequest(http_method='POST', url='/netflow_resources/search', args=args, response_type='json')

    def getNetflowResource(self, netflow_resource_id, properties=None):
        """ getNetflowResource :
        Fetch the properties of a Netflow resource.
        Platforms:
            Vision Edge 10S

        Example:
        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/netflow_resources/{netflow_resource_id}', params=params, response_type='json')

    def modifyNetflowResource(self, netflow_resource_id, args):
        """ modifyNetflowResource :
        Update the properties of an existing Netflow resource.
        Platforms:
            Vision Edge 10S

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/netflow_resources/{netflow_resource_id}', args=args, response_type='none')

    def attachNetflowResource(self, netflow_resource_id, args):
        """ attachNetflowResource :
        Attach a Netflow resource by attaching a filter to it.
        The request dictionary contains allocated_bandwidth and object_id.
        Platforms:
            Vision Edge 10S

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/netflow_resources/{netflow_resource_id}/attach', args=args, response_type='none')

    def detachNetflowResource(self, netflow_resource_id, args):
        """ detachNetflowResource :
        Detach a Netflow resource by disconnecting the attached filter.
        The request dictionary contains object_id.
        Platforms:
            Vision Edge 10S

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/netflow_resources/{netflow_resource_id}/detach', args=args, response_type='none')

    def getNetflowResourceBandwidth(self, netflow_resource_id):
        """ getNetflowResourceBandwidth :
        Get the bandwidth details for a Netflow resource.
        Platforms:
            Vision Edge 10S

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/netflow_resources/{netflow_resource_id}/get_bandwidth_details', response_type='json')


    # /netservice_instances

    def getAllNetserviceInstances(self):
        """ getAllNetserviceInstances :
        Fetch a list containing the summaries for all the netservice instances in the system.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='GET', url='/netservice_instances', response_type='json')

    def createNetserviceInstance(self, args):
        """ createNetserviceInstance :
        Create a new netservice instance in the system.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/netservice_instances', args=args, response_type='json')

    def getNetserviceInstancesDetails(self, ids=None):
        """ getNetserviceInstancesDetails :
        Fetch detailed properties for all or selected netservice instances.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/netservice_instances/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchNetserviceInstances(self, args):
        """ searchNetserviceInstances :
        Search for a specific netservice instance in the system by certain properties.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/netservice_instances/search', args=args, response_type='json')

    def getNetserviceInstance(self, netservice_id):
        """ getNetserviceInstance :
        Fetch the properties of a netservice instance object.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/netservice_instances/{netservice_id}', response_type='json')

    def modifyNetserviceInstance(self, netservive_id, args):
        """ modifyNetserviceInstance :
        Update the properties of an existing netservice instance.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/netservice_instances/{netservive_id}', args=args, response_type='none')

    def deleteNetserviceInstance(self, netservive_id, args):
        """ deleteNetserviceInstance :
        Remove an existing netservice instance from the system.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='DELETE', url=f'/netservice_instances/{netservive_id}', args=args, response_type='none')

    def deployNetserviceInstance(self, netservive_id):
        """ deployNetserviceInstance :
        Deployes a specific netservice instance in the system.
        This method is allowed only on the following models: 8000.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/netservice_instances/{netservive_id}/deploy', args=None, response_type='none')

    def drainNetserviceInstance(self, netservive_id):
        """ drainNetserviceInstance :
        Drains a specific netservice instance in the system.
        This method is allowed only on the following models: 8000.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/netservice_instances/{netservive_id}/drain', args=None, response_type='none')

    def getAllNetserviceInstancesType(self, netservive_type):
        """ getAllNetserviceInstancesType :
        Fetch a list containing the available resources for specified deployment type in the system.
        This method is allowed only on the following models: 8000.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/netservice_instances/{netservive_type}/list_available_resources', response_type='none')

    def restartNetserviceInstance(self, netservive_id):
        """ restartNetserviceInstance :
        Restarts a specific netservice instance in the system.
        This method is allowed only on the following models: 8000.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/netservice_instances/{netservive_id}/restart', args=None, response_type='none')


    # /netservice_resources

    def getAllNetserviceResources(self):
        """ getAllNetserviceResources :
        Fetch summaries for all Netservice resources.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url='/netservice_resources', response_type='json')

    def getNetserviceResourcesDetails(self, ids=None):
        """ getNetserviceResourcesDetails :
        Fetch detailed properties for all or selected Netservice resources.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/netservice_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchNetserviceResources(self, args):
        """ searchNetserviceResources :
        Search Netservice resources by supported properties.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/netservice_resources/search', args=args, response_type='json')

    def getNetserviceResource(self, resource_id, properties=None):
        """ getNetserviceResource :
        Fetch the properties of a Netservice resource.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/netservice_resources/{resource_id}', params=params, response_type='json')

    def modifyNetserviceResource(self, resource_id, args):
        """ modifyNetserviceResource :
        Update an existing Netservice resource.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/netservice_resources/{resource_id}', args=args, response_type='none')

    def disableNetserviceResource(self, resource_id, args):
        """ disableNetserviceResource :
        Disable a Netservice resource by disconnecting its attached filter.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/netservice_resources/{resource_id}/disable', args=args, response_type='none')

    def enableNetserviceResource(self, resource_id, args):
        """ enableNetserviceResource :
        Enable a Netservice resource by attaching it to a filter.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/netservice_resources/{resource_id}/enable', args=args, response_type='none')


    # /netservice_settings

    def getNetserviceSettings(self):
        """ getNetserviceSettings :
        Displays the netservice settings, including version info for the OS, all the
        net services and containers in the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='GET', url='/netservice_settings', response_type='json')

    def modifyNetserviceSettings(self, netservive_settings_id, args):
        """ modifyNetserviceSettings :
        Update the settings of the netservices.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/netservice_settings/{netservive_settings_id}', args=args, response_type='none')


    # /netservices

    def getAllNetservices(self):
        """ getAllNetservices :
        Fetch a list containing the summaries for all the netservices in the system.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='GET', url='/netservices', response_type='json')

    def getNetservicesDetails(self, ids=None):
        """ getNetservicesDetails :
        Fetch detailed properties for all or selected netservices.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/netservices/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def getNetserviceLicensedFeatures(self):
        """ getNetserviceLicensedFeatures :
        Fetch the features of a netservice object that are included in the installed license.
        Platforms:
            Vision One, Vision X

        Example:
        """
        return self._sendRequest(http_method='GET', url='/netservices/licensed_features', response_type='json')

    def searchNetservices(self, args):
        """ searchNetservices :
        Search for a specific netservice in the system by certain properties.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='POST', url='/netservices/search', args=args, response_type='json')

    def getNetservice(self, netservice_id):
        """ getNetservice :
        Fetch the properties of a netservice object.
        Platforms:
            Vision 400, Vision 400XT, Vision One, Vision X, Vision X 400G

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/netservices/{netservice_id}', response_type='json')


    # /object_template_collections

    def getAllObjectTemplateCollections(self):
        """ getAllObjectTemplateCollections :
        Fetch summaries for all object template collections.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url='/object_template_collections', response_type='json')

    def createObjectTemplateCollection(self, args):
        """ createObjectTemplateCollection :
        Create an object template collection.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/object_template_collections', args=args, response_type='json')

    def searchObjectTemplateCollections(self, args):
        """ searchObjectTemplateCollections :
        Search object template collections by supported properties.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/object_template_collections/search', args=args, response_type='json')

    def getObjectTemplateCollection(self, collection_id):
        """ getObjectTemplateCollection :
        Fetch the properties of an object template collection.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url=f'/object_template_collections/{collection_id}', response_type='json')

    def modifyObjectTemplateCollection(self, collection_id, args):
        """ modifyObjectTemplateCollection :
        Update an object template collection.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/object_template_collections/{collection_id}', args=args, response_type='none')

    def deleteObjectTemplateCollection(self, collection_id):
        """ deleteObjectTemplateCollection :
        Delete an object template collection.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='DELETE', url=f'/object_template_collections/{collection_id}', args=None, response_type='none')


    # /object_templates

    def getAllObjectTemplates(self):
        """ getAllObjectTemplates :
        Fetch summaries for all object templates.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url='/object_templates', response_type='json')

    def searchObjectTemplates(self, args):
        """ searchObjectTemplates :
        Search object templates by supported properties.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/object_templates/search', args=args, response_type='json')

    def getObjectTemplate(self, template_id):
        """ getObjectTemplate :
        Fetch the properties of an object template.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='GET', url=f'/object_templates/{template_id}', response_type='json')

    def modifyObjectTemplate(self, template_id, args):
        """ modifyObjectTemplate :
        Update an object template.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/object_templates/{template_id}', args=args, response_type='none')

    def deleteObjectTemplate(self, template_id):
        """ deleteObjectTemplate :
        Delete an object template.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='DELETE', url=f'/object_templates/{template_id}', args=None, response_type='none')


    # /passive_ssl_resources

    def getAllPassiveSslResources(self):
        """ getAllPassiveSslResources :
        Fetch summaries for all PassiveSSL resources.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision One, Vision X

        """
        return self._sendRequest(http_method='GET', url='/passive_ssl_resources', response_type='json')

    def getPassiveSslResourcesDetails(self, ids=None):
        """ getPassiveSslResourcesDetails :
        Fetch detailed properties for all or selected PassiveSSL resources.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url='/passive_ssl_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchPassiveSslResources(self, args):
        """ searchPassiveSslResources :
        Search PassiveSSL resources by supported properties.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision One, Vision X

        """
        return self._sendRequest(http_method='POST', url='/passive_ssl_resources/search', args=args, response_type='json')

    def getPassiveSslResource(self, resource_id, properties=None):
        """ getPassiveSslResource :
        Fetch the properties of a PassiveSSL resource.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision One, Vision X

        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/passive_ssl_resources/{resource_id}', params=params, response_type='json')

    def modifyPassiveSslResource(self, resource_id, args):
        """ modifyPassiveSslResource :
        Update an existing PassiveSSL resource.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/passive_ssl_resources/{resource_id}', args=args, response_type='none')

    def disablePassiveSslResource(self, resource_id, args):
        """ disablePassiveSslResource :
        Disable a PassiveSSL resource by disconnecting its attached filter.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/passive_ssl_resources/{resource_id}/disable', args=args, response_type='none')

    def enablePassiveSslResource(self, resource_id, args):
        """ enablePassiveSslResource :
        Enable a PassiveSSL resource by attaching it to a filter.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision One, Vision X

        """
        return self._sendRequest(http_method='PUT', url=f'/passive_ssl_resources/{resource_id}/enable', args=args, response_type='none')


    # /port_groups

    def getAllPortGroups(self):
        """ getAllPortGroups :
        Fetch a list containing the summaries for all the port groups in the system.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getAllPortGroups()
        [{u'id': 202, u'name': u'PGF27'}, {u'id': 203, u'name': u'PGF31'}, {u'id': 204, u'name': u'PGF30'}, {u'id': 205, u'name': u'PGF29'}, {u'id': 206, u'name': u'PGF28'}, {u'id': 251, u'name': u'PGF1'}, {u'id': 252, u'name': u'PGF2'}, {u'id': 253, u'name': u'PGF3'}, {u'id': 254, u'name': u'PGF4'}, {u'id': 255, u'name': u'PGF5'}, {u'id': 288, u'name': u'PGF6'}, {u'id': 289, u'name': u'PGF7'}, {u'id': 290, u'name': u'PGF8'}, {u'id': 291, u'name': u'PGF9'}, {u'id': 292, u'name': u'PGF10'}, {u'id': 325, u'name': u'PGF11'}, {u'id': 326, u'name': u'PGF12'}, {u'id': 327, u'name': u'PGF13'}, {u'id': 328, u'name': u'PGF14'}, {u'id': 329, u'name': u'PGF15'}, {u'id': 362, u'name': u'PGF16'}, {u'id': 363, u'name': u'PGF17'}, {u'id': 364, u'name': u'PGF18'}, {u'id': 365, u'name': u'PGF19'}, {u'id': 366, u'name': u'PGF20'}, {u'id': 399, u'name': u'PGF21'}, {u'id': 400, u'name': u'PGF22'}, {u'id': 401, u'name': u'PGF23'}, {u'id': 402, u'name': u'PGF24'}, {u'id': 403, u'name': u'PGF25'}, {u'id': 404, u'name': u'PG1'}]
        """
        return self._sendRequest(http_method='GET', url='/port_groups', response_type='json')

    def createPortGroup(self, args):
        """ createPortGroup :
        Create a new port group.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.createPortGroup({'mode': 'NETWORK', 'type': 'INTERCONNECT', 'port_list': [59,60]})
        {u'id': u'405'}
        """
        return self._sendRequest(http_method='POST', url='/port_groups', args=args, response_type='json')

    def getPortGroupsDetails(self, ids=None):
        """ getPortGroupsDetails :
        Fetch detailed properties for all or selected port groups.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/port_groups/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchPortGroups(self, args):
        """ searchPortGroups :
        Search for a specific port group in the system by certain properties.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.searchPortGroups({'enabled_status' : 'DISABLED'})
        [{u'id': 404, u'name': u'PG1'}]
        """
        return self._sendRequest(http_method='POST', url='/port_groups/search', args=args, response_type='json')

    def getPortGroupWritableProperties(self):
        """ getPortGroupWritableProperties :
        List writable property names for port groups.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/port_groups/writable_props', args=None, response_type='json')

    def modifyPortGroup(self, port_group_id, args):
        """ modifyPortGroup :
        Update properties of a port group.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.modifyPortGroup('PG2', {'port_list': [59,60,61,62]})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/port_groups/{port_group_id}', args=args, response_type='none')

    def deletePortGroup(self, port_group_id):
        """ deletePortGroup :
        Remove a port group from the system. The port group is specified by a port_group_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.deletePortGroup('PG2')
        ''
        """
        return self._sendRequest(http_method='DELETE', url=f'/port_groups/{port_group_id}', args=None, response_type='none')

    def applyTemplateToPortGroup(self, port_group_id, args):
        """ applyTemplateToPortGroup :
        Apply an object template to a port group.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/port_groups/{port_group_id}/apply_template', args=args, response_type='none')

    def createTemplateFromPortGroup(self, port_group_id, args):
        """ createTemplateFromPortGroup :
        Create an object template from a port group.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/port_groups/{port_group_id}/create_template', args=args, response_type='json')

    def disablePortGroup(self, port_group_id):
        """ disablePortGroup :
        Disables a port group by disabling all the contained ports.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/port_groups/{port_group_id}/disable', args=None, response_type='none')

    def enablePortGroup(self, port_group_id):
        """ enablePortGroup :
        Enables a port group by enabling all the contained ports.
        Platforms:
            NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/port_groups/{port_group_id}/enable', args=None, response_type='none')

    def getAllProbes(self, port_group):
        """ getAllProbes:
        Retrieves all probes associated with a port group.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.getAllProbes('100')
        [{u'is_redundant': False, u'description': u'GRE Probe', u'created_date_time': 1503632180163, u'last_modified_date_time': 1503632180163, u'is_active': True, u'created_by_user': u'admin', u'last_modified_by_user': u'admin', u'failed_over_to_probe_id': None, u'ip_address': u'10.218.20.20', u'id': 2, u'port_id_list': [36, 37], u'name': u'RADCOM Probe'}]
        """
        return self._sendRequest(http_method='GET', url=f'/port_groups/{port_group}/probes', args=None, response_type='json')

    def createProbe(self, port_group, args):
        """ createProbe:
        Adds a probe to a port group.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.createProbe('100', {'description': 'GRE Probe', 'ip_address': '10.218.20.20', 'is_redundant': False, 'name': 'RADCOM Probe', 'port_id_list': [36, 37]})
        {u'id': 1}
        """

        return self._sendRequest(http_method='POST', url=f'/port_groups/{port_group}/probes', args=args, response_type='json')

    def getProbe(self, port_group, probe):
        """ getProbe:
        Retrieves a probe associated with a port group.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.getProbe('100', '3')
        {u'is_redundant': False, u'description': u'GRE Probe', u'created_date_time': 1503632397617, u'last_modified_date_time': 1503632397617, u'is_active': False, u'created_by_user': u'admin', u'last_modified_by_user': u'admin', u'failed_over_to_probe_id': None, u'ip_address': u'10.218.20.20', u'id': 3, u'port_id_list': [36, 37], u'name': u'RADCOM Probe'}
        """
        return self._sendRequest(http_method='GET', url=f'/port_groups/{port_group}/probes/{probe}', args=None, response_type='json')

    def modifyProbe(self, port_group, probe, args):
        """ modifyProbe:
        Updates a probe associated with a port group.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.modifyProbe('100', '4', {'ip_address': '10.218.20.30'})
        ''
        """

        return self._sendRequest(http_method='PUT', url=f'/port_groups/{port_group}/probes/{probe}', args=args, response_type='none')

    def deleteProbe(self, port_group, probe):
        """ deleteProbe:
        Delete a probe associated with a port group.
        Platforms:
            GSC 7400

        Example:
        gsc.deleteProbe('100', '1')
        """

        return self._sendRequest(http_method='DELETE', url=f'/port_groups/{port_group}/probes/{probe}', args=None, response_type='none')

    def getPortGroup(self, port_group, properties=None):
        """ getPortGroup :
        Fetch the properties of a port group object which is specified by its
        port_group_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getPortGroup('404')
        {u'trim_settings': None, u'supports_timestamp': False, u'dedup_settings': None, u'vntag_strip_settings': None, u'vxlan_strip_settings': None, u'failover_mode': u'REBALANCE', u'keywords': [], u'supports_dedup': False, u'id': 404, u'fabric_path_strip_settings': None, u'supports_vntag_strip': False, u'has_dropped_packets': False, u'filtering_direction': u'INGRESS', u'supports_trailer_strip': False, u'icon_type': u'INTERCONNECT', u'last_filter_order_event': None, u'supports_mpls_strip': False, u'enabled_status': u'ENABLED', u'supports_burst_buffer': False, u'custom_icon_id': None, u'trailer_strip_settings': None, u'mpls_strip_settings': None, u'type': u'INTERCONNECT', u'tx_light_status': u'ON', u'filter_criteria': {u'logical_operation': u'AND'}, u'supports_std_vlan_strip': True, u'pause_frames_status': u'IGNORE', u'dest_filter_list': [], u'description': None, u'snmp_tag': None, u'l2gre_strip_settings': None, u'gtp_strip_settings': None, u'burst_buffer_settings': None, u'force_link_up': u'NOT_SUPPORTED', u'supports_trim': False, u'supports_gtp_strip': False, u'port_list': [58], u'supports_vxlan_strip': False, u'name': u'PG1', u'supports_l2gre_strip': False, u'supports_fabric_path_strip': False, u'link_status': {u'speed': 0, u'link_up': False}, u'interconnect_info': {u'addr': u'0.0.0.0', u'port_group': None}, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1442434236579}, u'default_name': u'PG1', u'supports_erspan_strip': False, u'mod_count': 1, u'timestamp_settings': None, u'erspan_strip_settings': None, u'mode': u'NETWORK', u'source_filter_list': [], u'filter_mode': u'PASS_ALL', u'std_vlan_strip_settings': {u'ingress_count': 0, u'egress_count': 0, u'enabled': False, u'strip_mode': None}, u'history': [{u'type': u'MODIFY', u'time': 1442434236579, u'caused_by': u'admin', u'details': None, u'props': [u'PORT_LIST']}]}
        """
        params = None
        if properties:
            params = {'properties': ''.join(properties.split())}

        return self._sendRequest(http_method='GET', url=f'/port_groups/{port_group}', params=params, response_type='json')

    def getPortGroupProperties(self, port_group, properties):
        """ getPortGroupProperties :
        Fetch one or more properties of a port group object which is specified by its
        port_group_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getPortGroupProperties('50', 'keywords,link_status,default_name,enabled,filter_mode')
        {u'filter_mode': u'DISABLE', u'keywords': [], u'default_name': u'PG1', u'enabled': None, u'link_status': {u'speed': 10000, u'link_up': True}}
        """
        return self.getPortGroup(port_group, properties)

    def getPortGroupProperty(self, port_group, property):
        """ getPortGroupProperty :
        Fetch a property of a port group object which is specified by its
        port_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getPortGroupProperty('PG1', 'keywords')
        [u'TIME']
        """
        return self.getPortGroup(port_group, property)[property]


    # /ports

    def getAllPorts(self):
        """ getAllPorts :
        Fetch a list containing summaries for all the ports in the system.

        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getAllPorts()
        [{u'id': 58, u'name': u'P1-01'}, {u'id': 59, u'name': u'P1-02'}, {u'id': 60, u'name': u'P1-03'}, {u'id': 61, u'name': u'P1-04'}, {u'id': 62, u'name': u'P1-05'}, {u'id': 63, u'name': u'P1-06'}, {u'id': 64, u'name': u'P1-07'}, {u'id': 65, u'name': u'P1-08'}, {u'id': 66, u'name': u'P1-09'}, {u'id': 67, u'name': u'P1-10'}, {u'id': 68, u'name': u'P1-11'}, {u'id': 69, u'name': u'P1-12'}, {u'id': 70, u'name': u'P1-13'}, {u'id': 71, u'name': u'P1-14'}, {u'id': 72, u'name': u'P1-15'}, {u'id': 73, u'name': u'P1-16'}]
        """
        return self._sendRequest(http_method='GET', url='/ports', response_type='json')

    def createPort(self, args):
        """ createPort :
        Create a new port on the system. This can be used only to create
        virtual ports for GRE origination.

        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        >>> nto.createPort({'parent_port_id': 16, 'type': 'VIRTUAL_PORT', 'netstack_tunnel_origination_remote_settings': {'enable_arp': True, 'remote_ip_address': '10.0.1.3'}})
        {'default_name': 'P01-T01', 'id': 100, 'name': 'P01-T01'}
        >>> nto.modifyPort('P01', {'netstack_tunnel_origination_local_settings': {'enabled': True, 'l2gre_key': 1, 'vnid': None}})
        b''
        """
        return self._sendRequest(http_method='POST', url='/ports', args=args, response_type='json')

    def getPortsDetails(self, ids=None):
        """ getPortsDetails :
        Fetch detailed properties for all or selected ports.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/ports/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchPorts(self, args):
        """ searchPorts :
        Search for a specific port in the system by certain properties.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.searchPorts({'mode': 'TOOL'})
        [{u'id': 58, u'name': u'P1-01'}]
        """
        return self._sendRequest(http_method='POST', url='/ports/search', args=args, response_type='json')

    def getPortWritableProperties(self):
        """ getPortWritableProperties :
        List writable property names for ports.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/ports/writable_props', args=None, response_type='json')

    def deletePort(self, port):
        """ deletePort :
        Remove a port from the system. This can be used only to remove
        virtual ports for GRE origination.

        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        >>> nto.modifyPort('P01', {'netstack_tunnel_origination_local_settings': {'enabled': False}})
        b''
        >>> nto.deletePort('P01-T01')
        b''
        """
        return self._sendRequest(http_method='DELETE', url=f'/ports/{port}', args=None, response_type='none')

    def applyObjectTemplateToPort(self, port_id, args):
        """ applyObjectTemplateToPort :
        Apply an object template to a port.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/ports/{port_id}/apply_template', args=args, response_type='none')

    def clearPort(self, port):
        """ clearPort :
        Clears a port to default configuration. No properties are required in the HTTP Body.

        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        >>> nto.clearPort('P1-01')
        b''
        """
        return self._sendRequest(http_method='PUT', url=f'/ports/{port}/clear', args=None, response_type='none')

    def createObjectTemplateFromPort(self, port_id, args):
        """ createObjectTemplateFromPort :
        Create an object template from a port.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/ports/{port_id}/create_template', args=args, response_type='json')

    def deletePortPcapFile(self, port_id, args):
        """ deletePortPcapFile:
        Deletes one or more PCAP files from Port.

        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/ports/{port_id}/delete_pcap_files', args=args, response_type='json')

    def downloadPortPcapFiles(self, port_id, args):
        """ downloadPortPcapFiles:
        Download one or more PCAP files for Port.

        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/ports/{port_id}/download_pcap_files', args=args, response_type='bytes')

    def getPortPcapFileList(self, port_id):
        """ getPortPcapFileList:
        Get a list of all PCAP files available for Port.

        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/ports/{port_id}/get_pcap_file_list', args=None, response_type='json')

    def startPortCapture(self, port_id, args):
        """ startPortCapture:
        Start capture on a Port. The optional request can specify max_pkt_count
        and traffic_direction.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        """
        return self._sendRequest(http_method='PUT', url=f'/ports/{port_id}/start_capture', args=args, response_type='none')

    def getPortTransceiverInfo(self, port_id):
        """ getPortTransceiverInfo :
        Fetch the transceiver information of a port object which is specified by its
        port_id_or_nam
        Platforms:
            UNMATCHED - likely deprecated

        Example:

        >>> nto.getPortTransceiverInfo('P03')
        {'lanes': 1, 'port_default_name': 'P03', 'port_id': '18', 'port_name': 'P03', 'transceiver_info': [{'cable': 'N/A', 'compliance': '100G AOC or 25GAUI C2M AOC', 'connector': 'No separable connector', 'diag_calibration': 'Not Applicable', 'identifier': 'QSFP28', 'length_comment': 'OM4 50um', 'length_mode': 'Unspecified', 'max_length': '6 meters', 'present': 'true', 'rx_input_power1': '1.3392', 'rx_input_power1_dbm': '1.27', 'rx_input_power2': '1.3545', 'rx_input_power2_dbm': '1.32', 'rx_input_power3': '1.3764', 'rx_input_power3_dbm': '1.39', 'rx_input_power4': '1.352', 'rx_input_power4_dbm': '1.31', 'rx_input_power_high_alert_threshold': '3.4673', 'rx_input_power_high_alert_threshold_dbm': '5.40', 'rx_input_power_high_warning_threshold': '1.7378', 'rx_input_power_high_warning_threshold_dbm': '2.40', 'rx_input_power_low_alert_threshold': '0.0467', 'rx_input_power_low_alert_threshold_dbm': '-13.31', 'rx_input_power_low_warning_threshold': '0.0933', 'rx_input_power_low_warning_threshold_dbm': '-10.30', 'rx_input_power_status1': 'Normal', 'rx_input_power_status2': 'Normal', 'rx_input_power_status3': 'Normal', 'rx_input_power_status4': 'Normal', 'temperature': '35', 'temperature_high_alert_threshold': '80', 'temperature_high_warning_threshold': '70', 'temperature_low_alert_threshold': '-10', 'temperature_low_warning_threshold': '0', 'temperature_status': 'Normal', 'tx_bias1': '6.75', 'tx_bias2': '6.75', 'tx_bias3': '6.75', 'tx_bias4': '6.75', 'tx_bias_high_alert_threshold': '8.5', 'tx_bias_high_warning_threshold': '8.0', 'tx_bias_low_alert_threshold': '5.492', 'tx_bias_low_warning_threshold': '6.0', 'tx_bias_status1': 'Normal', 'tx_bias_status2': 'Normal', 'tx_bias_status3': 'Normal', 'tx_bias_status4': 'Normal', 'tx_output_power1': '1.6412', 'tx_output_power1_dbm': '2.15', 'tx_output_power2': '1.6222', 'tx_output_power2_dbm': '2.10', 'tx_output_power3': '1.5521', 'tx_output_power3_dbm': '1.91', 'tx_output_power4': '1.5447', 'tx_output_power4_dbm': '1.89', 'tx_output_power_high_alert_threshold': '3.4673', 'tx_output_power_high_alert_threshold_dbm': '5.40', 'tx_output_power_high_warning_threshold': '1.7378', 'tx_output_power_high_warning_threshold_dbm': '2.40', 'tx_output_power_low_alert_threshold': '0.0724', 'tx_output_power_low_alert_threshold_dbm': '-11.40', 'tx_output_power_low_warning_threshold': '0.1445', 'tx_output_power_low_warning_threshold_dbm': '-8.40', 'tx_output_power_status1': 'Normal', 'tx_output_power_status2': 'Normal', 'tx_output_power_status3': 'Normal', 'tx_output_power_status4': 'Normal', 'vendor_date_code': '05-07-2018', 'vendor_lot_code': '  ', 'vendor_name': 'Mellanox', 'vendor_oui': '0002c9', 'vendor_part_number': 'MFA1A00-C003', 'vendor_rev': 'B1', 'vendor_serial_number': 'MT1823FT00529', 'voltage': '3.2691', 'voltage_high_alert_threshold': '3.5', 'voltage_high_warning_threshold': '3.465', 'voltage_low_alert_threshold': '3.1', 'voltage_low_warning_threshold': '3.135', 'voltage_status': 'Normal', 'wavelength': '8500'}]}        """
        return self._sendRequest(http_method='GET', url=f'/ports/{port_id}/transceiver_info', args=None, response_type='json')

    def getPort(self, port, properties=None, side=None):
        """ getPort :
        Fetch the properties of a port object which is specified by its
        port_id_or_name.

        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getPort('58')
        {u'trim_settings': None, u'supports_timestamp': False, u'dedup_settings': None, u'filter_criteria': {u'logical_operation': u'AND'}, u'vntag_strip_settings': None, u'std_port_tagging_settings': {u'enabled': False, u'vlan_id': 101}, u'link_up_down_trap_enabled': True, u'filter_match_count_unit': u'PACKETS', u'gtp_fd_settings': None, u'keywords': [u'LC1'], u'tunnel_termination_settings': {u'ip_version': 4, u'dest_ip_addr': None, u'enabled': False, u'empty_erspan_header': False, u'tunnel_protocol': None}, u'supports_dedup': False, u'id': 58, u'fabric_path_strip_settings': None, u'supports_vxlan_strip': False, u'port_group_id': None, u'mpls_strip_settings': None, u'max_licensed_speed': u'40G', u'supports_vntag_strip': False, u'has_dropped_packets': False, u'filtering_direction': u'INGRESS', u'supports_trailer_strip': False, u'tunnel_mac': None, u'supports_tunnel_termination': False, u'supports_mpls_strip': False, u'copper_link_polling': False, u'last_filter_order_event': None, u'vxlan_strip_settings': None, u'supports_burst_buffer': False, u'custom_icon_id': None, u'trailer_strip_settings': None, u'media_type': u'QSFP_PLUS_40G', u'expiration_time': 1449727199651, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'type': u'QSFP_PLUS', u'link_settings': u'40G_FULL', u'tx_light_status': u'ON', u'connect_in_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'supports_std_vlan_strip': True, u'dest_filter_list': [], u'description': None, u'snmp_tag': None, u'l2gre_strip_settings': None, u'gtp_strip_settings': None, u'burst_buffer_settings': None, u'force_link_up': u'NOT_SUPPORTED', u'supports_trim': False, u'supports_gtp_strip': False, u'license_status': u'VALID', u'resource_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'supports_std_port_tagging': True, u'remote_fabric_port': None, u'connect_out_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'name': u'P1-01', u'supports_l2gre_strip': False, u'supports_fabric_path_strip': False, u'ignore_pause_frames': True, u'link_status': {u'duplex': u'UNKNOWN', u'pause': u'UNKNOWN', u'speed': u'N/A', u'link_up': False}, u'icon_type': u'QSFP_PLUS', u'default_name': u'P1-01', u'enabled': False, u'supports_erspan_strip': False, u'mod_count': 21, u'timestamp_settings': None, u'erspan_strip_settings': None, u'mode': u'NETWORK', u'supports_gtp_flow_distribution': False, u'source_filter_list': [], u'filter_mode': u'PASS_ALL', u'std_vlan_strip_settings': {u'ingress_count': 0, u'egress_count': 0, u'enabled': False, u'strip_mode': None}, u'history': []}
        """
        params = {}
        if properties:
            params['properties'] = ''.join(properties.split())
        if side is not None:
            params['side'] = side

        return self._sendRequest(http_method='GET', url=f'/ports/{port}', params=params, response_type='json')

    def modifyPort(self, port_id, args, side=None):
        """ modifyPort :
        Update the properties of a port.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.modifyPort('58', {'mode': 'TOOL'})
        ''
        """
        params = None if side is None else {'side': side}
        return self._sendRequest(http_method='PUT', url=f'/ports/{port_id}', args=args, params=params, response_type='none')

    def getPortProperties(self, port, properties):
        """ getPortProperties :
        Fetch one or more properties of a port object which is specified by its
        port_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getPortProperties('PB07', 'enabled,link_status')
        {u'enabled': True, u'link_status': {u'duplex': u'FULL', u'pause': u'DISABLED', u'speed': u'10G', u'link_up': True}}
        """
        return self.getPort(port, properties)

    def getPortProperty(self, port, property):
        """ getPortProperty :
        Fetch a property of a port object which is specified by its
        port_id_or_name.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getPortProperty('PB07', 'enabled')
        {u'enabled': True}
        """
        return self.getPort(port, property)[property]


    # /recirculated_afm_resources

    def getAllAfms(self):
        """ getAllAfms :
        Fetch a list containing the summaries for all the recirculated AFM resources in the system.
        Platforms:
            7300/7303, Vision 400, Vision 400XT, Vision Edge 10S, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getAllAfms()
        [{u'id': 96, u'name': u'L1-AFM'}]
        """
        return self._sendRequest(http_method='GET', url='/recirculated_afm_resources', response_type='json')

    def getAfmsDetails(self, ids=None):
        """ getAfmsDetails :
        Fetch detailed properties for all or selected PacketStack/recirculated AFM resources.
        Platforms:
            Vision 400, Vision 400XT, Vision Edge 10S, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(
            http_method='POST',
            url='/recirculated_afm_resources/detail',
            args=None,
            params=self._buildIdsParams(ids),
            response_type='json'
        )

    def searchAfms(self, args):
        """ searchAfms :
        Search for a specific recirculated AFM resource in the system by certain properties.
        Platforms:
            7300/7303, Vision 400, Vision 400XT, Vision Edge 10S, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.searchAfms({'description': 'AFM Resources'})
        [{u'id': 96, u'name': u'L1-AFM'}]
        """
        return self._sendRequest(http_method='POST', url='/recirculated_afm_resources/search', args=args, response_type='json')

    def getAfm(self, afm_id, properties=None):
        """ getAfm :
        Fetch the properties of a recirculated AFM object.
        Platforms:
            7300/7303, Vision 400, Vision 400XT, Vision Edge 10S, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getAfm('96')
        {u'description': u'AFM Resources', u'lane_config_list': [{u'allocated_bandwidth': 10, u'attachment_id': u'52', u'attachment_type': u'PORT'}, {u'allocated_bandwidth': 10, u'attachment_id': u'53', u'attachment_type': u'PORT'}], u'capture_source': None, u'lineboard_id': None, u'default_name': u'L1-AFM', u'resource_status': u'READY', u'name': u'L1-AFM', u'mod_count': 20, u'license_status': u'NOT_PRESENT', u'capture_port_group': None, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'id': 96, u'connect_disconnect_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'history': [{u'type': u'MODIFY', u'time': 1497393506254, u'caused_by': u'admin', u'details': None, u'props': [u'DESCRIPTION']}]}
        >>> nto.getAfm('L1-AFM')
        {u'description': u'AFM Resources', u'lane_config_list': [{u'allocated_bandwidth': 10, u'attachment_id': u'52', u'attachment_type': u'PORT'}, {u'allocated_bandwidth': 10, u'attachment_id': u'53', u'attachment_type': u'PORT'}], u'capture_source': None, u'lineboard_id': None, u'default_name': u'L1-AFM', u'resource_status': u'READY', u'name': u'L1-AFM', u'mod_count': 20, u'license_status': u'NOT_PRESENT', u'capture_port_group': None, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'id': 96, u'connect_disconnect_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'history': [{u'type': u'MODIFY', u'time': 1497393506254, u'caused_by': u'admin', u'details': None, u'props': [u'DESCRIPTION']}]}
        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/recirculated_afm_resources/{afm_id}', params=params, response_type='json')

    def modifyAfm(self, afm_id, args):
        """ modifyAfm:
        Update the properties of an existing recirculated AFM resource.
        Platforms:
            7300/7303, Vision 400, Vision 400XT, Vision Edge 10S, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.modifyAfm('96', {'description': 'Shared AFM Resources'})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/recirculated_afm_resources/{afm_id}', args=args, response_type='none')

    def disableAfm(self, afm_id, args):
        """ disableAfm :
        Disables an recirculated AFM by disconnecting the attached port, port group or filter.
        Platforms:
            7300/7303, Vision 400, Vision 400XT, Vision Edge 10S, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.disableAfm('96', {'object_id': '53'})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/recirculated_afm_resources/{afm_id}/disable', args=args, response_type='none')

    def enableAfm(self, afm_id, args):
        """ enableAfm :
        Enables an recirculated AFM by attaching a port, port group or filter to it.
        Platforms:
            7300/7303, Vision 400, Vision 400XT, Vision Edge 10S, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.enableAfm('96', {'allocated_bandwidth': 10, 'object_id': '53', 'port_mode': 'NETWORK'})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/recirculated_afm_resources/{afm_id}/enable', args=args, response_type='none')

    def getBandwidthDetailsAfm(self, afm_id):
        """ getBandwidthDetailsAfm :
        Gets the bandwidth details for the Recirculated AFM resource.
        Platforms:
            7300/7303, Vision 400, Vision 400XT, Vision Edge 10S, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getBandwidthDetailsAfm('96')
        {u'allocated_bandwidth': 20, u'total_bandwidth': 160, u'available_bandwidth': 140, u'bandwidth_increment': 10}
        """
        return self._sendRequest(http_method='PUT', url=f'/recirculated_afm_resources/{afm_id}/get_bandwidth_details', args=None, response_type='json')

    def setAfmLoadBalance(self, afm_id, args):
        """ setAfmLoadBalance:
        Set load balance weights on PacketStack data lanes( internal ports).
        Platforms:
            Vision Edge 10S, Vision One, Vision X

        Example:
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/recirculated_afm_resources/{afm_id}/set_load_balance', args=args, response_type='none')

    def updateAfmAttachment(self, afm_id, args):
        """ updateAfmAttachment :
        Update a PacketStack/recirculated AFM attachment to a port, port group, or filter.
        Platforms:
            Vision 400, Vision 400XT, Vision X 400G

        """
        return self._sendRequest(http_method='PUT', url=f'/recirculated_afm_resources/{afm_id}/update_attachment', args=args, response_type='none')


    # /recovery_appliance

    def getRecoveryApplianceProperties(self, args):
        """ getRecoveryApplianceProperties:
        Retrieve the properties of the Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.getRecoveryApplianceProperties()
        TBD
        """
        return self._sendRequest(http_method='GET', url='/recovery_appliance', args=args, response_type='json')

    def modifyRecoveryApplianceProperties(self, args):
        """ modifyRecoveryApplianceProperties:
        Update the properties of the Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.modifyRecoveryApplianceProperties()
        TBD
        """
        return self._sendRequest(http_method='PUT', url='/recovery_appliance', args=args, response_type='none')

    def getNumberSessions(self):
        """ getNumberSessions:
        Retrieve the number sessions backed up in the Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        TBD
        """
        return self._sendRequest(http_method='GET', url='/recovery_appliance/get_num_sessions', args=None, response_type='json')

    def getNtpServersStatus(self):
        """ getNtpServersStatus:
        Retrieve NTP servers status configured for the Recovery Appliance.
        Platforms:
            GSC 7400

        Example:
        >>> gsc.getNTPServersStatus()
       TBD
        """
        return self._sendRequest(http_method='GET', url='/recovery_appliance/ntp_servers_status', args=None, response_type='json')


    # /rtp_correlator_resources

    def getAllRtps(self):
        """ getAllRtps :
        Fetch a list containing the summaries for all the RTP Correlator resources in the system.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='GET', url='/rtp_correlator_resources', response_type='json')

    def getRtpsDetails(self, ids=None):
        """ getRtpsDetails :
        Fetch detailed properties for all or selected RTP Correlator resources.
        Platforms:
            Vision One

        """
        return self._sendRequest(http_method='POST', url='/rtp_correlator_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchRtps(self, args):
        """ searchRtps :
        Search for a specific RTP Correlator resource in the system by certain properties.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='POST', url='/rtp_correlator_resources/search', args=args, response_type='json')

    def getRtp(self, rtp_id, properties=None):
        """ getRtp :
        Fetch the properties of a RTP Correlator resource object.
        Platforms:
            Vision One

        Example:
        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/rtp_correlator_resources/{rtp_id}', params=params, response_type='json')

    def modifyRtp(self, rtp_id, args):
        """ modifyRtp :
        Update the properties of an existing RTP Correlator resource.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/rtp_correlator_resources/{rtp_id}', args=args, response_type='none')

    def disableRtp(self, rtp_id, args):
        """ disableRtp :
        Disables an RTP resource by disconnecting the attached filter.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/rtp_correlator_resources/{rtp_id}/disable', args=args, response_type='none')

    def enableRtp(self, rtp_id, args):
        """ enableRtp :
        Enables an RTP resource by attaching a filter to it.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/rtp_correlator_resources/{rtp_id}/enable', args=args, response_type='none')


    # /sip_correlator_resources

    def getAllSips(self):
        """ getAllSips :
        Fetch a list containing the summaries for all the SIP Correlator resources in the system.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='GET', url='/sip_correlator_resources', response_type='json')

    def getSipsDetails(self, ids=None):
        """ getSipsDetails :
        Fetch detailed properties for all or selected SIP Correlator resources.
        Platforms:
            Vision One

        """
        return self._sendRequest(http_method='POST', url='/sip_correlator_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchSips(self, args):
        """ searchSips :
        Search for a specific SIP Correlator resource in the system by certain properties.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='POST', url='/sip_correlator_resources/search', args=args, response_type='json')

    def getSip(self, sip_id, properties=None):
        """ getSip :
        Fetch the properties of a SIP Correlator resource object.
        Platforms:
            Vision One

        Example:
        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/sip_correlator_resources/{sip_id}', params=params, response_type='json')

    def modifySip(self, sip_id, args):
        """ modifySip :
        Update the properties of an existing SIP Correlator resource.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/sip_correlator_resources/{sip_id}', args=args, response_type='none')

    def addSipAllowistEntries(self, sip_id, args):
        """ addSipAllowistEntries :
        Adds the entries sent in the 'allowlist' parameter as an array of Strings.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/sip_correlator_resources/{sip_id}/allowList', args=args, response_type='none')

    def deleteSipAllowListEntries(self, sip_id, args):
        """ deleteSipAllowListEntries :
        Deletes the entries sent in the 'allowlist' parameter as an array of Strings.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/sip_correlator_resources/{sip_id}/allowList', args=args, response_type='none')

    def retrieveSipAllowlistChunk(self, sip_id, args):
        """ retrieveSipAllowlistChunk :
        Retrieve an Allow List chunk using the 'start' parameter as the starting index. If that
        value exceeds the size of the Allow List, an empty array will be returned.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/sip_correlator_resources/{sip_id}/allowList/chunk', args=args, response_type='none')

    def retrieveSipWhitelistChunk(self, sip_id, args):
        """ retrieveSipWhitelistChunk :
        Retrieve a White List chunk using the 'start' parameter as the starting index. If that
        value exceeds the size of the White List, an empty array will be returned.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/sip_correlator_resources/{sip_id}/chunk', args=args, response_type='none')

    def clearSipAllowList(self, sip_id):
        """ clearSipAllowList :
        Delete all the Allow List entries.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/sip_correlator_resources/{sip_id}/allowList/clear', args=None, response_type='none')

    def clearSipWhiteList(self, sip_id):
        """ clearSipWhiteList :
        Delete all the White List entries.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/sip_correlator_resources/{sip_id}/clear', args=None, response_type='none')

    def disableSip(self, sip_id):
        """ disableSip :
        Detaches an SIP resource by disconnecting from the attached filter.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/sip_correlator_resources/{sip_id}/disable', args=None, response_type='none')

    def enableSip(self, sip_id, args):
        """ enableSip :
        Enables a SIP Correlator resource by attaching a filter to it.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='PUT', url=f'/sip_correlator_resources/{sip_id}/enable', args=args, response_type='none')

    def exportSipAllowListEntries(self, sip_id):
        """ exportSipAllowListEntries :
        Exports AllowList entries to a CSV. Each one will be on a separate line.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/sip_correlator_resources/{sip_id}/exportAllowList', args=None, response_type='none')

    def exportSipWhiteListEntries(self, sip_id):
        """ exportSipWhiteListEntries :
        Exports WhiteList entries to a CSV. Each one will be on a separate line.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/sip_correlator_resources/{sip_id}/exportWhiteList', args=None, response_type='bytes')

    def retrieveSipFilteredAllowlistChunk(self, sip_id, args):
        """ retrieveSipFilteredAllowlistChunk :
        Retrieve an Allow List chunk using the 'start' parameter as the starting index and
        the 'filter' parameter as a RegExp pattern to filter the entries. If the 'start'
        parameter value exceeds the size of the Allow List, an empty array will be returned.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/sip_correlator_resources/{sip_id}/allowList/chunk/filter', args=args, response_type='none')

    def retrieveSipFilteredWhitelistChunk(self, sip_id, args):
        """ retrieveSipFilteredWhitelistChunk :
        Retrieve a White List chunk using the 'start' parameter as the starting index and
        the 'filter' parameter as a RegExp pattern to filter the entries. If the 'start'
        parameter value exceeds the size of the White List, an empty array will be returned.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/sip_correlator_resources/{sip_id}/filter', args=args, response_type='none')

    def getSipAllowListHash(self, sip_id):
        """ getSipAllowListHash :
        Get the hash value for the SIP Correlator Allow List.
        Platforms:
            Vision One

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/sip_correlator_resources/{sip_id}/hash', args=None, response_type='json')

    def importSipAllowListEntries(self, sip_id, args):
        """ importSipAllowListEntries :
        Imports Allow List entries from CSV. Each one should be on a separate line.
        Platforms:
            Vision One

        Example:
        """

        file_name = args['file_name']
        f = {'file': (file_name, open(file_name ,'rb'), 'application/octet-stream')}
        return self._sendRequest(
            http_method='POST',
            url=f'/sip_correlator_resources/{sip_id}/importAllowList',
            args=args,
            file_info=f,
            response_type='none'
        )

    def importSipWhiteListEntries(self, sip_id, args):
        """ importSipWhiteListEntries :
        Imports White List entries from CSV. Each one should be on a separate line.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """

        file_name = args['file_name']
        f = {'file': (file_name, open(file_name ,'rb'), 'application/octet-stream')}
        return self._sendRequest(
            http_method='POST',
            url=f'/sip_correlator_resources/{sip_id}/importWhiteList',
            args=args,
            file_info=f,
            response_type='json'
        )

    def addSipWhiteListEntries(self, sip_id, args):
        """ addSipWhiteListEntries :
        Adds the entries sent in the 'whitelist' parameter as an array of Strings.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='POST', url=f'/sip_correlator_resources/{sip_id}/whiteList', args=args, response_type='bytes')

    def deleteSipWhiteListEntries(self, sip_id, args):
        """ deleteSipWhiteListEntries :
        Deletes the entries sent in the 'whitelist' parameter as an array of Strings.
        Platforms:
            UNMATCHED - likely deprecated

        Example:
        """
        return self._sendRequest(http_method='DELETE', url=f'/sip_correlator_resources/{sip_id}/whiteList', args=args, response_type='bytes')


    # /stats

    def getManagementStats(self):
        """ getManagementStats :
        Returns the statistics for active management port.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X
            400G

        Example:
        """
        return self._sendRequest(http_method='GET', url='/stats/mgmt_port', args=None, response_type='json')

    def resetDrops(self, args):
        """ resetDrops :
        Reset the overflow drop counts for a set of specific NTO tool ports and/or output port groups.
        Platforms:
            GSC 7400, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.resetDrops({'PORT': [58]})
        {u'reset_drops_attempt_count': 134, u'reset_drops_success_count': 118}
        """
        return self._sendRequest(http_method='POST', url='/stats/reset_drops', args=args, response_type='json')

    def resetStats(self, args):
        """ resetStats :
        Reset the stats for a set of specific NTO ports, port groups, and/or filters.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.resetStats({'PORT': [59], 'PORT_GROUP': [405]})
        {}
        """
        return self._sendRequest(http_method='POST', url='/stats/reset_stats', args=args, response_type='none')


    # /stats{id}

    def getStats(self, args, toolUid=None, streamName=None):
        """ getStats :
        Retrieve a stats snapshot containing the specified objects.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getStats({'stat_name': ['np_peak_gtp_v2_deleted_sessions_time', 'np_total_rx_count_valid_packets'], 'port_group': '91'})
        {u'stats_snapshot': [{u'np_peak_gtp_v2_deleted_sessions_time': 1441391232493, u'reset_by': u'null', u'reset_time': 1441390286194, u'default_name': u'PG1', u'stats_time': 1441391232493, u'np_total_rx_count_valid_packets': 0, u'type': u'Port Group', u'id': u'91'}]}
        """
        params = {}
        if toolUid is not None:
            params['toolUid'] = toolUid
        if streamName is not None:
            params['streamName'] = streamName
        return self._sendRequest(http_method='POST', url='/stats', args=args, params=params, response_type='json')


    # /system

    def modifySystem(self, args):
        """ modifySystem :
        Update the system properties.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.modifySystem({'system_info': {u'location': 'Austin', u'name': 'The Big Box'}})
        ''
        """
        return self._sendRequest(http_method='PUT', url='/system', args=args, response_type='none')

    def getSpecificSystem(self, system_id):
        """ getSpecificSystem :
        Retrieve the properties of the system specified.
        Platforms:
            NTO 5200

        Example:
        """
        return self._sendRequest(http_method='GET', url=f'/system/{system_id}', response_type='json')

    def modifySpecificSystem(self, system_id, args):
        """ modifySpecificSystem :
        Update the properties of the system specified.
        Platforms:
            NTO 5200

        Example:
        >>> nto.modifySystem({'system_info': {u'location': 'Austin', u'name': 'The Big Box'}})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/system/{system_id}', args=args, response_type='none')


    # /system{id}

    def getSystem(self, properties=None):
        """ getSystem :
        Retrieve the properties of the system.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getSystem()
        {u'mgmt_port2_link_status': {u'duplex': u'FULL', u'active_port': False, u'speed': u'1G', u'link_up': True}, u'union_mode': u'INDEPENDENT', u'timestamp_config': {u'time_source': u'LOCAL'}, u'fan_failure_count': 0, u'web_api_config': {u'enabled': True, u'port': 9000, u'token_timeout': {u'value': 10, u'unit': u'MIN'}}, u'session_timeout_interval': 0,
            <snip>
        """
        params = None
        if properties:
            params = {'properties': ''.join(properties.split())}

        return self._sendRequest(http_method='GET', url='/system', params=params, response_type='json')

    def getSystemProperties(self, properties):
        """ getSystemProperties :
        Fetch one or more systen properties.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getSystemProperties('snmp_config,dns_config')
        {u'dns_config': {u'suffix1': None, u'suffix2': None, u'primary_server': None, u'alt_server': None}, u'snmp_config': {u'trap_recipients': [{u'remote_user': None, u'traps': [u'COLD_START', u'WARM_START', u'LINK_UP_DOWN', u'TEST_NOTIFICATION'], u'retry_count': 1, u'host': {u'value': u'155.174.7.97'}, u'version': u'V2', u'community_string': u'V2/155.174.7.97:162', u'timeout': 5, u'port': 162}], u'refresh_time': 1, u'gets_enabled': True, u'traps_enabled': True, u'get_access': [{u'version': u'V2', u'community_string': u'AnueComm4ATSro', u'local_user': None}]}}
        """
        return self.getSystem(properties)

    def getSystemProperty(self, property):
        """ getSystemProperty :
        Fetch a systen property.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getSystemProperty('snmp_config')
        {u'trap_recipients': [{u'remote_user': None, u'traps': [u'COLD_START', u'WARM_START', u'LINK_UP_DOWN', u'TEST_NOTIFICATION'], u'retry_count': 1, u'host': {u'value': u'155.174.7.97'}, u'version': u'V2', u'community_string': u'V2/155.174.7.97:162', u'timeout': 5, u'port': 162}], u'refresh_time': 1, u'gets_enabled': True, u'traps_enabled': True, u'get_access': [{u'version': u'V2', u'community_string': u'AnueComm4ATSro', u'local_user': None}]}
        """
        return self.getSystem(property)[property]


    # /tool_connectors

    def getAllInlineToolConnectors(self):
        """ getAllInlineToolConnectors :
        Fetch a list containing the summaries for all the Inline Tool Connectors in the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getAllInlineToolConnectors()
        [{'id': 101, 'name': 'Test Tool Connector'}]
        """
        return self._sendRequest(http_method='GET', url='/tool_connectors', response_type='json')

    def createInlineToolConnector(self, args):
        """ createInlineToolConnector :
        Create a new Inline Tool Connector in the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.createInlineToolConnector({'assigned_status': 'ACTIVE', 'description': 'Tool Connector', 'name': 'Test Tool Connector', 'side_a_port': 17, 'side_b_port': 18, 'sync_current_status': True})
        {'default_name': 'ITC1', 'id': 104, 'name': 'Test Tool Connector'}
        """
        return self._sendRequest(http_method='POST', url='/tool_connectors', args=args, response_type='json')

    def searchInlineToolConnectors(self, args):
        """ searchnlineToolConnectors :
        Search for a specific Inline Tool Connector in the system by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.searchInlineToolConnectors({'assigned_status': 'ACTIVE'})
        [{'assigned_status': 'ACTIVE', 'created': {'caused_by': 'admin', 'details': None, 'time': 1605729055930, 'type': 'CREATE'}, 'current_status': 'ACTIVE', 'default_name': 'ITC1', 'description': 'Tool Connector', 'history': None, 'id': 101, 'mod_count': 0, 'name': 'Test Tool Connector', 'side_a_port': 10, 'side_a_port_group': None, 'side_b_port': 11, 'side_b_port_group': None, 'sync_current_status': True, 'tool_resource_list': []}]
        """
        return self._sendRequest(http_method='POST', url='/tool_connectors/search', args=args, response_type='json')

    def getInlineToolConnector(self, tool_conector_id, properties=None):
        """ getInlineToolConnector :
        Fetch the properties of an Inline Tool Connector.
        To request only select properties (partial response), append to the URL the query parameter
        '?properties=value', where value is comma-separated list to select multiple fields for example:
        /resource_type/{object-id}?properties=description,name.
        Query Parameter is optional, see section Partial get under Usage Examples.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getInlineToolConnector('101')
        {'assigned_status': 'ACTIVE', 'created': {'caused_by': 'admin', 'details': None, 'time': 1605729055930, 'type': 'CREATE'}, 'current_status': 'ACTIVE', 'default_name': 'ITC1', 'description': 'Tool Connector', 'history': None, 'id': 101, 'mod_count': 0, 'name': 'Test Tool Connector', 'side_a_port': 10, 'side_a_port_group': None, 'side_b_port': 11, 'side_b_port_group': None, 'sync_current_status': True, 'tool_resource_list': []}
        """
        params = None
        if properties is not None:
            params = {'properties': properties}
        return self._sendRequest(http_method='GET', url=f'/tool_connectors/{tool_conector_id}', params=params, response_type='json')

    def modifyInlineToolConnector(self, tool_conector_id, args):
        """ modifyInlineToolConnector :
        Update the properties of an existing Inline Tool Connector.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.modifyInlineToolConnector('101', {'description': 'new'})
        b''
        """
        return self._sendRequest(http_method='PUT', url=f'/tool_connectors/{tool_conector_id}', args=args, response_type='none')

    def deleteInlineToolConnector(self, tool_connector_id):
        """ deleteInlineToolConnector :
        Remove an existing inline Tool Connector from the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.deleteInlineToolConnector('101')
        b''
        """
        return self._sendRequest(http_method='DELETE', url=f'/tool_connectors/{tool_connector_id}', args=None, response_type='none')


    # /tool_resources

    def getAllInlineToolResources(self):
        """ getAllInlineToolResources :
        Fetch a list containing the summaries for all the inline tool resources in the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getAllInlineToolResources()
        [{'id': 109, 'name': 'test resource'}]
        """
        return self._sendRequest(http_method='GET', url='/tool_resources', response_type='json')

    def createInlineToolResource(self, args):
        """ createInlineToolResource :
        Create a new inline tool resource in the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.createInlineToolResource({"name": "test resource", "tool_connector_list": [{"assigned_status": "ACTIVE", "description": "test resource descr", "name": "test connector", "side_a_port": 10, "side_b_port": 11, "sync_current_status": True}]})
        {'default_name': 'ITR1', 'id': 109, 'name': 'test resource'}
        """
        return self._sendRequest(http_method='POST', url='/tool_resources', args=args, response_type='json')

    def getToolResourcesDetails(self, ids=None):
        """ getToolResourcesDetails :
        Fetch detailed properties for all or selected inline tool resources.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/tool_resources/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchInlineToolResources(self, args):
        """ searchInlineToolResources :
        Search for a specific inline tool resource in the system by certain properties.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.searchInlineToolResources({'heartbeat_id': None})
        [{'alert_type': 'NO_ALERT', 'created': {'caused_by': 'admin', 'details': None, 'time': 1605730117523, 'type': 'CREATE'}, 'default_name': 'ITR1', 'description': None, 'heartbeat_id': None, 'history': None, 'id': 109, 'ignore_mod_count': True, 'inline_service_chain_priority_list': [], 'is_mac_reversed_rhb': False, 'misc': {'access_map': {'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'10': 'Allow All', '11': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P08, P09: Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS']}, 'mod_count': 0, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'test resource', 'negative_heartbeat_id': None, 'state': 'ACTIVE', 'tool_connector_list': [{'assigned_status': 'ACTIVE', 'connector_type': 'TOOL_CONNECTOR', 'current_status': 'ACTIVE', 'name': 'test connector', 'side_a_port': '10', 'side_b_port': '11', 'sync_current_status': True}]}]
        """
        return self._sendRequest(http_method='POST', url='/tool_resources/search', args=args, response_type='json')

    def getInlineToolResource(self, tool_resource_id):
        """ getInlineToolConnector :
        Fetch the properties of a inline tool resource object.
        To request only select properties (partial response), append to the URL the query
        parameter '?properties=value', where value is comma-separated list to select multiple
        fields for example:
        /resource_type/{object-id}?properties=description,name.
        Query Parameter is optional, see section Partial get under Usage Examples.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.getInlineToolResource('109')
        {'alert_type': 'NO_ALERT', 'created': {'caused_by': 'admin', 'details': None, 'time': 1605730117523, 'type': 'CREATE'}, 'default_name': 'ITR1', 'description': None, 'heartbeat_id': None, 'history': None, 'id': 109, 'ignore_mod_count': True, 'inline_service_chain_priority_list': [], 'is_mac_reversed_rhb': False, 'misc': {'access_map': {'MODIFY_ACCESS_SETTINGS': {'access_settings': {'groups': [], 'policy': 'INHERITED'}, 'affecting_ports': {'10': 'Allow All', '11': 'Allow All'}, 'affecting_resource': {}, 'current_value': 'All users. Derived from *P08, P09: Allow All', 'expression_text': 'All users.', 'operation_name': 'Modify', 'operation_phrase': 'modify', 'tooltip': 'Inherit from Ports', 'user_names': '', 'users_statement': 'Anyone can perform'}}, 'access_props': ['MODIFY_ACCESS_SETTINGS']}, 'mod_count': 0, 'modify_access_settings': {'groups': [], 'policy': 'INHERITED'}, 'name': 'test resource', 'negative_heartbeat_id': None, 'state': 'ACTIVE', 'tool_connector_list': [{'assigned_status': 'ACTIVE', 'connector_type': 'TOOL_CONNECTOR', 'current_status': 'ACTIVE', 'name': 'test connector', 'side_a_port': '10', 'side_b_port': '11', 'sync_current_status': True}]}
        """
        return self._sendRequest(http_method='GET', url=f'/tool_resources/{tool_resource_id}', response_type='json')

    def modifyInlineToolResource(self, tool_resource_id, args):
        """ modifyInlineToolResource :
        Update the properties of an existing inline tool resource.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.modifyInlineToolResource('109', {'name': 'New Name'})
        b''
        """
        return self._sendRequest(http_method='PUT', url=f'/tool_resources/{tool_resource_id}', args=args, response_type='none')

    def deleteInlineToolResource(self, tool_resource_id):
        """ deleteInlineToolConnector :
        Remove an existing inline tool resource from the system.
        Platforms:
            7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S,
            Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50,
            Vision Edge OS 9516, Vision One, Vision X, Vision X 400G

        Example:
        >>> nto.deleteInlineToolResource('New Name')
        b''
        """
        return self._sendRequest(http_method='DELETE', url=f'/tool_resources/{tool_resource_id}', args=None, response_type='none')


    # /users

    def getAllUsers(self):
        """ getAllUsers :
        Fetch a list containing the summaries for all the users in the system, or
        if a user ID is specified, fetch the properties of that user object.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getAllUsers()
        [{u'id': 56, u'name': u'admin'}, {u'id': 52, u'name': u'tcl'}]
        """
        return self._sendRequest(http_method='GET', url='/users', response_type='json')

    def createUser(self, args):
        """ createUser :
        Create a new user.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.createUser({'login_id': 'oper', 'is_sysadm': False, 'password': 'oper'})
        {u'id': u'54'}
        """
        return self._sendRequest(http_method='POST', url='/users', args=args, response_type='json')

    def getUsersDetails(self, ids=None):
        """ getUsersDetails :
        Fetch detailed properties for all or selected users.
        Platforms:
            TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision
            Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge
            OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision X 400G

        """
        return self._sendRequest(http_method='POST', url='/users/detail', args=None, params=self._buildIdsParams(ids), response_type='json')

    def searchUsers(self, args):
        """ searchUsers :
        Search a specific user from the system by certain properties.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.searchUsers({'is_sysadm': False})
        [{u'id': 54, u'name': u'oper'}]
        """
        return self._sendRequest(http_method='POST', url='/users/search', args=args, response_type='json')

    def getUser(self, user):
        """ getUser :
        Fetch a list containing the summaries for all the users in the system, or
        if a user ID is specified, fetch the properties of that user object.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.getUser('tcl')
        {u'login_id': u'tcl', u'session_type': None, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1442436968401}, u'is_sysadm': True, u'phone': u'867-53009', u'email': u'tcl@nto.com', u'mod_count': 0, u'is_logged_in': False, u'full_name': u'tcl', u'authentication_mode': u'LOCAL', u'id': 52, u'history': []}
        """
        return self._sendRequest(http_method='GET', url=f'/users/{user}', response_type='json')

    def changePasswordUserByVersion(self, user_id, old_password, new_password):
        """ changePasswordUserByVersion :
        Change the user password.
        Platforms:
            GSC 7400, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.changePasswordUserByVersion('tcl1', 'tcl1', 'fredMota@123')
        ''
        """
        self._set_sw_version()

        if self.sw_major_version < 4 or (self.sw_major_version == 4 and self.sw_minor_version < 5):
            args = {'password': new_password}
            return self._sendRequest(http_method='PUT', url=f'/users/{user_id}', args=args, response_type='none')
        else:
            args = {'new_password' : new_password, 'old_password' : old_password}
            return self._sendRequest(http_method='PUT', url=f'/users/{user_id}/change_password', args=args, response_type='none')

    def modifyUser(self, user_id, args):
        """ modifyUser :
        Update the properties of an existing user.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.modifyUser('oper', {'password': '***'})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/users/{user_id}', args=args, response_type='none')

    def deleteUser(self, user_id):
        """ deleteUser :
        Remove a user from the system. The user is specified by an user_id.
        Platforms:
            GSC 7400, NTO 5200, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge
            100, Vision Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40,
            Vision Edge 50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One,
            Vision X, Vision X 400G

        Example:
        >>> nto.deleteUser('54')
        ''
        """
        return self._sendRequest(http_method='DELETE', url=f'/users/{user_id}', args=None, response_type='none')

    def changePasswordUser(self, user_id, args):
        """ changePasswordUser :
        Change the user password.
        Platforms:
            GSC 7400, 7300/7303, TradeVision, Vision 400, Vision 400XT, Vision 7816, Vision Edge 100, Vision
            Edge 10S, Vision Edge 400P, Vision Edge 400P Rev2, Vision Edge 400S, Vision Edge 40, Vision Edge
            50, Vision Edge OS 9516, Vision Edge OS 5812, Vision Edge OS 7712, Vision One, Vision X, Vision
            X 400G

        Example:
        >>> nto.changePasswordUser('tcl1', {'new_password' : 'tcl1', 'old_password' : 'fredMota@123'})
        ''
        """
        return self._sendRequest(http_method='PUT', url=f'/users/{user_id}/change_password', args=args, response_type='none')


    # /{id}

    def search(self, entity_type, args):
        """ search :
        Search an entity.
        Platforms:
            GSC 7400, 7300/7303, Vision 400, Vision 7816, Vision Edge 100, Vision Edge 10S, Vision Edge
            400P, Vision Edge 400S, Vision Edge 40, Vision Edge 50, Vision Edge OS 9516, Vision Edge OS
            5812, Vision Edge OS 7712, Vision One, Vision X

        Example:
        >>> nto.search('port_groups', {'mode': 'NETWORK'})
        [{u'id': 94, u'name': u'GSC Network Ports PB09-PB16'}, {u'id': 92, u'name': u'GSC Network Ports PB01-PB08'}, {u'id': 91, u'name': u'GSC Network Ports PA01-PA08'}, {u'id': 95, u'name': u'GSC Network Ports PA09-PA16'}]
        """
        return self._sendRequest(http_method='POST', url=f'/{entity_type}/search', args=args, response_type='json')
