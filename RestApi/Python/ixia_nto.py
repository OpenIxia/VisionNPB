#################################################################################
##
## File:   ixia_nto.py
## Date:   August 5, 2014
## Author: Fred Mota (fmota@ixiacom.com)
##
## Description:
## The intent of this file is to provide a Python package that will facilitate
## the access to Ixia NTO devices using the new RESTful Web API interface.
##
## This library can be used to manage both, the NTO, and the GSC.
##
## (c) 1998-2016 Ixia. All rights reserved.
##
## References:
##   - Using certificates in urllib3
##     http://stackoverflow.com/questions/23954120/using-certificates-in-urllib3
##
################################################################################

import urllib3
import base64
import json
import time
import os
import sys

class NtoApiClient(object):

    def __init__(self, host, username, password, port=8000, debug=False, logFile=None):
        #urllib3.disable_warnings()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.host = host
        self.port = port
        self.user = username
        self.password = password
        self.debug = debug
        self.auth_b64 = ''
        self.password_headers = ''
        self.token_headers = ''
        self.connection = ''
        self.logFile = logFile

        self.auth_b64 = base64.b64encode(bytearray(username + ":" + password, 'ascii')).decode('ascii')
        self.password_headers = { 'Authorization' : 'Basic ' + self.auth_b64, 'Content-type' : 'application/json' }

        #self.connection = urllib3.connectionpool.HTTPSConnectionPool(host, port=port, ssl_version='TLSv1_2')
        self.connection = urllib3.connectionpool.HTTPSConnectionPool(host, port=port, cert_reqs='CERT_NONE', ca_certs=None, timeout=240, retries=2)
        response = self.connection.urlopen('GET', '/api/auth', headers=self.password_headers)
    
        if debug:
            self._log ("Status=%s"  % response.status)
            self._log ("Reason=%s"  % response.reason)
            self._log ("Headers=%s" % response.headers)
            self._log ("Data=%s"    % response.data)

        self.token = response.headers['x-auth-token']
        self.token_headers = { 'Authentication' : self.token, 'Content-type' : 'application/json' }


    def __str__(self):
        return ("NtoApiClient('host=%s', 'port=%s', 'user=%s', 'password=%s', 'auth=%s', 'debug=%s', 'password_hdrs=%s', 'token_hdrs=%s', 'connection=%s'") % (self.host, self.port,  self.user, self.password, self.auth_b64, self.debug, self.password_headers, self.token_headers, self.connection)

    def __repr__(self):
        return ("NtoApiClient('host=%s', 'port=%s', 'user=%s', 'password=%s', 'auth=%s', 'debug=%s', 'password_hdrs=%s', 'token_hdrs=%s', 'connection=%s'") % (self.host, self.port,  self.user, self.password, self.auth_b64, self.debug, self.password_headers, self.token_headers, self.connection)

    def _log(self, message):
        handle = open(self.logFile, 'a') if self.logFile else sys.stdout
        handle.write(message)
        if handle is not sys.stdout:
            handle.close()

    def _callServer(self, HTTPMethod, URL, argsAPI=None, decode=True):
        """ Call server method HTTPMethod with error handling
            and returns the response. """

        response = None
        if self.debug:
            self._log ("Sending a message to the server with parameters:\n")
            self._log (" HTTPMethod=%s\n" % HTTPMethod)
            self._log (" URL=%s\n"        % URL)
            self._log (" argsAPI=%s\n"    % argsAPI)

        argsAPI = json.dumps(argsAPI)
        response = self.connection.urlopen(HTTPMethod, URL, body=argsAPI, headers=self.token_headers)

        if self.debug:
            self._log ("Response:\n")
            self._log (" Status=%s\n"  % response.status)
            self._log (" Reason=%s\n"  % response.reason)
            self._log (" Headers=%s\n" % response.headers)
            self._log (" Data=%s\n"    % response.data)
            self._log (" decode=%s\n"  % decode)

        data = response.data
        if decode:
            data = json.loads(data.decode('ascii'))

        return data


    def setDebug(self, debug=False):
        """ Turn on/off debug messages """
        self.debug = debug

    ###################################################
    # Actions
    ###################################################
    def authenticate(self):
        """ authenticate :
        Athenticate with the NTO using username and password.
        
        Sample usage:
        >>> nto.authenticate()
        """
        response = self.connection.urlopen('GET', '/api/auth', headers=self.password_headers)

        if self.debug:
            self._log ("Status=%s"  % response.status)
            self._log ("Reason=%s"  % response.reason)
            self._log ("Headers=%s" % response.headers)
            self._log ("Data=%s"    % response.data)

        self.token_headers = { 'Authentication' : response.headers['x-auth-token'], 'Content-type' : 'application/json' }

    def addAggregationSwitch(self):
        """ addAggregationSwitch :
        Adds a new Aggregation Switch to a Switch Cluster.
        
        Sample usage:
        """
        return self._callServer('POST', '/api/actions/add_aggregation_switch', None)
            
    def certificateManagement(self, argsAPI):
        """ certificateManagement :
        Allows Syslog and TLS/HTTPS certificates to be uploaded and deleted. Basic
        information can also be viewed for certificates installed on the system.
        
        Sample usage:
        >>> nto.certificateManagement({'action': 'VIEW', 'certificate_use': 'DEFAULT_TLS_HTTPS'})
        {u'authentication': [{u'valid_from': u'May 28, 2015 10:06:25 AM GMT', u'sha1_fingerprint': u'D3:75:74:30:D7:D8:50:FE:73:2F:10:E3:62:59:1B:EF:83:24:44:58', u'signature_algorithm': u'SHA256WITHRSA', u'valid_to': u'May 25, 2025 10:06:25 AM GMT', u'version': u'3', u'signature': u'12:B5:F1:75:7B:26:86:B2:C7:CE:A8:CE:74:CC:E8:82:8A:A3:45:45:AB:D3:DF:35:96:6A:50:61:F7:70:32:51:0A:03:5E:D1:14:1E:19:8E:ED:1A:E0:71:6E:CD:79:3C:67:70:F1:66:73:6C:1E:4F:97:97:94:79:25:D9:16:9C:B5:C7:E1:84:2A:A4:D6:FE:74:E7:E1:B5:B7:E0:32:0F:12:EA:A0:9C:62:75:D8:70:63:1B:C2:04:67:B9:33:5B:FE:9F:73:20:8B:AF:92:EA:6E:1A:61:B7:79:2A:AF:9E:50:EF:7D:7D:CE:DD:55:BD:20:E3:D7:C3:49:EB:A1:7D:B7:C8:89:43:19:13:59:4D:B6:2F:B9:22:8C:06:5C:4D:BB:8C:03:5B:45:B2:6D:DC:B5:4A:80:9A:14:32:2B:44:9D:CF:83:D8:E8:81:B8:77:94:2D:71:D0:54:ED:47:53:45:06:28:39:86:7D:EF:9D:3D:DC:BD:06:E0:BC:EF:62:AA:85:02:20:D7:E6:61:4E:12:81:04:9E:42:AA:40:18:4F:1B:3D:41:62:9B:E4:36:A9:F8:39:5F:60:2B:C1:83:5D:CF:FE:9F:3B:C0:FD:62:A7:D6:47:9E:C4:73:02:CA:C6:86:F5:7B:52:5B:E8:58:3B:23:57:3F:EE:2C:09:E2', u'serial_number': u'1165506059 (4578360b)', u'md5_fingerprint': u'57:7E:03:2E:2B:67:AA:E7:75:44:AA:21:5C:8F:BE:A1', u'subject': u'CN=Ixia, OU=Ixia, O=Ixia, L=Calabasas, ST=California, C=US', u'issuer': u'CN=Ixia, OU=Ixia, O=Ixia, L=Calabasas, ST=California, C=US'}]}
        """
        return self._callServer('POST', '/api/actions/certificates', argsAPI)

    def changeRole(self):
        """ changeRole :
        This command changes role between supervisor and independent.
        
        Sample usage:
        >>> nto.changeRole()
        """
        argsAPI = {}
        return self._callServer('POST', '/api/actions/change_role', argsAPI)

    def changePortSpeed(self, argsAPI):
        """ changePortSpeed :
        Changes the speed configuration of port.

        Sample usage:
        >>> nto.changePortSpeed({'port_list': [64], 'qsfp28_port_mode': 'MODE_QSFP'})
        '{}'
        """
        return self._callServer('POST', '/api/actions/change_speed_configuration', argsAPI, False)

    def clearAggregationSwitch(self):
        """ clearAggregationSwitch :
        Clears the configuration of an aggregation switch.
        
        Sample usage:
        """
        return self._callServer('POST', '/api/actions/clear_aggregation_switch', None)

    def changeQsfp28PortMode(self, argsAPI):
        """ changeQsfp28PortMode :
        Changes the QSFP mode of a QSFP28 port.
            
        Sample usage:
        """
        return self._callServer('POST', '/api/actions/change_qsfp28_port_mode', argsAPI, False)

    def changePortAggregationMode(self, argsAPI):
        """ changePortAggregationMode :
        Agregates four 10G ports into one 40G port and backward.
        
        Sample usage:
        """
        return self._callServer('POST', '/api/actions/change_port_aggregation_mode', argsAPI, False)

    def clearConfig(self):
        """ clearConfig :
        Clear the configuration by deleting all filters, regular users, groups,
        filter templates, filter template collections, port groups, and custom
        icons and by setting all ports to default values.

        Sample usage:
        >>> nto.clearConfig()
        {u'message': u'Configuration cleared.'}
        """
        argsAPI = {}
        return self._callServer('POST', '/api/actions/clear_config', argsAPI)
    
    def clearFiltersAndPorts(self):
        """ clearFiltersAndPorts :
        This command deletes all filters and port groups and sets all ports to
        default values.

        Sample usage:
        >>> nto.clearFiltersAndPorts()
        {u'message': u'Filters and ports cleared.'}
        """
        argsAPI = {}
        return self._callServer('POST', '/api/actions/clear_filters_and_ports', argsAPI)
    
    def clearSystem(self):
        """ clearSystem :
        This command clears the system and restores it to a default state, including
        resetting the admin account to default values. The license currently
        installed will not be removed.
        
        Sample usage:
        >>> nto.clearSystem()
        {u'message': u'System restored to default state.'}
        """
        argsAPI = {}
        return self._callServer('POST', '/api/actions/clear_system', argsAPI)

    def enableFipsServerEncryption(self):
        """ enableFipsServerEncryption :
        This commands causes FIPS encryption to be enabled on the server.
        
        Sample usage:
        *** TO BE TESTED ***
        >>> nto.enableFipsServerEncryption()
        """
        argsAPI = {}
        return self._callServer('POST', '/api/actions/enable_fips_server_encryption', argsAPI)

    def exportConfig(self, argsAPI):
        """ exportConfig :
        Return configuration settings from an NTO to a file.

        Sample usage:
        nto.exportConfig({'boundary' : 'INCLUDE', 'description' : 'SNMP Config', 'export_type' : 'CUSTOM', 'file_name' : '/Users/fmota/Desktop/snmp+user.ata', 'user': None, 'system' : 'snmp_config'})
        """
        file_name = ''
        if 'file_name' in argsAPI:
            file_name = argsAPI['file_name']

        file = self._callServer('POST', '/api/actions/export', argsAPI, False)
        f = open(file_name, 'wb')
        f.write(file)
        f.close()

    def exportKeyGenLicense(self, argsAPI):
        """ exportKeyGenLicense :
        Export the KeyGen license details to a json file that can be used
        on the migration portal to obtain a new style license for an NTO
        or an union.
        
        Sample usage:
        >>> nto.exportKeyGenLicense({'file_name': 'mylicense'})
        """

        file_name = ''
        if 'file_name' in argsAPI:
            file_name = argsAPI['file_name']

        file = self._callServer('POST', '/api/actions/export_keygen_license_to_json', argsAPI, False)
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
        argsAPI = {}
        return self._callServer('POST', '/api/actions/fips_server_encryption_status', argsAPI)

    def factoryReset(self):
        """ factoryReset :
        This command clears the system and restores it to a factory default
        state, including resetting the admin account to default values. The
        license currently installed will also be removed.
        
        Sample usage:
        >>> nto.factoryReset()
        """
        argsAPI = {}
        return self._callServer('POST', '/api/actions/factory_reset', argsAPI)

    def generateCsr(self, argsAPI):
        """ generateCsr :
        Allows Syslog and TLS/HTTPS certificates to be uploaded and deleted. Basic
        information can also be viewed for certificates installed on the system.
        
        Sample usage:
        >>> nto.generateCsr({'csr_use' : 'SYSLOG', 'tls_cert_request_info' : {'city' : 'Austin', 'common_name' : 'Test API', 'country' : 'US', 'organization' : 'Ixia', 'organization_unit' : 'NVS', 'state' : 'TX', 'subject_alt_name' : 'Anue'}})
        {u'csr': u'-----BEGIN CERTIFICATE REQUEST-----MIIC5zCCAc8CAQAwWzELMAkGA1UECBMCVFgxDzANBgNVBAcTBkF1c3RpbjELMAkGA1UEBhMCVVMxDDAKBgNVBAsTA05WUzENMAsGA1UEChMESXhpYTERMA8GA1UEAxMIVGVzdCBBUEkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4RNOnSPTRamGkAwj/otEgzAFYIEXlpsO4OS16P49l3c0n5ShDs0uo2pd4a0Qe4Wvh/KX4L1oZbxS/2YNJgNlLiRkHo5K62ZYYskfNGXPBYfkkRDLk76SrhgHyoGSEy8h6OdeE2QpfgsD/XLQVoFQ3dVemSwo76bE3Vap333fJmvtNJNgItkKqKBW3zF1doSWJwEHDwwhG9/KSfFBHf/qE51LRj2iybZQE4ijZGHv0I7CtSF20166sH75EhsoK8/vs1RT6LpyuEM9JKoRzmvE1ufk3nHtlvF3UniUluUCubXfldaEROIeBvYfoWZGGuyzAN01ZbxZ+/K2ENokpVKPbAgMBAAGgRzBFBgkqhkiG9w0BCQ4xODA2MA8GA1UdEQQIMAaCBEFudWUwDgYDVR0PAQH/BAQDAgUgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQAfVnwTv1t56YWU2W5+Fjlc9nuTL7eAoKqkioTJ1CuAINLybbHYUVXVfpBahfjj7g6ZmiWZ383SK7ImuPfHE7kt/eRDna+/+HUQ22799HQmyLcxCkYZVSH8gWkTNbUIhgh4AFMwt83zWu324P+qNkh5u0sckPTfNzry3Mxz2QzmM5sP+oU8/RCt04iYzz5KSu+tzHWJ9FOGLQqQ73Ausz0smTDFBlVLs8VCifHVc2QmSbIofHVPUOUEjWo+FFb6WK6/7NjgE4DM9rVDV7eW9WXZgos6WnXRVMIpedeibh31iM/sc63F0tQHXt696kfO19LBc6FLMKLCvVtkGfSnq5u9-----END CERTIFICATE REQUEST-----'}
        """
        return self._callServer('POST', '/api/actions/generate_csr', argsAPI)

    def getAvailableFilterCriteria(self, argsAPI):
        """ getAvailableFilterCriteria :
        Return a list of filter criteria which can be used given an already
        present set of filter criteria.
            
        Sample usage:
        >>> nto.getAvailableFilterCriteria({'filter_object_type': 'FILTER'})
        []
        """
        return self._callServer('POST', '/api/actions/get_available_filter_criteria', argsAPI)

    def getLoginInfo(self):
        """ getLoginInfo :
        Return info helpful for login.

        Sample usage:
        """
        return self._callServer('POST', '/api/actions/get_login_info', None)

    def getFabricPorts(self, argsAPI):
        """ getFabricPorts :
        Return fabric ports information for one or more members. This
        information can be used as input to the update_fabric_ports action.
        
        Sample usage:
        >>> nto.getFabricPorts()
        """
        return self._callServer('POST', '/api/actions/get_fabric_ports', argsAPI)

    def getMemoryMeters(self):
        """ getMemoryMeters :
        Return the filter memory meters showing memory allocation and percentage used.
        
        Sample usage:
        >>> nto.getMemoryMeters()
        [{u'unit_name': u'LC1', u'memory_meters': [{u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 89, u'avail_pcnt': 100, u'meter_name': u'FILTER_ETHERTYPE_VLAN_L3_L4'}, {u'alloc_pcnt': 89, u'avail_pcnt': 100, u'meter_name': u'FILTER_L2_L3_L4'}], u'memory_type': u'DYNAMIC_FILTER_NON_IP'}, {u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 50, u'avail_pcnt': 100, u'meter_name': u'DYNAMIC_SIP_IPV4'}, {u'alloc_pcnt': 50, u'avail_pcnt': 100, u'meter_name': u'DYNAMIC_DIP'}], u'memory_type': u'DYNAMIC_FILTER_IP'}, {u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 100, u'avail_pcnt': 100, u'meter_name': u'NETWORK_PORT_L2_L3_IPV4'}], u'memory_type': u'NETWORK_PORT_FILTER'}, {u'custom_memory_slice_count': 0, u'meters': [{u'alloc_pcnt': 100, u'avail_pcnt': 100, u'meter_name': u'TOOL_PORT_L2_L3_IPV4'}], u'memory_type': u'TOOL_PORT_FILTER'}]}, ...
        """
        argsAPI = {}
        return self._callServer('POST', '/api/actions/get_memory_meters', argsAPI)
        
    def getTranceiverInfo(self):
        """ getTranceiverInfo :
        Return the tranceivor information.
            
        Sample usage:
        >>> nto.getTranceiverInfo()
        [{u'line_card_number': 1, u'line_card_tranceiver_info': u"<h1>Demo sample</h1><br/><br/><br/><table border='2'><tr><td bgcolor='#6495ED'><font size='+1' color='black'><b>Port: P1-01 (demo)</b></font><br/><br/><table border='1'><tr><th bgcolor='silver'>Hardware Info</th><th bgcolor='silver'>Vendor Name</th><th bgcolor='silver'>OUI</th><th bgcolor='silver'>Part Number</th><th bgcolor='silver'>Revision</th><th bgcolor='silver'>Serial Number</th><th bgcolor='silver'>Date Code</th><th bgcolor='silver'>Lot Code</th></tr><tr><th bgcolor='white'>SFP</th><th bgcolor='white'>ANUE SYSTEMS</th><th bgcolor='white'>009065</th><th bgcolor='white'>200-06-0003</th><th bgcolor=
        """
        argsAPI = {}
        return self._callServer('POST', '/api/actions/get_tranceiver_info', argsAPI)
    
    def getObjectType(self, argsAPI):
        """ getObjectType :
        Return the object type for an internal id.

        Sample usage:
        >>> nto.getObjectType({'id':238})
        {u'object_type': u'PORT'}
        """
        return self._callServer('POST', '/api/actions/get_object_type', argsAPI)

    def getProperties(self, argsAPI):
        """ getProperties :
        Return a list of the properties that are available for a particular type of object.

        Sample usage:
        >>> nto.getProperties({'object_type' : 'monitor'})
        {u'properties': [u'actions', u'created', u'description', u'history', u'id', u'mod_count', u'name', u'trigger']}
        """
        return self._callServer('POST', '/api/actions/get_props', argsAPI)

    def getPropertyValues(self, argsAPI):
        """ getPropertyValues :
        Return a list of the properties that are available for a particular type of object.

        Sample usage:
        >>> nto.getPropertyValues({'object_type': 'port', 'prop_name': 'force_link_up'})
        {u'value': [u'DISABLED', u'ENABLED', u'MIXED', u'NOT_SUPPORTED']}
        """
        return self._callServer('POST', '/api/actions/get_values', argsAPI)

    def importConfig(self, argsAPI):
        """ import_cfg :
        Copy configuration settings from a file to an NTO.

        Sample usage:
        >>> nto.importConfig({'boundary': 'INCLUDE', 'import_type': 'CUSTOM', 'file_name': '/Users/fmota/Desktop/snmp+user.ata', 'system' : 'snmp_config'})
        '{"message": "Configuration imported from /Users/fmota/Desktop/snmp+user.ata."}'
        """

        file_name = ''
        if 'file_name' in argsAPI:
            file_name = argsAPI['file_name']
            del argsAPI['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        buffer = bytearray()

        # Set param
        buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
        buffer.extend(b'Content-Disposition: form-data; name="param"\r\n')
        buffer.extend(b'Content-Type: application/json\r\n')
        buffer.extend(b'\r\n')
        buffer.extend(bytearray(json.dumps(argsAPI), 'ascii'))
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

    def installLicense(self, argsAPI):
        """ installLicense :
        This command installs a license file on a NTO, a union, or a member.
        
        Sample usage:
        >>> nto.installLicense({'file_name': '/Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt'})
        '{"message": "License installed from /Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt."}'
        """
            
        file_name = ''
        if 'file_name' in argsAPI:
            file_name = argsAPI['file_name']
            del argsAPI['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())

        buffer = bytearray()

        # Set param
        if len(argsAPI.keys()) > 0:
            buffer.extend(b'--' + bytearray(boundary, 'ascii') + b'\r\n')
            buffer.extend(b'Content-Disposition: form-data; name="param"\r\n')
            buffer.extend(b'Content-Type: application/json\r\n')
            buffer.extend(b'\r\n')
            #buffer.extend(json.dumps({'action_target' : target}))
            buffer.extend(json.dumps(argsAPI))
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

    def installLicense_old(self, argsAPI):
        """ installLicense :
        This command installs a license file on a NTO, a union, or a member.

        Sample usage:
        >>> nto.installLicense({'file_name': '/Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt'})
        '{"message": "License installed from /Users/fmota/Desktop/IxiaLicenseA_17_Fred_20150826_1.txt."}'
        """

        file_name = ''
        if 'file_name' in argsAPI:
            file_name = argsAPI['file_name']
            del argsAPI['file_name']

        boundary = "-----WebKitFormBoundary" + str(int(time.time())) + str(os.getpid())
        
        parts = []
        
        # Set param
        if len(argsAPI.keys()) > 0:
            parts.append('--' + boundary)
            parts.append('Content-Disposition: form-data; name="param"')
            parts.append('Content-Type: application/json')
            parts.append('')
            #parts.append(json.dumps({'action_target' : target}))
            parts.append(json.dumps(argsAPI))

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

    def installSoftware(self, argsAPI):
        """ installSoftware :
        This command installs a software upgrade file on an NTO. When installing
        software on a supervisor in a union, all members in the union will be
        upgraded to the same software level automatically.
        
        Sample usage:
        >>> nto.installSoftware({'file_name': '/Users/fmota/Desktop/NVOS-4.3.1.1-52xx-141844-20150722-174244.zip'})
        '{"message": "Software installation complete. The system will be restarted. Visit the 5288 launch page in your browser to obtain the updated client software."}'
        """

        file_name = ''
        if 'file_name' in argsAPI:
            file_name = argsAPI['file_name']

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
                                                                                        
    def powerDown(self, argsAPI={}):
        """ powerDown :
        This command safely shuts down an NTO, a union or a member.

        Sample usage:
        >>> nto.powerDown()
        {u'message': u'System shutdown requested.'}

        """
        return self._callServer('POST', '/api/actions/power_down', argsAPI)

    def pullConfigFromHaPeer(self):
        """ pullConfigFromHaPeer :
        Pulls the configuration from the HA peer machine.

        Sample usage:
        *** TO BE TESTED ***
        >>> nto.pullConfigFromHaPeer()
        """
        argsAPI={}
        return self._callServer('POST', '/api/actions/pull_config_from_ha_peer', argsAPI)

    def pushConfigToHaPeer(self):
        """ pushConfigToHaPeer :
        Pushes the local configuration to the HA peer machine.

        Sample usage:
        *** TO BE TESTED ***
        >>> nto.pushConfigToHaPeer()
        """
        argsAPI={}
        return self._callServer('POST', '/api/actions/push_config_to_ha_peer', argsAPI)

    def removeLicense(self):
        """ removeLicense :
        This command will remove the license and power down the NTO.
        
        Sample usage:
        >>> nto.removeLicense()
        """
        argsAPI={}
        return self._callServer('POST', '/api/actions/remove_license', argsAPI)

    def removeLineCard(self, argsAPI):
        """ removeLineCard :
        This command will remove the line card based on the given line card id.

        Sample usage:
        >>> nto.removeLineCard({'line_card_id': 1})
        {u'message': u'System restart requested.'}
        """
        return self._callServer('POST', '/api/actions/remove_line_card', argsAPI)
    
    def restart(self, argsAPI={}):
        """ restart :
        This command safely restarts an NTO, a union, or a member.

        Sample usage:
        >>> nto.restart()
        {u'message': u'System restart requested.'}
        """
        return self._callServer('POST', '/api/actions/restart', argsAPI)

    def revertSoftware(self):
        """ revertSoftware :
        This command revert software to it's previous version.
        
        Sample usage:
        >>> nto.revertSoftware()
        {u'message': u'Software revert requested. The system will be restarted. Visit the 7300 launch page in your browser to obtain the reverted client software.'}
        """
        argsAPI={}
        return self._callServer('POST', '/api/actions/revert_software', argsAPI)
        
    def saveLogs(self, argsAPI):
        """ saveLogs :
        Save the current system log files for subsequent delivery to Anue Support.

        Sample usage:
        >>> nto.saveLogs({'file_name': '/Users/fmota/Desktop/NTO-log.zip'})
        """

        file_name = ''
        if 'file_name' in argsAPI:
            file_name = argsAPI['file_name']
        
        file = self._callServer('POST', '/api/actions/save_logs', argsAPI, False)
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
        argsAPI={}
        return self._callServer('POST', '/api/actions/set_ha_sync_port', argsAPI)

    def setIpConfig(self, argsAPI):
        """ setIpConfig :
        Changes the IP configuration of a system.

        Sample usage:
        >>> nto.setIPConfig({'ipv4_address': '192.168.2.149', 'ipv4_enabled': True, 'ipv4_gateway': '192.168.2.2', 'ipv4_netmask': '255.255.255.0', 'ipv6_address': 'fe80::5daa:83ed:42f8:6c08%11', 'ipv6_enabled': False, 'ipv6_prefix_length': 64})
        {u'message': u'The new IP configuration has been submitted.'}
        """
        return self._callServer('POST', '/api/actions/set_ip_config', argsAPI)

    def swapPortLicenses(self, argsAPI):
        """ swapPortLicenses :
        Swaps port licenses.
        
        Sample usage:
        """
        return self._callServer('POST', '/api/actions/swap_port_licenses', argsAPI, False)

    def modifyFabricPorts(self, argsAPI):
        """ modifyFabricPorts :
        Changes the fabric ports configuration for the specified member switch.
        
        Sample usage:
        """
        return self._callServer('POST', '/api/actions/update_fabric_ports', argsAPI)
        
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
        return self._callServer('GET', '/api/capture_resources')
    
    def getCapture(self, resource):
        """ getCapture :
        Fetch the properties of a capture object.

        Sample usage:
        >>> nto.getCapture('177')
        {u'trailer_stripping_mode': u'USE_LOCAL_TIME', u'capture_count_unit': u'PACKETS', u'id': 177, u'has_dropped_packets': False, u'max_buffer_capacity': 14680063, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'connect_disconnect_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'status': u'IDLE_WITH_DATA', u'fill_to_trigger_position': False, u'description': None, u'trigger_position': 25, u'resource_status': u'READY', u'license_status': u'NOT_PRESENT', u'trailer_stripping_enabled': False, u'buffer_size': 200, u'trigger_criteria': {u'logical_operation': u'AND'}, u'name': u'L1-CAP', u'buffer_type': u'LINEAR', u'capture_source': 307, u'lineboard_id': 175, u'default_name': u'L1-CAP', u'trigger_mode': u'MANUAL', u'mod_count': 3, u'history': [{u'type': u'MODIFY', u'time': 1442009546427, u'caused_by': u'admin', u'details': None, u'props': [u'CAPTURE_SOURCE', u'BUFFER_SIZE']}]}
        """
        return self._callServer('GET', '/api/capture_resources/' + resource)

    def deleteCaptureFile(self, resource, argsAPI):
        """ deleteCaptureFile :
        Deletes a capture file from a capture resource.

        Sample usage:
        >>> nto.deleteFileCapture('546', {'file_name': 'File 1.pcap'})
        ''
        """
        return self._callServer('DELETE', '/api/capture_resources/' + resource + '/delete_file ', argsAPI, False)

    def disableCapture(self, resource):
        """ disableCapture :
        Disables a capture resource by disconnecting the attached filter.

        Sample usage:
        >>> nto.disableCapture('L1-CAP')
        ''
        """
        argsAPI = {}
        return self._callServer('PUT', '/api/capture_resources/' + resource + '/disable', argsAPI, False)

    def downloadCaptureFile(self, resource, argsAPI, local_file_name=None):
        """ downloadCaptureFile :
        Downloads a capture file of capture resource.

        Sample usage:
        >>> nto.downloadFileCapture('L1-CAP', {'file_name': 'Suspicious Netflow export.pcap'})
        """
            
        file_name = ''
        if 'file_name' in argsAPI:
            file_name = argsAPI['file_name']

        file = self._callServer('POST', '/api/capture_resources/' + resource + '/download_file', argsAPI, False)
        if local_file_name is None:
            local_file_name = file_name
        f = open(local_file_name, 'wb')
        f.write(file)
        f.close()

    def enableCapture(self, resource, argsAPI):
        """ enableCapture :
        Enables a capture by attaching a filter to it.

        Sample usage:
        >>> nto.enableCapture('546', {'filter_id': '524'})
        ''
        """
        return self._callServer('PUT', '/api/capture_resources/' + resource + '/enable', argsAPI, False)

    def ftpTransferCapture(self, resource, argsAPI):
        """ ftpTransferCapture :
        Transfers via FTP a capture file or the buffer of a capture resource.

        Sample usage:
        >>> nto.ftpTransferCapture('317', {'address': '10.218.6.43', 'file_name': '150604_085131.pcap', 'password': '****', 'range_type': 'ALL_PACKETS', 'remote_file_name': 'fred-api.pcap', 'user': 'fredmota', 'port': 21})
        '{\n        "id": 2,\n        "progress": 0,\n        "state": "PENDING"\n}'
        """
        return self._callServer('POST', '/api/capture_resources/' + resource + '/ftp_file', argsAPI, False)

    def getTriggerPacketCapture(self, resource):
        """ getTriggerPacketCapture :
        Gets the number of the packet that triggered the capture.

        Sample usage:
        >>> nto1.getTriggerPacketCapture('546')
        {u'triggerPacketNumber': 1025}
        """
        return self._callServer('GET', '/api/capture_resources/' + resource + '/trigger_packet')

    def listCaptureFiles(self, resource):
        """ listCaptureFiles :
        Fetch a list containing the summaries for all the captures in the system.

        Sample usage:
        >>> nto.listFilesCapture('546')
        [{u'access_settings': {u'policy': u'REQUIRE_MEMBER', u'groups': [u'group1', u'group2']}, u'description': u'Capture file description', u'capture_date': 1440119146145, u'name': u'File 2.pcap', u'packet_count': 32, u'duration': 12, u'size': 262144, u'access_policy_id': u'7300-demodemo'}]
        """
        argsAPI = {}
        return self._callServer('GET', '/api/capture_resources/' + resource + '/files', argsAPI)

    def scpTransferCapture(self, resource, argsAPI):
        """ scpTransferCapture :
        Transfers via SCP a capture file or the buffer of a capture resource.

        Sample usage:
        >>> nto.scpTransferCapture('317', {'address': '10.218.30.1', 'file_name': '150604_085131.pcap', 'password': 'Anue', 'port': 22, 'range_type': 'ALL_PACKETS', 'remote_file_name': 'fred-api.pcap', 'user': 'support'})
        '{\n        "id": 3,\n        "progress": 0,\n        "state": "PENDING"\n}'
        """
        return self._callServer('POST', '/api/capture_resources/' + resource + '/scp_file', argsAPI, False)

    def saveBufferCapture(self, resource, argsAPI):
        """ saveBufferCapture :
        Saves the buffer of a capture resource to a new capture file.

        Sample usage:
        >>> nto.saveBufferCapture('L1-CAP', {'file_name': 'wep_api_test.pcap', 'description': 'Web API Saved File', 'range' : '1-10', 'range_type': 'RANGE'})
        {u'progress': 0, u'state': u'PENDING', u'id': 1}
        """
        return self._callServer('POST', '/api/capture_resources/' + resource + '/save_buffer', argsAPI)

    def searchCapture(self, argsAPI):
        """ searchCapture :
        Search for a specific capture in the system by certain properties.

        Sample usage:
        >>> nto.searchCapture({'status': 'IDLE_WITH_DATA'})
        [{u'id': 177, u'name': u'L1-CAP'}]
        """
        return self._callServer('POST', '/api/capture_resources/search', argsAPI)

    def startCapture(self, resource):
        """ startCapture :
        Starts a capture resource to capture packets via the attached filter.

        Sample usage:
        >>> nto.startCapture('L1-CAP')
        ''
        """
        argsAPI = {}
        return self._callServer('PUT', '/api/capture_resources/' + resource + '/start', argsAPI, False)

    def stopCapture(self, resource):
        """ stopCapture :
        Stops a capture resource to capture packets via the attached filter.

        Sample usage:
        >>> nto.stopCapture('L1-CAP')
        ''
        """
        argsAPI = {}
        return self._callServer('PUT', '/api/capture_resources/' + resource + '/stop', argsAPI, False)

    def modifyCapture(self, resource, argsAPI):
        """ modifyCapture :
        Update the properties of an existing capture resource.

        Sample usage:
        >>> nto.modifyCapture('L1-CAP', {'buffer_size': 100})
        ''
        """
        return self._callServer('PUT', '/api/capture_resources/' + resource, argsAPI, False)

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
        return self._callServer('GET', '/api/atip_resources')
        
    def getAtip(self, resource):
        """ getCapture :
        Fetch the properties of an ATIP resource.

        Sample usage:
        >>> nto.getAtip('L2-ATIP')
        {u'fill_to_trigger_position': False, u'description': None, u'capture_source': 304, u'lineboard_id': 173, u'default_name': u'L2-ATIP', u'resource_status': u'READY', u'name': u'L2-ATIP', u'mod_count': 5, u'license_status': u'VALID', u'modify_access_settings': {u'policy': u'REQUIRE_ADMIN', u'groups': []}, u'id': 179, u'connect_disconnect_access_settings': {u'policy': u'REQUIRE_ADMIN', u'groups': []}, u'history': [{u'type': u'MODIFY', u'time': 1442009546622, u'caused_by': u'admin', u'details': None, u'props': [u'NETFLOW_ENABLED']}]}
        """
        return self._callServer('GET', '/api/atip_resources/' + resource)

    def disableAtip(self, resource):
        """ disableAtip :
        Disables an ATIP by disconnecting the attached filter.

        Sample usage:
        >>> nto.disableAtip('319')
        ''
        """
        argsAPI = {}
        return self._callServer('PUT', '/api/atip_resources/' + resource + '/disable', argsAPI, False)

    def enableAtip(self, resource, argsAPI):
        """ enableAtip :
        Enables a capture by attaching a filter to it.

        Sample usage:
        >>> nto.enableAtip('319', {'filter_id': 'F1'})
        ''
        """
        return self._callServer('PUT', '/api/atip_resources/' + resource + '/enable', argsAPI, False)

    def searchAtip(self, argsAPI):
        """ searchAtip :
        Search for a specific ATIP resource in the system by certain properties.

        Sample usage:
        >>> nto.searchAtip({'resource_status': 'READY'})
        [{u'id': 179, u'name': u'L2-ATIP'}]
        """
        return self._callServer('POST', '/api/atip_resources/search', argsAPI)

    def modifyAtip(self, resource, argsAPI):
        """ modifyAtip:
        Update the properties of an existing ATIP resource.

        Sample usage:
        >>> nto.modifyAtip('L2-ATIP', {'description': 'ATIP at slot #2'})
        ''
        """
        return self._callServer('PUT', '/api/atip_resources/' + resource, argsAPI, False)


    ###################################################
    # Authentication
    ###################################################
    def logout(self):
        """ logout :
        This call is used to invalidate any token returned from other calls to the web API.
        
        Sample usage:
        >>> nto.logout()
        'User "admin" has logged out.'
        """
        argsAPI = {}
        return self._callServer('GET', '/api/auth/logout', argsAPI, False)

    ###################################################
    # Bypass connectors
    ###################################################
    def createBypass(self, argsAPI):
        """ createBypass :
        Create a new Inline Bypass Connector in the system.

        Sample usage:
        """
        return self._callServer('POST', '/api/bypass_connectors', argsAPI)

    def getBypass(self, bypass_id):
        """ getBypass :
        Fetch the properties of an Inline Bypass Connector.

        Sample usage:
        """
        return self._callServer('GET', '/api/bypass_connectors/' + bypass_id)

    def getAllBypasses(self):
        """ getAllBypasses :
        Fetch a list containing the summaries for all the Inline Bypass Connectors in the system.

        Sample usage:
        """
        return self._callServer('GET', '/api/bypass_connectors')

    def searchBypass(self, argsAPI):
        """ searchBypass :
        Search for a specific Inline Bypass Connector in the system by certain properties.

        Sample usage:
        """
        return self._callServer('POST', '/api/bypass_connectors/search', argsAPI)

    def modifyBypass(self, bypass_id, argsAPI):
        """ modifyBypass:
        Update the properties of an existing Inline Bypass Connector.

        Sample usage:
        >>> nto.modifyAtip('L2-ATIP', {'description': 'ATIP at slot #2'})
        ''
        """
        return self._callServer('PUT', '/api/bypass_connectors/' + bypass_id, argsAPI, False)

    ####################################
    # Control Tower Evolution
    ####################################

    # CTE Cluster

    def getCteCluster(self, argsAPI):
        """ getCteCluster :
        Retrieve the properties of the CTE cluster.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_cluster', argsAPI)


    # CTE Connections

    def createCteConnection(self, argsAPI):
        """ createCteConnection :
        Create a new CTE connection in the system.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_connections', argsAPI)

    def deleteCteConnection(self, cte_id):
        """ deleteCteConnection :
        Remove a CTE connection.

        Sample usage:
        """
        return self._callServer('DELETE', '/api/cte_connections/' + cte_id, None, False)

    def getCteConnection(self, cte_id):
        """ getCteConnection :
        Fetch the properties of a CTE connection.

        Sample usage:
        """
        return self._callServer('GET', '/api/cte_connections/' + cte_id)

    def getAllCteConnections(self):
        """ getAllCteConnections :
        Fetch a list containing the summaries for all the CTE connections.
            
        Sample usage:
        """
        return self._callServer('GET', '/api/cte_connections')

    def searchCteConnection(self, argsAPI):
        """ searchCteConnection :
        Search a specific CTE connection by certain properties.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_connections/search', argsAPI)

    def modifyCteConnection(self, cte_id, argsAPI):
        """ modifyCteConnection :
        Update the properties of an existing CTE connection.

        Sample usage:
        """
        return self._callServer('PUT', '/api/cte_connections/' + cte_id, argsAPI, False)


    # CTE Filters

    def createCteFilter(self, argsAPI):
        """ createCteFilter :
        Create a new CTE filter in the system.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_filters', argsAPI)

    def deleteCteFilter(self, cte_filter_id):
        """ deleteCteFilter :
        Remove a CTE filter.

        Sample usage:
        """
        return self._callServer('DELETE', '/api/cte_filters/' + cte_filter_id, None, False)

    def getCteFilter(self, cte_filter_id):
        """ getCteFilter :
        Fetch the properties of a CTE filter.

        Sample usage:
        """
        return self._callServer('GET', '/api/cte_filters/' + cte_filter_id)

    def getAllCteFilters(self):
        """ getAllCteFilters :
        Fetch a list containing the summaries for all the CTE filters.

        Sample usage:
        """
        return self._callServer('GET', '/api/cte_filters')

    def searchCteFilter(self, argsAPI):
        """ searchCteFilter :
        Search a specific CTE filter by certain properties.
        
        Sample usage:
        """
        return self._callServer('POST', '/api/cte_filters/search', argsAPI)

    def modifyCteFilter(self, cte_filter_id, argsAPI):
        """ modifyCteFilter :
        Update the properties of an existing CTE connection.

        Sample usage:
        """
        return self._callServer('PUT', '/api/cte_filters/' + cte_filter_id, argsAPI, False)


    # CTE Members

    def getCteMember(self, cte_member_id):
        """ getCteMember :
        Fetch the properties of a CTE member.

        Sample usage:
        """
        return self._callServer('GET', '/api/cte_members/' + cte_member_id)

    def getAllCteMembers(self):
        """ getAllCteMembers :
        Fetch a list containing the summaries for all the CTE members.

        Sample usage:
        """
        return self._callServer('GET', '/api/cte_members')

    def searchCteMember(self, argsAPI):
        """ searchCteMember :
        Search a specific CTE member by certain properties.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_members/search', argsAPI)


    # CTE Operations

    def clearCteConfig(self):
        """ clearCteConfig :
        Create a CTE topology.
        
        Sample usage:
        """
        argsAPI = {}
        return self._callServer('POST', '/api/cte_operations/cte_clear_config', argsAPI, False)

    def clearCteFiltersAndPort(self):
        """ clearCteFiltersAndPort :
        This command deletes all filters and port groups and sets all ports to default values..
        
        Sample usage:
        """
        argsAPI = {}
        return self._callServer('POST', '/api/cte_operations/cte_clear_filters_and_ports', argsAPI, False)

    def createCteTopology(self, argsAPI):
        """ createCteTopology :
        Create a CTE topology.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_operations/create_topology', argsAPI)

    def disbandCteTopology(self, argsAPI):
        """ disbandCteTopology :
        Disband the CTE topology. The local device and all other members
        that can be notified will be forced out of the topology. Manual
        disband on unreachable devices is required to recover them.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_operations/disband_topology', argsAPI)

    def exportCteTopology(self, argsAPI):
        """ exportCteTopology :
        Export topology configuration to a file.
        
        Sample usage:
        """
        return self._callServer('POST', '/api/cte_operations/export', argsAPI)

    def forceRemoveFromCteTopology(self, argsAPI):
        """ forceRemoveFromCteTopology :
        Given a failed member of a CTE topology by its IPv4 address, force
        remove it from the topology.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_operations/force_remove', argsAPI)

    def importCteTopology(self, argsAPI):
        """ importCteTopology :
        Import topology configuration from a file.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_operations/import', argsAPI)

    def joinCteTopology(self, argsAPI):
        """ joinCteTopology :
        Join the current stack to a CTE topology.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_operations/join_topology', argsAPI)

    def leaveCteTopology(self, argsAPI):
        """ leaveCteTopology :
        Given a member of a CTE topology by its IPv4 address, this action will
        disconnect it from the topology.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_operations/leave_topology', argsAPI)


    # CTE Port Groups

    def getCtePortGroup(self, cte_port_group_id):
        """ getCtePortGroup :
        Fetch the properties of a CTE port group.

        Sample usage:
        """
        return self._callServer('GET', '/api/cte_port_groups/' + cte_port_group_id)

    def getAllCtePortGroups(self):
        """ getAllCtePortGroups :
        Fetch a list containing the summaries for all the CTE port groups.

        Sample usage:
        """
        return self._callServer('GET', '/api/cte_port_groups')

    def searchCtePortGroup(self, argsAPI):
        """ searchCtePortGroup :
        Search a specific CTE port group by certain properties.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_port_groups/search', argsAPI)


    # CTE Ports

    def getCtePort(self, cte_port_id):
        """ getCtePort :
        Fetch the properties of a CTE port.

        Sample usage:
        """
        return self._callServer('GET', '/api/cte_ports/' + cte_port_id)

    def getAllCtePorts(self):
        """ getAllCtePorts :
        Fetch a list containing the summaries for all the CTE ports.

        Sample usage:
        """
        return self._callServer('GET', '/api/cte_ports')

    def searchCtePortGroup(self, argsAPI):
        """ searchCtePortGroup :
        Search a specific CTE port by certain properties.

        Sample usage:
        """
        return self._callServer('POST', '/api/cte_ports/search', argsAPI)
        
    ####################################
    # CTE Remote Systems (deprecated)
    ####################################
    def getAllCtes(self):
        """ getAllCtes :
        Fetch a list containing the summaries for all the CTE remote
        systems available on this device.

        Sample usage:
        """
        return self._callServer('GET', '/api/cte_remote_system')

    def getCte(self, cte_id):
        """ getCte :
        Fetch the properties of a CTE remote system available on the local device.
        
        Sample usage:
        """
        return self._callServer('GET', '/api/cte_remote_system/' + cte_id)

    def connectCte(self, argsAPI):
        """ connectCte :
        Make a new CTE remote system available on the local device.
            
        Sample usage:
        """
        return self._callServer('POST', '/api/cte_remote_system', argsAPI)

    def disconnectCte(self, cte_id):
        """ disconnectCte :
        Remove a CTE remote system from the local device.
        
        Sample usage:
        """
        argsAPI = {}
        return self._callServer('DELETE', '/api/cte_remote_system/' + cte_id , argsAPI, False)

    def searchCte(self, argsAPI):
        """ searchCte :
        Search by certain properties for a specific CTE remote systems available on this device.
        
        Sample usage:
        """
        return self._callServer('POST', '/api/cte_remote_system/search', argsAPI)

    def modifyCte(self, cte_id, argsAPI):
        """ modifyCte :
        Update the connection details of a CTE remote system available on the local device.
        
        Sample usage:
        """
        return self._callServer('PUT', '/api/cte_remote_system/' + cte_id, argsAPI, False)
    

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
        return self._callServer('GET', '/api/custom_icons')

    def getIcon(self, icon):
        """ getIcon :
        Fetch the properties of a custom icon which is specified by its custom_icon_id_or_name.

        Samle usage:
        >>> nto.getIcon('75')
        {u'description': u'A bomb!', u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1440623340772}, u'name': u'A Big Bomb!', u'mod_count': 2, u'id': 75, u'history': [{u'type': u'MODIFY', u'time': 1440623518301, u'caused_by': u'admin', u'details': None, u'props': [u'NAME']}]}
        """
        return self._callServer('GET', '/api/custom_icons/' + icon)

    def createIcon(self, argsAPI):
        """ createIcon :
        Create a new custom icon.
        
        Sample usage:
        >>> nto.createIcon({'description': 'A bomb!', 'file_name': '/Users/fmota/Desktop/bomb.jpeg', 'name' : 'Bomb'})
        {u'id': u'75'}
        """
        description = ''
        if 'description' in argsAPI:
            description = argsAPI['description']

        file_name = ''
        if 'file_name' in argsAPI:
            file_name = argsAPI['file_name']

        name = ''
        if 'name' in argsAPI:
            name = argsAPI['name']

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

    def modifyIcon(self, icon_id, argsAPI):
        """ modifyIcon :
        Update properties of a custom icon.

        Sample usage:
        >>> nto.modifyIcon('75', {'name' : 'A Big Bomb!'})
        ''
        """
        return self._callServer('PUT', '/api/custom_icons/' + icon_id, argsAPI, False)

    def searchIcon(self, argsAPI):
        """ searchFilterTemplateCollections :
        Search for a specific custom icon in the system by certain properties.

        Sample usage:
        >>> nto.searchIcon({'name' : 'A Big Bomb!'})
        [{u'id': 75, u'name': u'A Big Bomb!'}]
        """
        return self._callServer('POST', '/api/custom_icons/search', argsAPI)

    def deleteIcon(self, icon_id):
        """ deleteIcon :
        Remove a custom icon from the system.
        The custom icon is specified by a custom_icon_id_or_name.

        Sample usage:
        >>>.deleteIcon('75')
        ''
        """
        return self._callServer('DELETE', '/api/custom_icons/' + icon_id, None, False)

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
        return self._callServer('GET', '/api/filter_template_collections')
    
    def getFilterTemplateCollection(self, filter_template_collection):
        """ getFilterTemplateCollection :
        Fetch the properties of a filter template collection object which is specified by its
        filter_template_collection_id_or_name.

        Sample usage:
        >>> nto.getFilterTemplateCollection('467')
        {u'description': None, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1429303086082}, u'name': u'NET_TROUBLESHOOTING', u'mod_count': 2, u'id': 467, u'history': []}
        """
        return self._callServer('GET', '/api/filter_template_collections/' + filter_template_collection)
    
    def createFilterTemplateCollection(self, argsAPI):
        """ createFilterTemplateCollection :
        Create a new filter template collection.

        Sample usage:
        >>> nto.createFilterTemplateCollection({'description': 'My filter collection', 'name': 'Private Filter Collection'})
        {u'id': u'50'}
        """
        return self._callServer('POST', '/api/filter_template_collections', argsAPI)
    
    def modifyFilterTemplateCollection(self, filter_template_collection_id, argsAPI):
        """ modifyFilterTemplateCollection :
        Update properties of a filter template collection.

        Sample usage:
        >>> nto.modifyFilterTemplateCollection('50', {'description': 'My private filter collection'})
        ''
        """
        return self._callServer('PUT', '/api/filter_template_collections/' + filter_template_collection_id, argsAPI, False)
    
    def searchFilterTemplateCollections(self, argsAPI):
        """ searchFilterTemplateCollections :
        Search for a specific filter template collection in the system by certain properties.

        Sample usage:
        >>> nto.searchFilterTemplateCollections({'name': 'Private Filter Collection'})
        [{u'id': 50, u'name': u'Private Filter Collection'}]
        """
        return self._callServer('POST', '/api/filter_template_collections/search', argsAPI)
    
    def deleteFilterTemplateCollection(self, filter_template_collection_id):
        """ deleteFilterTemplate :
        Remove a filter template collection from the system. The filter is specified by a
        filter_template_collection_id_or_name.

        Sample usage:
        >>> nto.deleteFilterTemplateCollection('50')
        ''
        """
        return self._callServer('DELETE', '/api/filter_template_collections/' + filter_template_collection_id, None, False)

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
        return self._callServer('GET', '/api/filter_templates')
    
    def getFilterTemplate(self, filter_template):
        """ getFilterTemplate :
        Fetch the properties of a filter templates object which is specified by its filter_template_id.

        Sample usage:
        >>> nto.getFilterTemplate('468')
        {u'description': u'Use for base line tools.  Checks ICMP and SNMP traffic.', u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1429303123112}, u'collection': u'NET_TROUBLESHOOTING', u'name': u'Too Much Overhead', u'mod_count': 5, u'criteria': {u'logical_operation': u'AND', u'ip_protocol': {u'value': u'1'}, u'layer4_src_or_dst_port': {u'port': u'161-162'}}, u'id': 468, u'history': []}
        """
        return self._callServer('GET', '/api/filter_templates/' + filter_template)
    
    def createFilterTemplate(self, argsAPI):
        """ createFilterTemplate :
        Create a new filter template.

        Sample usage:
        >>> nto.createFilterTemplate({'collection': 'Public', 'name': 'Virtual Traffic', 'criteria': {'vlan': {'vlan_id': '100'}, 'logical_operation': 'AND'}})
        {u'id': u'52'}
        """
        return self._callServer('POST', '/api/filter_templates', argsAPI)
    
    def modifyFilterTemplate(self, filter_template_id, argsAPI):
        """ modifyFilterTemplate :
        Update properties of a filter template.

        Sample usage:
        >>> nto.modifyFilterTemplate('52', {'criteria': {'vlan': {'vlan_id': '200'}, 'logical_operation': 'AND'}})
        ''
        """
        return self._callServer('PUT', '/api/filter_templates/' + filter_template_id, argsAPI, False)
    
    def searchFilterTemplates(self, argsAPI):
        """ searchFilterTemplates :
        Search for a specific filter template in the system by certain properties.

        Sample usage:
        >>> nto.searchFilterTemplates({'collection': 'Public'})
        [{u'id': 51, u'name': u'VLAN Gold'}, {u'id': 52, u'name': u'Virtual Traffic'}]
        """
        return self._callServer('POST', '/api/filter_templates/search', argsAPI)
    
    def deleteFilterTemplate(self, filter_template_id):
        """ deleteFilterTemplate :
        Remove a filter template from the system. The filter template is specified by a filter_template_id.

        Sample usage:
        >>> nto.deleteFilterTemplate('52')
        ''
        """
        return self._callServer('DELETE', '/api/filter_templates/' + filter_template_id, None, False)

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
        return self._callServer('GET', '/api/filters')
    
    def getFilter(self, filter):
        """ getFilter :
        Fetch the properties of a filter object which is specified by its filter_id_or_name.

        Sample usage:
        >>> nto.getFilter('461')
        {u'dynamic_filter_type': u'TWO_STAGE', u'connect_in_access_settings': {u'policy': u'INHERITED'}, u'dest_port_list': [], u'match_count_unit': u'PACKETS', u'description': None, u'resource_access_settings': {u'policy': u'INHERITED'}, u'created': None, u'modify_access_settings': {u'policy': u'INHERITED'}, u'default_name': u'F3', u'dest_port_group_list': [], u'name': u'Voice VLANs', u'mod_count': 6, u'snmp_tag': None, u'mode': u'PASS_BY_CRITERIA', u'criteria': {u'vlan': {u'priority': None, u'vlan_id': u'1000'}, u'logical_operation': u'AND'}, u'keywords': [], u'source_port_group_list': [], u'source_port_list': [410, 428], u'connect_out_access_settings': {u'policy': u'INHERITED'}, u'id': 461, u'history': [{u'type': u'MODIFY', u'time': 1442251734144, u'caused_by': u'internal', u'details': None, u'props': [u'SOURCE_PORT_LIST', u'DEST_PORT_LIST']}]}
        """
        return self._callServer('GET', '/api/filters/' + filter)
    
    def createFilter(self, argsAPI, allowTemporayDataLoss=False):
        """ createFilter :
        Create a new filter.

        Sample usage:
        >>> nto.createFilter({'source_port_list': ['218', '220'], 'dest_port_list': ['219'], 'mode': 'PASS_ALL'})
        {u'id': u'466'}
        """
        return self._callServer('POST', '/api/filters?allowTemporayDataLoss=' + str(allowTemporayDataLoss), argsAPI)
    
    def modifyFilter(self, filter_id, argsAPI, allowTemporayDataLoss=False):
        """ modifyFilter :
        Update properties of a filter.

        Sample usage:
        >>> nto.modifyFilter('F4', {'mode' : 'PASS_BY_CRITERIA', 'criteria' : {'logical_operation': 'AND', 'ipv4_session_flow': {'session_sets': [{'a_sessions': ['10.0.0.0/24:1', '12.0.0.0/24:1'], 'b_sessions': ['14.0.0.0/24:1', '16.0.0.0/24:1']}], 'flow_type': 'UNI'}}})
        ''
        """
        return self._callServer('PUT', '/api/filters/' + filter_id + '?allowTemporayDataLoss=' + str(allowTemporayDataLoss), argsAPI, False)
    
    def searchFilters(self, argsAPI):
        """ searchFilters :
        Search for a specific port group in the system by certain properties.

        Sample usage:
        >>> nto.searchFilters({'mode' : 'PASS_BY_CRITERIA'})
        [{u'id': 463, u'name': u'Syn Attack'}, {u'id': 465, u'name': u'Too Much Overhead'}, {u'id': 466, u'name': u'F8'}, {u'id': 55, u'name': u'F4'}, {u'id': 460, u'name': u'TCP, UDP, HTTP'}, {u'id': 462, u'name': u'ARP Storm'}, {u'id': 461, u'name': u'Voice VLANs'}]
        """
        return self._callServer('POST', '/api/filters/search', argsAPI)
    
    def deleteFilter(self, filter_id):
        """ deleteFilter :
        Remove a filter from the system. The filter is specified by a filter_id_or_name.

        Sample usage:
        >>> nto.deleteFilter('F4')
        ''
        """
        return self._callServer('DELETE', '/api/filters/' + filter_id, None, False)

    def getFilterProperty(self, filter, property):
        """ getFilterProperty :
        Fetch a property of a filter object which is specified by its
        port_id_or_name.
        
        Sample usage:
        >>> nto.getFilterProperty('F1', 'keywords')
        [u'TIME']
        """
        return self._callServer('GET', '/api/filters/' + filter + '?properties=' + property)[property]

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
        return self._callServer('GET', '/api/groups')
    
    def getGroup(self, group):
        """ getGroup :
        Fetch the properties of an user group object which is specified by its
        group_id_or_name.

        Sample usage:
        >>> nto.getGroup('369')
        {u'owners': [], u'auto_created': False, u'description': None, u'name': u'Security Mgmt', u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1256831414761}, u'accessible_ports': [], u'mod_count': 2, u'members': [u'bbrother', u'securityguy'], u'accessible_filters': [], u'id': 369, u'history': [{u'type': u'MODIFY', u'time': 1316645263611, u'caused_by': u'internal', u'details': None, u'props': [u'ACCESSIBLE_PORTS']}]}
        """
        return self._callServer('GET', '/api/groups/' + group)
    
    def createGroup(self, argsAPI):
        """ createGroup :
        Create a new user group.

        Sample usage:
        >>> nto.createGroup({'name' : 'Automation', 'members': ['bbrother', 'jfixit']})
        {u'id': u'477'}
        """
        return self._callServer('POST', '/api/groups', argsAPI)
    
    def modifyGroup(self, group_id, argsAPI):
        """ modifyGroup :
        Update the properties of an existing user group.

        Sample usage:
        >>> nto.modifyGroup('Automation', {'members': ['jfixit']})
        ''
        """
        return self._callServer('PUT', '/api/groups/' + group_id, argsAPI, False)
    
    def deleteGroup(self, group_id):
        """ deleteGroup :
        Remove a user from the system. The user is specified by a group_id_or_name.

        Sample usage:
        >>> nto.deleteGroup('477')
        ''
        """
        return self._callServer('DELETE', '/api/groups/' + group_id, None, False)
    
    def searchGroups(self, argsAPI):
        """ searchGroups :
        Search for a specific user group in the system by certain properties.

        Sample usage:
        >>> nto.searchGroups({'members': ['netopsguy']})
        [{u'id': 367, u'name': u'Network Mgmt'}]
        """
        return self._callServer('POST', '/api/groups/search', argsAPI)

    ###################################################
    # Heartbeats
    ###################################################
    def createHeartbeat(self, argsAPI):
        """ createHeartbeat :
        Create a new tool heartbeat in the system.

        Sample usage:
        """
        return self._callServer('POST', '/api/heartbeats', argsAPI)

    def deleteHeartbeat(self, heartbeat_id):
        """ deleteHeartbeat :
        Remove an existing tool heartbeat from the system.

        Sample usage:
        """
        return self._callServer('DELETE', '/api/heartbeats/' + heartbeat_id, None, False)

    def getHeartbeat(self, heartbeat_id):
        """ getHeartbeat :
        Fetch the properties of a tool heartbeat object.

        Sample usage:
        """
        return self._callServer('GET', '/api/heartbeats/' + bypass_id)

    def getAllHeartbeats(self):
        """ getAllHeartbeats :
        Fetch a list containing the summaries for all the tool heartbeats in the system.

        Sample usage:
        """
        return self._callServer('GET', '/api/heartbeats')

    def searchHeartbeat(self, argsAPI):
        """ searchHeartbeat :
        Search for a specific tool heartbeat in the system by certain properties.

        Sample usage:
        """
        return self._callServer('POST', '/api/heartbeats/search', argsAPI)

    def modifyHeartbeat(self, heartbeat_id, argsAPI):
        """ modifyHeartbeat:
        Update the properties of an existing tool heartbeat.

        Sample usage:
        """
        return self._callServer('PUT', '/api/heartbeats/' + heartbeat_id, argsAPI, False)

    ###################################################
    # Inline service chains
    ###################################################
    def createInline(self, argsAPI):
        """ createInline :
        Create a new inline service chain in the system.

        Sample usage:
        """
        return self._callServer('POST', '/api/inline_service_chains', argsAPI)

    def deleteInline(self, inline_id):
        """ deleteInline :
        Remove an existing inline service chain from the system.
            
        Sample usage:
        """
        return self._callServer('DELETE', '/api/inline_service_chains/' + inline_id, None, False)

    def getInline(self, inline_id):
        """ getInline :
        Fetch the properties of a inline service chain object.

        Sample usage:
        """
        return self._callServer('GET', '/api/inline_service_chains/' + inline_id)

    def getAllInlines(self):
        """ getAllInlines :
        Fetch a list containing the summaries for all the inline service chains in the system.

        Sample usage:
        """
        return self._callServer('GET', '/api/inline_service_chains')

    def searchInline(self, argsAPI):
        """ searchInline :
        Search for a specific inline service chain in the system by certain properties.

        Sample usage:
        """
        return self._callServer('POST', '/api/inline_service_chains/search', argsAPI)

    def modifyInline(self, inline_id, argsAPI):
        """ modifyInline:
        Update the properties of an existing inline service chain.

        Sample usage:
        """
        return self._callServer('PUT', '/api/inline_service_chains/' + inline_id, argsAPI, False)

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
        return self._callServer('GET', '/api/line_boards')
    
    def getLineBoard(self, line_board):
        """ getLineBoard :
        Fetch the properties of a line board.

        Sample usage:
        >>> nto.getLineBoard('LC6')
        {u'name': u'LC6', u'qsfp_card_mode': u'MODE_QSFP', u'default_name': u'LC6', u'mod_count': 9, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'id': 471}
        """
        return self._callServer('GET', '/api/line_boards/' + line_board)
    
    def searchLineBoard(self, argsAPI):
        """ searchLineBoard :
        Search for a specific capture in the system by certain properties.

        Sample usage:
        >>> nto.searchLineBoard({'name': 'LC6'})
        [{u'id': 471, u'name': u'LC6'}]
        """
        return self._callServer('POST', '/api/line_boards/search', argsAPI)
    
    def switchModeLineBoard(self, line_board):
        """ switchModeLineBoard :
        Switches the card mode to QSFP if in SFP mode and to SFP if in QSFP mode.

        Sample usage:
        >>> nto.switchModeLineBoard('LC6')
        ''
        """
        argsAPI = {}
        return self._callServer('PUT', '/api/line_boards/' + line_board + '/switch_mode', argsAPI, False)
    
    def modifyLineBoard(self, line_board, argsAPI):
        """ modifyLineBoard :
        Update the properties of an existing line board.

        Sample usage:
        >>> nto.modifyLineBoard('LC6', {'name' : 'Test LC'})
        ''
        """
        return self._callServer('PUT', '/api/line_boards/' + line_board, argsAPI, False)

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
        return self._callServer('GET', '/api/monitors')
    
    def getMonitor(self, monitor):
        """ getMonitor :
        Fetch the properties of a monitor object which is specified by its
        monitor_id_or_name.

        Sample usage:
        >>> nto.getMonitor('572')
        {u'description': None, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1442432114344}, u'actions': [{u'min_interval': {u'value': 15, u'unit': u'SEC'}, u'type': u'TRAP', u'enabled': True}], u'name': u'Low Traffic', u'mod_count': 0, u'trigger': {u'stat': u'NP_CURRENT_RX_UTILIZATION', u'window_size': 1, u'window_count': 1, u'down_threshold_enabled': True, u'up_threshold': 99, u'up_threshold_enabled': False, u'down_threshold': 10, u'type': u'PERCENT_STAT', u'ports': [58]}, u'id': 572, u'history': []}
        """
        return self._callServer('GET', '/api/monitors/' + monitor)
    
    def createMonitor(self, argsAPI):
        """ createMonitor :
        Create a new monitor.

        Sample usage:
        >>> nto.createMonitor({'actions': [{'min_interval': {'value': 15, 'unit': 'SEC'}, 'type': 'TRAP', 'enabled': True}], 'name': 'Drop Packets', 'trigger': {'stat': 'TP_TOTAL_DROP_COUNT_PACKETS', 'window_size': 1, 'min_change': 10, 'window_count': 1, 'type': 'COUNT_STAT', 'ports': [59]}})
        '{"id": "574"}'
        """
        return self._callServer('POST', '/api/monitors', argsAPI, False)
    
    def modifyMonitor(self, monitor_id, argsAPI):
        """ modifyMonitor :
        Update properties of a monitor.

        Sample usage:
        >>> nto.modifyMonitor('574', {'trigger': {'stat': 'TP_TOTAL_DROP_COUNT_PACKETS', 'window_size': 1, 'min_change': 20, 'window_count': 1, 'type': 'COUNT_STAT', 'ports': [59]}})
        ''
        """
        return self._callServer('PUT', '/api/monitors/' + monitor_id, argsAPI, False)
    
    def searchMonitors(self, argsAPI):
        """ searchMonitors :
        Search for a specific port group in the system by certain properties.

        Sample usage:
        >>> nto.searchMonitors({'name': 'Drop Packets'})
        [{u'id': 574, u'name': u'Drop Packets'}]
        """
        return self._callServer('POST', '/api/monitors/search', argsAPI)
    
    def deleteMonitor(self, monitor_id):
        """ deleteMonitor :
        Remove a monitor from the system. The monitor is specified by a monitor_id_or_name.

        Sample usage:
        >>> nto.deleteMonitor('572')
        ''
        """
        return self._callServer('DELETE', '/api/monitors/' + monitor_id, None, False)

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
        return self._callServer('GET', '/api/port_groups')
    
    def getPortGroup(self, port_group):
        """ getPortGroup :
        Fetch the properties of a port group object which is specified by its
        port_group_id_or_name.

        Sample usage:
        >>> nto.getPortGroup('404')
        {u'trim_settings': None, u'supports_timestamp': False, u'dedup_settings': None, u'vntag_strip_settings': None, u'vxlan_strip_settings': None, u'failover_mode': u'REBALANCE', u'keywords': [], u'supports_dedup': False, u'id': 404, u'fabric_path_strip_settings': None, u'supports_vntag_strip': False, u'has_dropped_packets': False, u'filtering_direction': u'INGRESS', u'supports_trailer_strip': False, u'icon_type': u'INTERCONNECT', u'last_filter_order_event': None, u'supports_mpls_strip': False, u'enabled_status': u'ENABLED', u'supports_burst_buffer': False, u'custom_icon_id': None, u'trailer_strip_settings': None, u'mpls_strip_settings': None, u'type': u'INTERCONNECT', u'tx_light_status': u'ON', u'filter_criteria': {u'logical_operation': u'AND'}, u'supports_std_vlan_strip': True, u'pause_frames_status': u'IGNORE', u'dest_filter_list': [], u'description': None, u'snmp_tag': None, u'l2gre_strip_settings': None, u'gtp_strip_settings': None, u'burst_buffer_settings': None, u'force_link_up': u'NOT_SUPPORTED', u'supports_trim': False, u'supports_gtp_strip': False, u'port_list': [58], u'supports_vxlan_strip': False, u'name': u'PG1', u'supports_l2gre_strip': False, u'supports_fabric_path_strip': False, u'link_status': {u'speed': 0, u'link_up': False}, u'interconnect_info': {u'addr': u'0.0.0.0', u'port_group': None}, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1442434236579}, u'default_name': u'PG1', u'supports_erspan_strip': False, u'mod_count': 1, u'timestamp_settings': None, u'erspan_strip_settings': None, u'mode': u'NETWORK', u'source_filter_list': [], u'filter_mode': u'PASS_ALL', u'std_vlan_strip_settings': {u'ingress_count': 0, u'egress_count': 0, u'enabled': False, u'strip_mode': None}, u'history': [{u'type': u'MODIFY', u'time': 1442434236579, u'caused_by': u'admin', u'details': None, u'props': [u'PORT_LIST']}]}
        """
        return self._callServer('GET', '/api/port_groups/' + port_group)
    
    def createPortGroup(self, argsAPI):
        """ createPortGroup :
        Create a new port group.

        Sample usage:
        >>> nto.createPortGroup({'mode': 'NETWORK', 'type': 'INTERCONNECT', 'port_list': [59,60]})
        {u'id': u'405'}
        """
        return self._callServer('POST', '/api/port_groups', argsAPI)
    
    def modifyPortGroup(self, port_group_id, argsAPI):
        """ modifyPortGroup :
        Update properties of a port group.

        Sample usage:
        >>> nto.modifyPortGroup('PG2', {'port_list': [59,60,61,62]})
        ''
        """
        return self._callServer('PUT', '/api/port_groups/' + port_group_id, argsAPI, False)
    
    def searchPortGroups(self, argsAPI):
        """ searchPortGroups :
        Search for a specific port group in the system by certain properties.

        Sample usage:
        >>> nto.searchPortGroups({'enabled_status' : 'DISABLED'})
        [{u'id': 404, u'name': u'PG1'}]
        """
        return self._callServer('POST', '/api/port_groups/search', argsAPI)
    
    def deletePortGroup(self, port_group_id):
        """ deletePortGroup :
        Remove a port group from the system. The port group is specified by a port_group_id_or_name.

        Sample usage:
        >>> nto.deletePortGroup('PG2')
        ''
        """
        return self._callServer('DELETE', '/api/port_groups/' + port_group_id, None, False)

    def disablePortGroup(self, port_group_id):
        """ disablePortGroup :
        Disables a port group by disabling all the contained ports.
        
        Sample usage:
        """
        return self._callServer('PUT', '/api/port_groups/' + port_group_id + '/disable', None, False)
        
    def enablePortGroup(self, port_group_id):
        """ enablePortGroup :
        Enables a port group by enabling all the contained ports.
        
        Sample usage:
        """
        return self._callServer('PUT', '/api/port_groups/' + port_group_id + '/enable', None, False)

    def getPortGroupProperty(self, port_group, property):
        """ getPortGroupProperty :
        Fetch a property of a port group object which is specified by its
        port_id_or_name.
        
        Sample usage:
        >>> nto.getPortGroupProperty('PG1', 'keywords')
        [u'TIME']
        """
        return self._callServer('GET', '/api/port_groups/' + port_group + '?properties=' + property)[property]

    ###################################################
    # Ports
    ###################################################
    def getAllPorts(self):
        """ getAllPorts :
        Fetch a list containing summaries for all the ports in the system.

        Sample usage:
        >>> nto.getAllPorts()
        [{u'id': 58, u'name': u'P1-01'}, {u'id': 59, u'name': u'P1-02'}, {u'id': 60, u'name': u'P1-03'}, {u'id': 61, u'name': u'P1-04'}, {u'id': 62, u'name': u'P1-05'}, {u'id': 63, u'name': u'P1-06'}, {u'id': 64, u'name': u'P1-07'}, {u'id': 65, u'name': u'P1-08'}, {u'id': 66, u'name': u'P1-09'}, {u'id': 67, u'name': u'P1-10'}, {u'id': 68, u'name': u'P1-11'}, {u'id': 69, u'name': u'P1-12'}, {u'id': 70, u'name': u'P1-13'}, {u'id': 71, u'name': u'P1-14'}, {u'id': 72, u'name': u'P1-15'}, {u'id': 73, u'name': u'P1-16'}]
        """
        return self._callServer('GET', '/api/ports')
    
    def getPort(self, port):
        """ getPort :
        Fetch the properties of a port object which is specified by its
        port_id_or_name.

        Sample usage:
        >>> nto.getPort('58')
        {u'trim_settings': None, u'supports_timestamp': False, u'dedup_settings': None, u'filter_criteria': {u'logical_operation': u'AND'}, u'vntag_strip_settings': None, u'std_port_tagging_settings': {u'enabled': False, u'vlan_id': 101}, u'link_up_down_trap_enabled': True, u'filter_match_count_unit': u'PACKETS', u'gtp_fd_settings': None, u'keywords': [u'LC1'], u'tunnel_termination_settings': {u'ip_version': 4, u'dest_ip_addr': None, u'enabled': False, u'empty_erspan_header': False, u'tunnel_protocol': None}, u'supports_dedup': False, u'id': 58, u'fabric_path_strip_settings': None, u'supports_vxlan_strip': False, u'port_group_id': None, u'mpls_strip_settings': None, u'max_licensed_speed': u'40G', u'supports_vntag_strip': False, u'has_dropped_packets': False, u'filtering_direction': u'INGRESS', u'supports_trailer_strip': False, u'tunnel_mac': None, u'supports_tunnel_termination': False, u'supports_mpls_strip': False, u'copper_link_polling': False, u'last_filter_order_event': None, u'vxlan_strip_settings': None, u'supports_burst_buffer': False, u'custom_icon_id': None, u'trailer_strip_settings': None, u'media_type': u'QSFP_PLUS_40G', u'expiration_time': 1449727199651, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'type': u'QSFP_PLUS', u'link_settings': u'40G_FULL', u'tx_light_status': u'ON', u'connect_in_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'supports_std_vlan_strip': True, u'dest_filter_list': [], u'description': None, u'snmp_tag': None, u'l2gre_strip_settings': None, u'gtp_strip_settings': None, u'burst_buffer_settings': None, u'force_link_up': u'NOT_SUPPORTED', u'supports_trim': False, u'supports_gtp_strip': False, u'license_status': u'VALID', u'resource_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'supports_std_port_tagging': True, u'remote_fabric_port': None, u'connect_out_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'name': u'P1-01', u'supports_l2gre_strip': False, u'supports_fabric_path_strip': False, u'ignore_pause_frames': True, u'link_status': {u'duplex': u'UNKNOWN', u'pause': u'UNKNOWN', u'speed': u'N/A', u'link_up': False}, u'icon_type': u'QSFP_PLUS', u'default_name': u'P1-01', u'enabled': False, u'supports_erspan_strip': False, u'mod_count': 21, u'timestamp_settings': None, u'erspan_strip_settings': None, u'mode': u'NETWORK', u'supports_gtp_flow_distribution': False, u'source_filter_list': [], u'filter_mode': u'PASS_ALL', u'std_vlan_strip_settings': {u'ingress_count': 0, u'egress_count': 0, u'enabled': False, u'strip_mode': None}, u'history': []}
        """
        return self._callServer('GET', '/api/ports/' + port)
    
    def modifyPort(self, port_id, argsAPI):
        """ modifyPort :
        Update the properties of a port.

        Sample usage:
        >>> nto.modifyPort('58', {'mode': 'TOOL'})
        ''
        """
        return self._callServer('PUT', '/api/ports/' + port_id, argsAPI, False)
    
    def searchPorts(self, argsAPI):
        """ searchPorts :
        Search for a specific port in the system by certain properties.

        Sample usage:
        >>> nto.searchPorts({'mode': 'TOOL'})
        [{u'id': 58, u'name': u'P1-01'}]
        """
        return self._callServer('POST', '/api/ports/search', argsAPI)
    
    def getPortProperties(self, port, properties):
        """ getPortProperties :
        Fetch one or more properties of a port object which is specified by its
        port_id_or_name.
            
        Sample usage:
        >>> nto.getPortProperties('PB07', 'enabled,link_status')
        {u'enabled': True, u'link_status': {u'duplex': u'FULL', u'pause': u'DISABLED', u'speed': u'10G', u'link_up': True}}
        """
        return self._callServer('GET', '/api/ports/' + port + '?properties=' + properties)
    
    def getPortProperty(self, port, property):
        """ getPortProperty :
        Fetch a property of a port object which is specified by its
        port_id_or_name.

        Sample usage:
        >>> nto.getPortProperty('PB07', 'enabled')
        {u'enabled': True}
        """
        return self._callServer('GET', '/api/ports/' + port + '?properties=' + property)[property]

    ###################################################
    # Recirculated AFM resources
    ###################################################
    def disableAfm(self, afm_id, argsAPI):
        """ disableAfm :
        Disables an recirculated AFM by disconnecting the attached port, port group or filter.

        Sample usage:
        >>> nto.disableAfm('96', {'object_id': '53'})
        ''
        """
        return self._callServer('PUT', '/api/recirculated_afm_resources/' + afm_id + '/disable', argsAPI, False)

    def enableAfm(self, afm_id, argsAPI):
        """ enableAfm :
        Enables an recirculated AFM by attaching a port, port group or filter to it.

        Sample usage:
        >>> nto.enableAfm('96', {'allocated_bandwidth': 10, 'object_id': '53', 'port_mode': 'NETWORK'})
        ''
        """
        return self._callServer('PUT', '/api/recirculated_afm_resources/' + afm_id + '/enable', argsAPI, False)

    def getBandwidthDetailsAfm(self, afm_id):
        """ getBandwidthDetailsAfm :
        Gets the bandwidth details for the Recirculated AFM resource.

        Sample usage:
        >>> nto.getBandwidthDetailsAfm('96')
        {u'allocated_bandwidth': 20, u'total_bandwidth': 160, u'available_bandwidth': 140, u'bandwidth_increment': 10}
        """
        return self._callServer('PUT', '/api/recirculated_afm_resources/' + afm_id + '/get_bandwidth_details', {})

    def getAfm(self, afm_id):
        """ getAfm :
        Fetch the properties of a recirculated AFM object.

        Sample usage:
        >>> nto.getAfm('96')
        {u'description': u'AFM Resources', u'lane_config_list': [{u'allocated_bandwidth': 10, u'attachment_id': u'52', u'attachment_type': u'PORT'}, {u'allocated_bandwidth': 10, u'attachment_id': u'53', u'attachment_type': u'PORT'}], u'capture_source': None, u'lineboard_id': None, u'default_name': u'L1-AFM', u'resource_status': u'READY', u'name': u'L1-AFM', u'mod_count': 20, u'license_status': u'NOT_PRESENT', u'capture_port_group': None, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'id': 96, u'connect_disconnect_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'history': [{u'type': u'MODIFY', u'time': 1497393506254, u'caused_by': u'admin', u'details': None, u'props': [u'DESCRIPTION']}]}

        >>> nto.getAfm('L1-AFM')
        {u'description': u'AFM Resources', u'lane_config_list': [{u'allocated_bandwidth': 10, u'attachment_id': u'52', u'attachment_type': u'PORT'}, {u'allocated_bandwidth': 10, u'attachment_id': u'53', u'attachment_type': u'PORT'}], u'capture_source': None, u'lineboard_id': None, u'default_name': u'L1-AFM', u'resource_status': u'READY', u'name': u'L1-AFM', u'mod_count': 20, u'license_status': u'NOT_PRESENT', u'capture_port_group': None, u'modify_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'id': 96, u'connect_disconnect_access_settings': {u'policy': u'ALLOW_ALL', u'groups': []}, u'history': [{u'type': u'MODIFY', u'time': 1497393506254, u'caused_by': u'admin', u'details': None, u'props': [u'DESCRIPTION']}]}

        """
        return self._callServer('GET', '/api/recirculated_afm_resources/' + afm_id)

    def getAllAfms(self):
        """ getAllAfms :
        Fetch a list containing the summaries for all the recirculated AFM resources in the system.

        Sample usage:
        >>> nto.getAllAfms()
        [{u'id': 96, u'name': u'L1-AFM'}]
        """
        return self._callServer('GET', '/api/recirculated_afm_resources')

    def searchAfm(self, argsAPI):
        """ searchAfm :
        Search for a specific recirculated AFM resource in the system by certain properties.

        Sample usage:
        >>> nto.searchAfm({'description': 'AFM Resources'})
        [{u'id': 96, u'name': u'L1-AFM'}]
        """
        return self._callServer('POST', '/api/recirculated_afm_resources/search', argsAPI)

    def modifyAfm(self, afm_id, argsAPI):
        """ modifyAfm:
        Update the properties of an existing recirculated AFM resource.

        Sample usage:
        >>> nto.modifyAfm('96', {'description': 'Shared AFM Resources'})
        ''
        """
        return self._callServer('PUT', '/api/recirculated_afm_resources/' + afm_id, argsAPI, False)

    ####################################
    # Statistics
    ####################################
    def getStats(self, argsAPI):
        """ getStats :
        Retrieve a stats snapshot containing the specified objects.

        Sample usage:
        >>> nto.getStats({'stat_name': ['np_peak_gtp_v2_deleted_sessions_time', 'np_total_rx_count_valid_packets'], 'port_group': '91'})
        {u'stats_snapshot': [{u'np_peak_gtp_v2_deleted_sessions_time': 1441391232493, u'reset_by': u'null', u'reset_time': 1441390286194, u'default_name': u'PG1', u'stats_time': 1441391232493, u'np_total_rx_count_valid_packets': 0, u'type': u'Port Group', u'id': u'91'}]}
        """
        return self._callServer('POST', '/api/stats', argsAPI)
    
    def resetStats(self, argsAPI):
        """ resetStats :
        Reset the stats for a set of specific NTO ports, port groups, and/or filters.

        Sample usage:
        >>> nto.resetStats({'PORT': [59], 'PORT_GROUP': [405]})
        {}
        """
        return self._callServer('POST', '/api/stats/reset', argsAPI)
    
    def getManagementStats(self):
        """ getManagementStats :
        Returns the statistics for active management port.
            
        Sample usage:
        """
        return self._callServer('POST', '/api/stats/mgmt_port', None)

    def resetDrops(self, argsAPI):
        """ resetDrops :
        Reset the overflow drop counts for a set of specific NTO tool ports and/or output port groups.

        Sample usage:
        >>> nto.resetDrops({'PORT': [58]})
        {u'reset_drops_attempt_count': 134, u'reset_drops_success_count': 118}
        """
        return self._callServer('POST', '/api/stats/reset_drops', argsAPI)
    
    ####################################
    # System
    ####################################
    def getSpecificSystem(self, system_id):
        """ getSpecificSystem :
        Retrieve the properties of the system specified.
            
        Sample usage:
            >>> nto.getSystem()
            {u'mgmt_port2_link_status': {u'duplex': u'FULL', u'active_port': False, u'speed': u'1G', u'link_up': True}, u'union_mode': u'INDEPENDENT', u'timestamp_config': {u'time_source': u'LOCAL'}, u'fan_failure_count': 0, u'web_api_config': {u'enabled': True, u'port': 9000, u'token_timeout': {u'value': 10, u'unit': u'MIN'}}, u'session_timeout_interval': 0,
            <snip>
            """
        return self._callServer('GET', '/api/system/' + system_id)

    def getSystem(self):
        """ getSystem :
        Retrieve the properties of the system.

        Sample usage:
        >>> nto.getSystem()
        {u'mgmt_port2_link_status': {u'duplex': u'FULL', u'active_port': False, u'speed': u'1G', u'link_up': True}, u'union_mode': u'INDEPENDENT', u'timestamp_config': {u'time_source': u'LOCAL'}, u'fan_failure_count': 0, u'web_api_config': {u'enabled': True, u'port': 9000, u'token_timeout': {u'value': 10, u'unit': u'MIN'}}, u'session_timeout_interval': 0,
            <snip>
        """
        return self._callServer('GET', '/api/system')

    def getSystemProperties(self, properties):
        """ getSystemProperties :
        Fetch one or more systen properties.

        Sample usage:
        >>> nto.getSystemProperties('snmp_config,dns_config')
        {u'dns_config': {u'suffix1': None, u'suffix2': None, u'primary_server': None, u'alt_server': None}, u'snmp_config': {u'trap_recipients': [{u'remote_user': None, u'traps': [u'COLD_START', u'WARM_START', u'LINK_UP_DOWN', u'TEST_NOTIFICATION'], u'retry_count': 1, u'host': {u'value': u'155.174.7.97'}, u'version': u'V2', u'community_string': u'V2/155.174.7.97:162', u'timeout': 5, u'port': 162}], u'refresh_time': 1, u'gets_enabled': True, u'traps_enabled': True, u'get_access': [{u'version': u'V2', u'community_string': u'AnueComm4ATSro', u'local_user': None}]}}
        """
        return self._callServer('GET', '/api/system?properties=' + properties)
        
    def getSystemProperty(self, property):
        """ getSystemProperty :
        Fetch a systen property.
            
        Sample usage:
        >>> nto.getSystemProperty('snmp_config')
        {u'trap_recipients': [{u'remote_user': None, u'traps': [u'COLD_START', u'WARM_START', u'LINK_UP_DOWN', u'TEST_NOTIFICATION'], u'retry_count': 1, u'host': {u'value': u'155.174.7.97'}, u'version': u'V2', u'community_string': u'V2/155.174.7.97:162', u'timeout': 5, u'port': 162}], u'refresh_time': 1, u'gets_enabled': True, u'traps_enabled': True, u'get_access': [{u'version': u'V2', u'community_string': u'AnueComm4ATSro', u'local_user': None}]}
        """
        return self._callServer('GET', '/api/system?properties=' + property)[property]
    
    def modifySystem(self, argsAPI):
        """ modifySystem :
        Update the system properties.

        Sample usage:
        >>> nto.modifySystem({'system_info': {u'location': 'Austin', u'name': 'The Big Box'}})
        ''
        """
        return self._callServer('PUT', '/api/system', argsAPI, False)

    def modifySpecificSystem(self, system_id, argsAPI):
        """ modifySpecificSystem :
        Update the properties of the system specified.
        
        Sample usage:
        >>> nto.modifySystem({'system_info': {u'location': 'Austin', u'name': 'The Big Box'}})
        ''
        """
        return self._callServer('PUT', '/api/system/' + system_id, argsAPI, False)
        
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
        return self._callServer('GET', '/api/users')

    def getUser(self, user):
        """ getUser :
        Fetch a list containing the summaries for all the users in the system, or
        if a user ID is specified, fetch the properties of that user object.

        Sample usage:
        >>> nto.getUser('tcl')
        {u'login_id': u'tcl', u'session_type': None, u'created': {u'type': u'CREATE', u'caused_by': u'admin', u'details': None, u'time': 1442436968401}, u'is_sysadm': True, u'phone': u'867-53009', u'email': u'tcl@nto.com', u'mod_count': 0, u'is_logged_in': False, u'full_name': u'tcl', u'authentication_mode': u'LOCAL', u'id': 52, u'history': []}
        """
        return self._callServer('GET', '/api/users/' + user)

    def changePasswordUser(self, user_id, argsAPI):
        """ changePasswordUser :
        Change the user password.

        Sample usage:
        >>> nto.changePasswordUser('tcl1', {'new_password' : 'tcl1', 'old_password' : 'fredMota@123'})
        ''
        """
        return self._callServer('PUT', '/api/users/' + user_id + '/change_password', argsAPI, False)

    def createUser(self, argsAPI):
        """ createUser :
        Create a new user.

        Sample usage:
        >>> nto.createUser({'login_id': 'oper', 'is_sysadm': False, 'password': 'oper'})
        {u'id': u'54'}
        """
        return self._callServer('POST', '/api/users', argsAPI)

    def modifyUser(self, user_id, argsAPI):
        """ modifyUser :
        Update the properties of an existing user.

        Sample usage:
        >>> nto.modifyUser('oper', {'password': '***'})
        ''
        """
        return self._callServer('PUT', '/api/users/' + user_id, argsAPI, False)

    def deleteUser(self, user_id):
        """ deleteUser :
        Remove a user from the system. The user is specified by an user_id.

        Sample usage:
        >>> nto.deleteUser('54')
        ''
        """
        return self._callServer('DELETE', '/api/users/' + user_id, None, False)

    def searchUsers(self, argsAPI):
        """ searchUsers :
        Search a specific user from the system by certain properties.

        Sample usage:
        >>> nto.searchUsers({'is_sysadm': False})
        [{u'id': 54, u'name': u'oper'}]
        """
        return self._callServer('POST', '/api/users/search', argsAPI)

    ####################################
    # Search
    ####################################
    def search(self, entity_type, argsAPI):
        """ search :
        Search an entity.

        Sample usage:
        >>> nto.search('port_groups', {'mode': 'NETWORK'})
        [{u'id': 94, u'name': u'GSC Network Ports PB09-PB16'}, {u'id': 92, u'name': u'GSC Network Ports PB01-PB08'}, {u'id': 91, u'name': u'GSC Network Ports PA01-PA08'}, {u'id': 95, u'name': u'GSC Network Ports PA09-PA16'}]
        """
        return self._callServer('POST', '/api/' + entity_type + '/search', argsAPI)
