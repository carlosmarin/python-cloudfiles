"""
authentication operations

Authentication instances are used to interact with the remote
authentication service, retreiving storage system routing information
and session tokens.

See COPYING for license information.
"""

from httplib  import HTTPSConnection, HTTPConnection
from sys      import version_info

from utils    import parse_url, THTTPConnection, THTTPSConnection
from cloudfiles.errors import ResponseError, AuthenticationError, AuthenticationFailed
from cloudfiles.fjson import json_loads
from consts   import user_agent, us_authurl, object_store_service_name, object_cdn_service_name

INVALID_RESP_MSG = "Invalid response from the authentication service."

class BaseAuthentication(object):
    """
    The base authentication class from which all others inherit.
    """
    def __init__(self, username, api_key, authurl=us_authurl, timeout=15,
                 useragent=user_agent,  auth_version=None, storage_region=None, servicenet=None):
        self.authurl = authurl
        self.auth_version = auth_version
        self.storage_region = storage_region
        self.servicenet = servicenet
        self.headers = dict()
        self.headers['x-auth-user'] = username
        self.headers['x-auth-key'] = api_key
        self.headers['User-Agent'] = useragent
        self.timeout = timeout
        (self.host, self.port, self.uri, self.is_ssl) = parse_url(self.authurl)
        if version_info[0] <= 2 and version_info[1] < 6:
            self.conn_class = self.is_ssl and THTTPSConnection or \
                THTTPConnection
        else:
            self.conn_class = self.is_ssl and HTTPSConnection or HTTPConnection

    def authenticate(self):
        """
        Initiates authentication with the remote service and returns a
        two-tuple containing the storage system URL and session token.

        Note: This is a dummy method from the base class. It must be
        overridden by sub-classes.
        """
        return (None, None, None)


class MockAuthentication(BaseAuthentication):
    """
    Mock authentication class for testing
    """
    def authenticate(self):
        return ('http://localhost/v1/account', None, 'xxxxxxxxx')


class Authentication(BaseAuthentication):
    """
    Authentication, routing, and session token management.
    """
    def authenticate(self):
        """
        Initiates authentication with the remote service and returns a
        two-tuple containing the storage system URL and session token.
        """
        conn = self.conn_class(self.host, self.port, timeout=self.timeout)

        if self.auth_version == '2.0':
            self.headers['content-type'] = 'application/json'
            self.headers['accept'] = 'application/json'
            body = '{"auth":{"RAX-KSKEY:apiKeyCredentials":{"username":"%s","apiKey":"%s"}}}' \
                   % (self.headers['x-auth-user'], self.headers['x-auth-key'])
            conn.request('POST', '/' + self.uri, body=body, headers=self.headers)
        else:
            conn.request('GET', '/' + self.uri, headers=self.headers)

        response = conn.getresponse()
        data = response.read()

        # A status code of 401 indicates that the supplied credentials
        # were not accepted by the authentication service.
        if response.status == 401:
            raise AuthenticationFailed()

        # Raise an error for any response that is not 2XX
        if response.status // 100 != 2:
            raise ResponseError(response.status, response.reason)

        storage_url = cdn_url = auth_token = None

        if self.auth_version == '2.0':
            try:
                data = json_loads(data)

                auth_token = data['access']['token']['id']

                # FIXME (Carlos): Improve ...
                for service in data['access']['serviceCatalog']:
                    if service['name'] == object_store_service_name:
                        endpoints = service['endpoints']
                        if self.storage_region is None and len(endpoints) > 0:
                            # First endpoint is the single 'x-storage-url' returned in Rackspace Auth v1.0
                            storage_url = endpoints[0]['internalURL' if self.servicenet else 'publicURL']
                            break
                        else:
                            for ep in endpoints:
                                if ep['region'] == self.storage_region:
                                    storage_url = ep['internalURL' if self.servicenet else 'publicURL']
                                    break

                    if service['name'] == object_cdn_service_name:
                        endpoints = service['endpoints']
                        if self.storage_region is None and len(endpoints) > 0:
                            cdn_url = endpoints[0]['publicURL']
                        else:
                            for ep in endpoints:
                                if ep['region'] == self.storage_region:
                                    cdn_url = ep['publicURL']
                                    break
            except:
                raise AuthenticationError(INVALID_RESP_MSG)

            if storage_url is None and self.storage_region:
                raise AuthenticationError('Unable to get Storage URL for region: "%s"' % self.storage_region)

        else:
            for hdr in response.getheaders():
                if hdr[0].lower() == "x-storage-url":
                    storage_url = hdr[1]
                if hdr[0].lower() == "x-cdn-management-url":
                    cdn_url = hdr[1]
                if hdr[0].lower() == "x-storage-token":
                    auth_token = hdr[1]
                if hdr[0].lower() == "x-auth-token":
                    auth_token = hdr[1]

        conn.close()

        if not (auth_token and storage_url):
            raise AuthenticationError(INVALID_RESP_MSG)

        return (storage_url, cdn_url, auth_token)

# vim:set ai ts=4 sw=4 tw=0 expandtab:
