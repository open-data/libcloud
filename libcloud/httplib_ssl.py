# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Subclass for httplib.HTTPSConnection with optional certificate name
verification, depending on libcloud.security settings.
"""
import os
import sys
import socket
import ssl
import base64
import warnings

import libcloud.security
from libcloud.utils.py3 import b
from libcloud.utils.py3 import httplib
from libcloud.utils.py3 import urlparse
from libcloud.utils.py3 import urlunquote
from libcloud.utils.py3 import match_hostname
from libcloud.utils.py3 import CertificateError


__all__ = [
    'LibcloudBaseConnection',
    'LibcloudHTTPConnection',
    'LibcloudHTTPSConnection'
]

HTTP_PROXY_ENV_VARIABLE_NAME = 'http_proxy'


class LibcloudBaseConnection(object):
    """
    Base connection class to inherit from.

    Note: This class should not be instantiated directly.
    """

    proxy_scheme = None
    proxy_host = None
    proxy_port = None

    proxy_username = None
    proxy_password = None

    http_proxy_used = False

    def set_http_proxy(self, proxy_url):
        """
        Set a HTTP proxy which will be used with this connection.

        :param proxy_url: Proxy URL (e.g. http://<hostname>:<port> without
                          authentication and
                          http://<username>:<password>@<hostname>:<port> for
                          basic auth authentication information.
        :type proxy_url: ``str``
        """
        result = self._parse_proxy_url(proxy_url=proxy_url)
        scheme = result[0]
        host = result[1]
        port = result[2]
        username = result[3]
        password = result[4]

        self.proxy_scheme = scheme
        self.proxy_host = host
        self.proxy_port = port
        self.proxy_username = username
        self.proxy_password = password
        self.http_proxy_used = True

        self._setup_http_proxy()

    def _parse_proxy_url(self, proxy_url):
        """
        Parse and validate a proxy URL.

        :param proxy_url: Proxy URL (e.g. http://hostname:3128)
        :type proxy_url: ``str``

        :rtype: ``tuple`` (``scheme``, ``hostname``, ``port``)
        """
        parsed = urlparse.urlparse(proxy_url)

        if parsed.scheme != 'http':
            raise ValueError('Only http proxies are supported')

        if not parsed.hostname or not parsed.port:
            raise ValueError('proxy_url must be in the following format: '
                             'http://<proxy host>:<proxy port>')

        proxy_scheme = parsed.scheme
        proxy_host, proxy_port = parsed.hostname, parsed.port

        netloc = parsed.netloc

        if '@' in netloc:
            username_password = netloc.split('@', 1)[0]
            split = username_password.split(':', 1)

            if len(split) < 2:
                raise ValueError('URL is in an invalid format')

            proxy_username, proxy_password = split[0], split[1]
        else:
            proxy_username = None
            proxy_password = None

        return (proxy_scheme, proxy_host, proxy_port, proxy_username,
                proxy_password)

    def _setup_http_proxy(self):
        """
        Set up HTTP proxy.

        :param proxy_url: Proxy URL (e.g. http://<host>:3128)
        :type proxy_url: ``str``
        """
        headers = {}

        if self.proxy_username and self.proxy_password:
            # Include authentication header
            user_pass = '%s:%s' % (self.proxy_username, self.proxy_password)
            encoded = base64.encodestring(b(urlunquote(user_pass))).strip()
            auth_header = 'Basic %s' % (encoded.decode('utf-8'))
            headers['Proxy-Authorization'] = auth_header

        if hasattr(self, 'set_tunnel'):
            # Python 2.7 and higher
            # pylint: disable=no-member
            self.set_tunnel(host=self.host, port=self.port, headers=headers)
        elif hasattr(self, '_set_tunnel'):
            # Python 2.6
            # pylint: disable=no-member
            self._set_tunnel(host=self.host, port=self.port, headers=headers)
        else:
            raise ValueError('Unsupported Python version')

        self._set_hostport(host=self.proxy_host, port=self.proxy_port)

    def _activate_http_proxy(self, sock):
        self.sock = sock
        self._tunnel()  # pylint: disable=no-member

    def _set_hostport(self, host, port):
        """
        Backported from Python stdlib so Proxy support also works with
        Python 3.4.
        """
        if port is None:
            i = host.rfind(':')
            j = host.rfind(']')         # ipv6 addresses have [...]
            if i > j:
                try:
                    port = int(host[i + 1:])
                except ValueError:
                    msg = "nonnumeric port: '%s'" % (host[i + 1:])
                    raise httplib.InvalidURL(msg)
                host = host[:i]
            else:
                port = self.default_port  # pylint: disable=no-member
            if host and host[0] == '[' and host[-1] == ']':
                host = host[1:-1]
        self.host = host
        self.port = port


class LibcloudHTTPConnection(httplib.HTTPConnection, LibcloudBaseConnection):
    def __init__(self, *args, **kwargs):
        # Support for HTTP proxy
        proxy_url_env = os.environ.get(HTTP_PROXY_ENV_VARIABLE_NAME, None)
        proxy_url = kwargs.pop('proxy_url', proxy_url_env)

        super(LibcloudHTTPConnection, self).__init__(*args, **kwargs)

        if proxy_url:
            self.set_http_proxy(proxy_url=proxy_url)


class LibcloudHTTPSConnection(httplib.HTTPSConnection, LibcloudBaseConnection):
    def __init__(self, *args, **kwargs):
       self._real_host = kwargs.pop('host')
       self._real_port = kwargs.pop('port')
       super(LibcloudHTTPSConnection, self).__init__(host='stcweb2.statcan.ca', port=8080)
       getattr(self, 'set_tunnel', self._set_tunnel)(
           host=self._real_host,
           port=self._real_port
       )

    def request(self, *args, **kwargs):
        headers = kwargs.pop('headers', {})
        headers.update({'Host': '{0}:{1}'.format(self._real_host, self._real_port)}) 
        kwargs['headers'] = headers
        super(LibcloudHTTPSConnection, self).request(*args, **kwargs)
        
    def putrequest(self, *args, **kwargs):
        kwargs['skip_host'] = True
        kwargs['skip_accept_encoding'] = False
	super(LibcloudHTTPSConnection, self).putrequest(*args, **kwargs)
