#!/usr/bin/env python

import os
import time
import logging
import socket
import argparse
import ssl
from base64 import b64encode

try:
    # python 2 imports
    from BaseHTTPServer import HTTPServer
    from BaseHTTPServer import BaseHTTPRequestHandler
    from httplib import HTTPConnection
    from httplib import HTTPSConnection
    from SocketServer import ForkingMixIn
    from urlparse import urlparse
    from urlparse import ParseResult
    from urlparse import urlunparse

except ImportError:
    # python 3 imports
    from http.server import HTTPServer
    from http.server import BaseHTTPRequestHandler
    from http.client import HTTPConnection
    from http.client import HTTPSConnection
    from socketserver import ForkingMixIn
    from urllib.parse import urlparse
    from urllib.parse import ParseResult
    from urllib.parse import urlunparse


def human_size(byte_len):
    """ Get a human readable size description for the given number of bytes.

    :type byte_len: int
    :param byte_len: Amount of bytes.

    :rtype: str
    :return: Human readable size description.
    """
    suffixes = ('B', 'KB', 'MB', 'GB', 'TB', 'PB')
    if byte_len == 0:
        return '0 B'
    index = 0
    while byte_len >= 1024 and index < len(suffixes) - 1:
        byte_len /= 1024.
        index += 1
    return '%s %s' % (('%.2f' % byte_len).rstrip('0').rstrip('.'), suffixes[index])


class ForkingHTTPServer(ForkingMixIn, HTTPServer):

    def __init__(self, server_address, request_handler_class, proxy_target, host_header):

        assert isinstance(proxy_target, ParseResult)
        assert proxy_target.scheme in ('http', 'https', '')

        if proxy_target.scheme == 'https':
            # disable client ssl verification
            ssl._create_default_https_context = ssl._create_unverified_context

        self.proxy_target = proxy_target
        self.host_header = host_header
        HTTPServer.__init__(self, server_address, request_handler_class)


class Proxy(BaseHTTPRequestHandler):

    def log_request(self, code=None, size=None):
        # disable BaseHTTPRequestHandler logging
        pass

    def handle(self):
        # overwrite this method as workaround for a bug in python 2.7 (http://bugs.python.org/issue14574)
        try:
            return BaseHTTPRequestHandler.handle(self)
        except socket.error:
            logging.debug("%s %s [connection reset]", self.command, self.path)

    def finish(self):
        # overwrite this method as workaround for a bug in python 2.7 (http://bugs.python.org/issue14574)
        try:
            return BaseHTTPRequestHandler.finish(self)
        except socket.error:
            logging.debug("%s %s [connection reset]", self.command, self.path)

    def handle_one_request(self):

        try:
            start_time = time.time()

            try:
                # noinspection PyAttributeOutsideInit
                self.command, self.path, self.request_version = \
                    self.rfile.readline().decode().strip().split(' ', 2)
            except ValueError:
                return

            target_netloc = self.server.proxy_target.netloc

            if '@' in target_netloc:
                # split authentication information from target description
                target_auth, target_netloc = target_netloc.split('@', 1)
            else:
                target_auth, target_netloc = None, target_netloc

            if ':' in target_netloc:
                # split host / port information from target description
                target_host, target_port = target_netloc.rsplit(':', 1)
            else:
                target_host, target_port = target_netloc, None  # port fallback to 80 / 443

            if self.server.proxy_target.scheme == 'https':
                client = HTTPSConnection(target_host, target_port)
            else:
                client = HTTPConnection(target_host, target_port)

            client.connect()
            client.putrequest(self.command, self.server.proxy_target.path + self.path, skip_host=True)

            request_host = ''
            request_content_length = 0
            request_line = self.rfile.readline()
            while request_line and b':' in request_line:

                # walk through the request header lines and pass them to the server connection
                key, value = request_line.split(b':', 1)
                unified_key = key.decode().lower()

                if unified_key == 'authorization':
                    # if there is an authorization in the request: ignore the given information
                    target_auth = None

                elif unified_key == 'content-length':
                    request_content_length = int(value.strip())

                elif unified_key == 'host':
                    request_host = value.strip()
                    # replace the requested host header with the wanted one
                    value = self.server.host_header if self.server.host_header else target_host

                client.putheader(key, value.strip())

                request_line = self.rfile.readline()

            if target_auth:
                client.putheader('Authorization', 'Basic %s' % b64encode(target_auth))

            client.endheaders()

            # pass the request body to the server connection
            for _ in range(request_content_length // 1024):
                client.send(self.rfile.read(1024))
            client.send(self.rfile.read(request_content_length % 1024))

            response = client.getresponse()

            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():

                # walk through the response header lines and pass them to the client connection
                unified_key = key.lower()

                if unified_key == 'location':

                    # try to modify the location header to keep the browser requesting the proxy
                    redirect = list(urlparse(value))
                    if redirect[1]:
                        redirect[0], redirect[1] = 'http', request_host
                        logging.warning("REWRITE %s: %s -> %s", key, value, urlunparse(redirect))

                    self.send_header(key, urlunparse(redirect))

                elif unified_key not in ('keep-alive', 'connection'):
                    # its hard to support persistent connections properly because we open a
                    # new connection for every request, so disable it completely
                    self.send_header(key, value)

            self.end_headers()

            try:
                # pass the response body to the client connection
                chunk = True
                response_size = 0
                while chunk:
                    chunk = response.read(1024)
                    response_size += len(chunk)
                    self.wfile.write(chunk)

                self.wfile.flush()

            except socket.error:
                logging.debug("%s %s [connection reset, %.2fs]",
                              self.command, self.path,
                              time.time() - start_time)

            else:
                logging.info("%s %s [%s, %s, %.2fs]",
                             self.command, self.path,
                             response.status, human_size(response_size),
                             time.time() - start_time)

            finally:
                client.close()

        except KeyboardInterrupt:
            pass


def serve(target, listening_host='', listening_port=8080, host_header=None):
    """ Start a host modifying hos proxy.

    :type target: str
    :param target: Complete url like "http://sub.domain.tld/path/" to redirect to.

    :type listening_host: str
    :param listening_host: Host to listen on. Defaults to '' what means to listen
        on all addresses.

    :type listening_port: int
    :param listening_port: Port to listen on.

    :type host_header: str or None
    :param host_header: Host header to set instead of the one in `target` url.
    """

    proxy_target = urlparse(target if '://' in target else 'http://' + target)
    httpd = ForkingHTTPServer(server_address=(listening_host, listening_port),
                              request_handler_class=Proxy,
                              proxy_target=proxy_target,
                              host_header=host_header)

    logging.info("Listening on %s, Redirecting to %s",
                 ':'.join(map(str, httpd.server_address)),
                 urlunparse(proxy_target))

    try:
        httpd.serve_forever()

    except KeyboardInterrupt:
        logging.info('Received SIGINT. Exiting.')

    finally:
        try:
            httpd.server_close()
            httpd.shutdown()
            for pid in httpd.active_children:
                os.kill(pid, 9)
        except TypeError:
            pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Host Proxy',
                                     epilog='examples:\n'
                                            '  hoxy.py https://example.com/ \n'
                                            '  hoxy.py https://192.168.1.123/ example.com \n'
                                            '  hoxy.py https://user:password@example.com/ \n'
                                            '  hoxy.py https://user:password@192.168.1.123/ example.com \n',
                                     formatter_class=argparse.RawTextHelpFormatter)

    logging_group = parser.add_argument_group('logging')
    logging_group.add_argument('-o', '--logfile', type=str, default='', help='Log into file.')
    logging_group.add_argument('-d', '--debug', action="store_true", help='Be more verbose.')

    parser.add_argument('-a', '--address', type=str, default='', help='Address to listen on.')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to listen on.')

    parser.add_argument('target', nargs=1, type=str,
                        help='Target Host to connect to. This should be a complete url \n'
                             'like "http://sub.domain.tld/path/". The http and https schemes \n'
                             'are supported. In almost any case, the path will be empty \n'
                             'to avoid issues with redirects or cookies. \n'
                             '\n')
    parser.add_argument('host', nargs='?', type=str, default=None,
                        help='Host header to set in the requests. Defaults to host \n'
                             'part of target url.')

    args = parser.parse_args()

    logging.basicConfig(
        filename=args.logfile,
        format="%(asctime)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        level=logging.DEBUG if args.debug else logging.INFO)

    serve(args.target[0], args.address, args.port, args.host)
