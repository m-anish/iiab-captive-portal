#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is a skeleton file that can serve as a starting point for a Python
console script. To run this script uncomment the following line in the
entry_points section in setup.py:

    [console_scripts]
    fibonacci = iiab_captive_portal.skeleton:run

Then run `python setup.py install` which will install the command `fibonacci`
inside your current environment.
Besides console scripts, the header (i.e. until _logger...) of this file can
also be used as template for Python modules.

Note: This skeleton file can be safely removed if not needed!
"""
from __future__ import division, print_function, absolute_import

import argparse
import sys
import logging
import subprocess
import http.server
import cgi
import configparser

from iiab_captive_portal import __version__

__author__ = "Anish Mangal"
__copyright__ = "Anish Mangal"
__license__ = "gpl3"

_logger = logging.getLogger(__name__)

config = {}

class CaptivePortal(http.server.BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        global config
        #this is the index of the captive portal
        #it simply redirects the user to the to login page
        html_redirect = """
        <html>
        <head>
            <meta http-equiv="refresh" content="0; url=http://%s:%s/login" />
        </head>
        <body>
            <b>Redirecting to login page</b>
        </body>
        </html>
        """%(config['ip_address'], config['port'])
        #the login page
        html_login = """
        <html>
        <body>
            <b>Login Form</b>
            <form method="POST" action="do_login">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """
    
    '''
    if the user requests the login page show it, else
    use the redirect page
    '''
    def do_GET(self):
        path = self.path
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        if path == "/login":
            self.wfile.write(self.html_login)
        else:
            self.wfile.write(self.html_redirect)
    '''
    this is called when the user submits the login form
    '''
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        form = cgi.FieldStorage()
        #form = cgi.FieldStorage(
        #    fp=self.rfile, 
        #    headers=self.headers,
        #    environ={'REQUEST_METHOD':'POST',
        #             'CONTENT_TYPE':self.headers['Content-Type'],
        #             })
        username = form.getvalue("username")
        password = form.getvalue("password")
        #dummy security check
        if username == config['username'] and password == config['password']:
            #authorized user
            remote_IP = self.client_address[0]
            print('New authorization from '+ remote_IP)
            print('Updating IP tables')
            subprocess.call(["iptables","-t", "nat", "-I", "PREROUTING","1", "-s", remote_IP, "-j" ,"ACCEPT"])
            subprocess.call(["iptables", "-I", "FORWARD", "-s", remote_IP, "-j" ,"ACCEPT"])
            self.wfile.write("You are now authorized. Navigate to any URL")
        else:
            #show the login form
            self.wfile.write(self.html_login)
        


def fib(n):
    """Fibonacci example function

    Args:
      n (int): integer

    Returns:
      int: n-th Fibonacci number
    """
    assert n > 0
    a, b = 1, 1
    for i in range(n-1):
        a, b = b, a+b
    return a


def parse_config(config_file):
    _logger.debug("In method parse_config")
    global config
    try:
        _logger.debug("Attempting to read configuration from %s" % config_file)
        parser = configparser.ConfigParser()
        parser.read(config_file)
        config['username'] = parser.get('captive-server', 'username')
        config['password'] = parser.get('captive-server', 'password')
        config['iface'] = parser.get('captive-server', 'iface')
        config['port'] = int(parser.get('captive-server', 'port'))
        config['ip_address'] = parser.get('captive-server', 'ip_address')
        return True
    except configparser.ParsingError as err:
        _logger.error('Could not parse:', err)
        return False    


def parse_args(args):
    """Parse command line parameters

    Args:
      args ([str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(
        description="A simple python and iptables based captive portal server for the IIAB project")
    parser.add_argument(
        '--version',
        action='version',
        version='iiab-captive-portal {ver}'.format(ver=__version__))
    parser.add_argument(
        '-c',
        '--conf',
        nargs='?',
        const="/etc/captive_server.conf",
        dest="config_path",
        help="path to config file. defaults to /etc/captive_server.conf",
        type=str,
        metavar="STR")
    parser.add_argument(
        '-v',
        '--verbose',
        dest="loglevel",
        help="set loglevel to INFO",
        action='store_const',
        const=logging.INFO)
    parser.add_argument(
        '-vv',
        '--very-verbose',
        dest="loglevel",
        help="set loglevel to DEBUG",
        action='store_const',
        const=logging.DEBUG)
    return parser.parse_args(args)


def setup_logging(loglevel):
    """Setup basic logging

    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(level=loglevel, stream=sys.stdout,
                        format=logformat, datefmt="%Y-%m-%d %H:%M:%S")


def main(args):
    """Main entry point allowing external calls

    Args:
      args ([str]): command line parameter list
    """
    global config
    args = parse_args(args)
    setup_logging(args.loglevel)
    parse_config(str(args.config_path))
    httpd = http.server.HTTPServer(('',config['port']), CaptivePortal)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    
    #_logger.debug("Starting crazy calculations...")
    #print("The {}-th Fibonacci number is {}".format(args.n, fib(args.n)))
    _logger.info("Script ends here")


def run():
    """Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
