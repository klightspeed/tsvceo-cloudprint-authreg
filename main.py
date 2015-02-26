#!/usr/bin/env python
#
# Copyright 2015 Townsville Catholic Education Office
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""TSVCEO Cloud Print Proxy Authentication Service Registration

"""

import webapp2
import jinja2
import os
import json
import logging
import binascii
import ipaddress

from google.appengine.ext import ndb
from google.appengine.api import users

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    autoescape=True,
    extensions=['jinja2.ext.autoescape'])

class PrintServer(ndb.Model):
    printerid = ndb.StringProperty(required=True)
    authserver = ndb.StringProperty(required=True)

class IPRangePermission(ndb.Model):
    ipver = ndb.IntegerProperty(required=True)
    startip = ndb.StringProperty(required=True)
    endip = ndb.StringProperty(required=True)

def getServerForPrinter(printerid):
    printserver = PrintServer.query(PrintServer.printerid == printerid).get()

    if printserver is not None:
        return printserver.authserver
    else:
        return None

def registerServerForPrinter(printerid, authserver):
    printserver = PrintServer.query(PrintServer.printerid == printerid).get()

    if printserver is None:
        printserver = PrintServer(printerid = printerid)

    printserver.authserver = authserver
    printserver.put()

def isIPAddressPermitted(ipstr):
    try:
        ipaddr = ipaddress.ip_address(unicode(ipstr))
        ipver = ipaddr.version
        iphex = binascii.hexlify(ipaddr.packed)

        for iprangeperm in IPRangePermission.query():
            if iprangeperm.ipver == ipver and iprangeperm.startip <= iphex and iprangeperm.endip >= iphex:
                return True

        return False

    except ValueError:
        return False

class QueryHandler(webapp2.RequestHandler):
    def get(self):
        printerid = self.request.get('printerid')

        if printerid is not None:
            response = {
                'printerid': printerid,
                'authserver': getServerForPrinter(printerid)
                }

            self.response.headers.add_header("Access-Control-Allow-Origin", "*")
            self.response.headers['Content-Type'] = 'application/json'
            self.response.write(json.dumps(response))
            return

        self.abort(400)

class RegisterHandler(webapp2.RequestHandler):
    def get(self):
        self.abort(400)

    def post(self):
        printerid = self.request.get('printerid')
        authserver = self.request.get('authserver')
        ipaddr = self.request.remote_addr

        logging.info("Registering printer " + printerid + " for server " + authserver + " from IP " + ipaddr)

        if isIPAddressPermitted(ipaddr):

            if printerid is not None and authserver is not None:
                registerServerForPrinter(printerid, authserver)
                self.response.write('OK')
                return

            self.abort(400)
        else:
            self.abort(403)

class AddIPRangeHandler(webapp2.RequestHandler):
    def get(self):
        self.abort(400)

    def post(self):
        user = users.get_current_user()

        if user and users.is_current_user_admin():
            startipstr = self.request.get('startip')
            endipstr = self.request.get('endip')

            if startipstr is not None and endipstr is not None:
                try:
                    startipaddr = ipaddress.ip_address(unicode(startipstr))
                    endipaddr = ipaddress.ip_address(unicode(endipstr))

                    if startipaddr.version != endipaddr.version:
                        self.abort(400)

                    startiphex = binascii.hexlify(startipaddr.packed)
                    endiphex = binascii.hexlify(endipaddr.packed)

                    if (endiphex < startiphex):
                        self.abort(400)

                    iprangeperm = IPRangePermission(ipver = startipaddr.version, startip = startiphex, endip = endiphex)
                    iprangeperm.put()

                    self.redirect('/')
                except:
                    self.abort(400)
            else:
                self.abort(400)


class RemoveIPRangeHandler(webapp2.RequestHandler):
    def get(self):
        self.abort(400)

    def post(self):
        user = users.get_current_user()

        if user and users.is_current_user_admin():
            rangeid = self.request.get('id')

            if rangeid is not None:
                rangekey = ndb.Key(IPRangePermission, int(rangeid))
                rangekey.delete()

            self.redirect('/')
        else:
            self.abort(403)

class MainHandler(webapp2.RequestHandler):
    def get(self):
        user = users.get_current_user()

        if user:
            if users.is_current_user_admin():
                iprangepermlist = IPRangePermission.query().fetch()
                iprangeperms = []

                for iprangeperm in iprangepermlist:
                    startipaddr = None
                    endipaddr = None

                    if iprangeperm.ipver == 4:
                        startipaddr = ipaddress.IPv4Address(binascii.unhexlify(iprangeperm.startip))
                        endipaddr = ipaddress.IPv4Address(binascii.unhexlify(iprangeperm.endip))
                    elif iprangeperm.ipver == 6:
                        startipaddr = ipaddress.IPv6Address(binascii.unhexlify(iprangeperm.startip))
                        endipaddr = ipaddress.IPv6Address(binascii.unhexlify(iprangeperm.endip))

                    if startipaddr is not None and endipaddr is not None:
                        iprangeperms.append({
                            'id': iprangeperm.key.id(),
                            'startip': str(startipaddr),
                            'endip': str(endipaddr)
                            })

                variables = {
                    'iprangeperms': iprangeperms
                    }
                template = JINJA_ENVIRONMENT.get_template('main.html')
                self.response.write(template.render(variables))
            else:
                self.abort(403)
        else:
            self.redirect(users.create_login_url('/'))

app = webapp2.WSGIApplication(
    [
        ('/', MainHandler),
        ('/addiprange', AddIPRangeHandler),
        ('/removeiprange', RemoveIPRangeHandler),
        ('/register', RegisterHandler),
        ('/query', QueryHandler)
    ],
    debug=True
    )

