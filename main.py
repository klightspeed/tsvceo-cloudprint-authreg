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

from google.appengine.ext import ndb

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    autoescape=True,
    extensions=['jinja2.ext.autoescape'])

class PrintServer(ndb.Model):
    printerid = ndb.StringProperty(required=True)
    authserver = ndb.StringProperty(required=True)

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

        logging.info("Registering printer " + printerid + " for server " + authserver)

        if printerid is not None and authserver is not None:
            registerServerForPrinter(printerid, authserver)
            self.response.write('OK')
            return

        self.abort(400)

class MainHandler(webapp2.RequestHandler):
    def get(self):
        variables = {}
        template = JINJA_ENVIRONMENT.get_template('main.html')
        self.response.write(template.render(variables))

app = webapp2.WSGIApplication(
    [
        ('/', MainHandler),
        ('/register', RegisterHandler),
        ('/query', QueryHandler)
    ],
    debug=True
    )

