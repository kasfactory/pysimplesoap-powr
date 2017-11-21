#!/usr/bin/python
# -*- coding: utf-8 -*-
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 3, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

"""Pythonic simple SOAP Client plugins for WebService Security extensions"""

from __future__ import unicode_literals
import sys

if sys.version > '3':
    basestring = unicode = str

import datetime
from decimal import Decimal
import os
import logging
import hashlib
import warnings

from . import __author__, __copyright__, __license__, __version__
from .simplexml import SimpleXMLElement

import random
import string
from hashlib import sha1


def randombytes(N):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))


# Namespaces:

WSSE_URI = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
WSU_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
XMLDSIG_URI = "http://www.w3.org/2000/09/xmldsig#"
X509v3_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
Base64Binary_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
PasswordDigest_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"


class UsernameToken:
    "WebService Security extension to add a basic credentials to xml request"

    def __init__(self, username="", password=""):
        self.token = {
            'wsse:UsernameToken': {
                'wsse:Username': username,
                'wsse:Password': password,
            }
        }

    def preprocess(self, client, request, method, args, kwargs, headers, soap_uri):
        "Add basic credentials to outgoing message"
        # always extract WS Security header and send it
        header = request('Header', ns=soap_uri, )
        k = 'wsse:Security'
        # for backward compatibility, use header if given:
        if k in headers:
            self.token = headers[k]
        # convert the token to xml
        header.marshall(k, self.token, ns=False, add_children_ns=False)
        header(k)['xmlns:wsse'] = WSSE_URI
        # <wsse:UsernameToken xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>

    def postprocess(self, client, response, method, args, kwargs, headers, soap_uri):
        "Analyze incoming credentials"
        # TODO: add some password validation callback?
        pass


class UsernameDigestToken(UsernameToken):
    """
    WebService Security extension to add a http digest credentials to xml request
    drift -> time difference from the server in seconds, needed for 'Created' header
    """

    def __init__(self, username="", password="", drift=0):
        self.username = username
        self.password = password
        self.drift = datetime.timedelta(seconds=drift)

    def preprocess(self, client, request, method, args, kwargs, headers, soap_uri):
        header = request('Header', ns=soap_uri, )
        wsse = header.add_child('wsse:Security', ns=False)
        wsse['xmlns:wsse'] = WSSE_URI
        wsse['xmlns:wsu'] = WSU_URI

        usertoken = wsse.add_child('wsse:UsernameToken', ns=False)
        usertoken.add_child('wsse:Username', self.username, ns=False)

        created = (datetime.datetime.utcnow() + self.drift).isoformat() + 'Z'
        usertoken.add_child('wsu:Created', created, ns=False)

        nonce = randombytes(16)
        wssenonce = usertoken.add_child('wsse:Nonce', nonce.encode('base64')[:-1], ns=False)
        wssenonce['EncodingType'] = Base64Binary_URI

        sha1obj = sha1()
        sha1obj.update(nonce + created + self.password)
        digest = sha1obj.digest()
        password = usertoken.add_child('wsse:Password', digest.encode('base64')[:-1], ns=False)
        password['Type'] = PasswordDigest_URI


BIN_TOKEN_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<wsse:Security soapenv:mustUnderstand="1" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    <wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="CertId-45851B081998E431E8132880700036719" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%(certificate)s</wsse:BinarySecurityToken>
    <ds:Signature Id="Signature-13" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        %(signed_info)s
        <ds:SignatureValue>%(signature_value)s</ds:SignatureValue>
        <ds:KeyInfo Id="KeyId-45851B081998E431E8132880700036720">
            <wsse:SecurityTokenReference wsu:Id="STRId-45851B081998E431E8132880700036821" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <wsse:Reference URI="#CertId-45851B081998E431E8132880700036719" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
            </wsse:SecurityTokenReference>
        </ds:KeyInfo>
    </ds:Signature>
</wsse:Security>
"""


class BinaryTokenSignature:
    "WebService Security extension to add a basic signature to xml request"

    def __init__(self, certificate="", private_key="", password=None, cacert=None):
        # read the X509v3 certificate (PEM)
        self.certificate = ''.join([line for line in open(certificate)
                                    if not line.startswith("---")])
        self.private_key = private_key
        self.password = password
        self.cacert = cacert

    def preprocess(self, client, request, method, args, kwargs, headers, soap_uri):
        "Sign the outgoing SOAP request"
        # get xml elements:
        body = request('Body', ns=soap_uri, )
        header = request('Header', ns=soap_uri, )
        # prepare body xml attributes to be signed (reference)
        body['wsu:Id'] = "id-14"
        body['xmlns:wsu'] = WSU_URI
        # workaround: copy namespaces so lxml can parse the xml to be signed
        for attr, value in request[:]:
            if attr.startswith("xmlns"):
                body[attr] = value
        # use the internal tag xml representation (not the full xml document)
        ref_xml = repr(body)
        # sign using RSA-SHA1 (XML Security)
        from . import xmlsec
        vars = xmlsec.rsa_sign(ref_xml, "#id-14",
                               self.private_key, self.password)
        vars['certificate'] = self.certificate
        # generate the xml (filling the placeholders)
        wsse = SimpleXMLElement(BIN_TOKEN_TMPL % vars)
        header.import_node(wsse)

    def postprocess(self, client, response, method, args, kwargs, headers, soap_uri):
        "Verify the signature of the incoming response"
        # Not verify the response
        pass

    def __check(self, value, expected, msg="WSSE sanity check failed"):
        if value != expected:
            raise RuntimeError(msg)
