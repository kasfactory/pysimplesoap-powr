#!/usr/bin/env python

from setuptools import setup

from pysimplesoap import __version__, __author__, __author_email__, __license__

# in the transition, register both:
for name in ('soap2py', 'PySimpleSOAP'):
    setup(
        name=name,
        version=__version__,
        description='Python simple and lightweight SOAP Library',
        author=__author__,
        author_email=__author_email__,
        url='http://code.google.com/p/pysimplesoap',
        packages=['pysimplesoap'],
        license=__license__,
        #    console=['client.py'],
        install_requires=[
          'xmltodict',
        ]
    )
