#!/usr/bin/env python

from setuptools import setup

"""PySimpleSOAP"""
__author__ = "Mariano Reingart"
__author_email__ = "reingart@gmail.com"
__copyright__ = "Copyright (C) 2013 Mariano Reingart"
__license__ = "LGPL 3.0"
__version__ = "1.16"


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
        install_requires=[
          'xmltodict',
        ]
    )
