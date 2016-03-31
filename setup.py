#!/usr/bin/env python

from setuptools import setup

setup(name='conseq',
      version='0.1',
      description='ConSeq dependency tracker',
      author='Philip Montgomery',
      author_email='pmontgom@broadinstitute.org',
      packages=['conseq', 'cpdshelpers'],
      scripts=['scripts/conseq'],
      install_requires=[ "colorlog", "grako", "jinja2", "paramiko", "requests", "boto", "tabulate" ]
     )