#!/usr/bin/env python

from setuptools import setup

setup(name='conseq',
      version='0.2.3',
      description='ConSeq dependency tracker',
      author='Philip Montgomery',
      author_email='pmontgom@broadinstitute.org',
      packages=['conseq', 'conseq.parser', 'cpdshelpers'],
      entry_points={   'console_scripts': ['conseq=conseq.main:main']
      },
      install_requires=[ "colorlog", "grako", "jinja2", "paramiko", "requests", "boto", "tabulate", "six" ]
     )