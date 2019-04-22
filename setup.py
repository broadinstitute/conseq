#!/usr/bin/env python

import ast
import re

from setuptools import setup

_version_re = re.compile(r'__version__\s*=\s*(.*)')

with open('conseq/__init__.py', 'rt') as f:
    version = str(ast.literal_eval(_version_re.search(
        f.read()).group(1)))

setup(name='conseq',
      version=version,
      description='ConSeq dependency tracker',
      author='Philip Montgomery',
      author_email='pmontgom@broadinstitute.org',
      packages=['conseq', 'conseq.parser'],
      entry_points={'console_scripts': ['conseq=conseq.main:conseq_command_entry']
                    },
      #      install_requires=[ "colorlog", "grako", "jinja2", "paramiko", "requests", "boto", "tabulate", "six" ]
      install_requires=["paramiko==2.1.2", "colorlog>=3.0.1", "requests>=2.9.1", "boto>=2.38.0", "tabulate>=0.7.7", "six>=1.10.0", "jinja2", "tatsu==4.2.6", "pytest"]
      )
