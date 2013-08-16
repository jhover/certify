#!/usr/bin/env python
#
# Setup prog for Certify certificate management utility

import sys
from distutils.core import setup

from certify import core
release_version=core.__version__

setup(
    name="certify",
    version=release_version,
    description='Utilities for handing automated Grid host certificates.',
    long_description='''Simple tools for automating grid host certificate application and renewal.''',
    license='GPL',
    author='John Hover, Jay Packard',
    author_email='jhover@bnl.gov, jpackard@bnl.gov',
    url='https://www.racf.bnl.gov/experiments/usatlas/griddev/',
    packages=[ 'certify',
               'certify.plugins'
              ],
    classifiers=[
          'Development Status :: 3 - Beta',
          'Environment :: Console',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: GPL',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Topic :: System Administration :: Management',
    ],
    scripts=[ 'scripts/certify',
             ],
    data_files=[ ('share/certify', 
                      ['README.txt',
                       'NOTES.txt',            
                       'LGPL.txt',
                        ]
                  ),
                  ('share/certify/config', ['config/certify.conf','config/hosts.conf']              
                   ),
               ]
)

