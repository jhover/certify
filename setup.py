#!/usr/bin/env python
#
# Setup prog for VOMSAdmin Library
#
#

import sys
from distutils.core import setup

# For now, don't forget to increment this in certify-binary.py
release_version='0.9.1'

# Re-write version string in certify-binary.py
#f = open('./certify/certify-binary.py' ,'w')

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

