#!/usr/bin/env python
import os
import sys
import getopt
import commands
import getpass
import stat
import re
import datetime
import tempfile
import urllib2
import logging

from ConfigParser import ConfigParser

# Since script is in package "certify" we can know what to add to path
(libpath,tail) = os.path.split(sys.path[0])
sys.path.append(libpath)

from certify.core import Certify

debug = 0
info = 0
warn = 0
list = 0
noclean = 0
config_file = None
hostsuri_override= None
default_configfile = os.path.expanduser("~/.certify/certify.conf")
logfile = None
version="0.8.8"

usage = """Usage: main.py [OPTIONS]  
OPTIONS: 
    -h --help                   Print this message
    -l --list                   Print list of configured hosts. No effects.
    -d --debug                  Debug messages
    -v --verbose                Verbose information
    -c --config                 Config file [~/.certify/certify.conf]
    -H --hosturi                Override hosturi in config file. [file://~/.certify/hosts.conf]              
    -N --noclean                Don't delete temporary files.
    -V --version                Print program version and exit.
    -L --logfile                Log output to logfile as well as stdout.
 """

# Handle command line options
argv = sys.argv[1:]
try:
    opts, args = getopt.getopt(argv, 
                               "c:H:hldvNVL:", 
                               ["config=",
                                "hostsuri="
                                "help", 
                                "list", 
                                "debug", 
                                "verbose",
                                "noclean",
                                "version",
                                "logfile="
                                ])
except getopt.GetoptError, error:
    print( str(error))
    print( usage )                          
    sys.exit(1)
for opt, arg in opts:
    if opt in ("-h", "--help"):
        print(usage)                     
        sys.exit()            
    elif opt in ("-c", "--config"):
        config_file = arg
    elif opt in ("-H", "--hostsuri"):
        hostsuri_override = arg
    elif opt in ("-l", "--list"):
        list = 1
    elif opt in ("-d", "--debug"):
        debug = 1
    elif opt in ("-v", "--verbose"):
        info = 1
    elif opt in ("-N", "--noclean"):
        noclean = 1
    elif opt in ("-V","--version"):
        print(version)
        sys.exit()
    elif opt in ("-L","--logfile"):
        logfile = arg
 
log = logging.getLogger()

# Read in config file
cp=ConfigParser()
if not config_file:
    config_file = default_configfile
got_config = cp.read(config_file)
#if not got_config:
#    print("No configuration file specified and no default file (~/.certify/certify.conf).")
#    print(usage)
#    sys.exit(0)

# Set up logging. 
# Check python version 
major, minor, release, st, num = sys.version_info

# Set up logging, handle differences between Python versions... 
# In Python 2.3, logging.basicConfig takes no args
#
FORMAT23="[ %(levelname)s ] %(asctime)s %(filename)s (Line %(lineno)d): %(message)s"
FORMAT24=FORMAT23
FORMAT25="[%(levelname)s] %(asctime)s %(module)s.%(funcName)s(): %(message)s"
FORMAT26=FORMAT25

if major == 2:
    if minor ==3:
        formatstr = FORMAT23
    elif minor == 4:
        formatstr = FORMAT24
    elif minor == 5:
        formatstr = FORMAT25
    elif minor == 6:
        formatstr = FORMAT26

log = logging.getLogger()
hdlr = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(FORMAT23)
hdlr.setFormatter(formatter)
log.addHandler(hdlr)
# Handle file-based logging.
if logfile:
    hdlr = logging.FileHandler(logfile)
    hdlr.setFormatter(formatter)
    log.addHandler(hdlr)

logLev = cp.get('global','logLevel').lower()
if logLev == 'debug':
    log.setLevel(logging.DEBUG)
elif logLev == 'info':
    log.setLevel(logging.INFO)
elif logLev == 'warn':
    log.setLevel(logging.WARN)
if debug: 
    log.setLevel(logging.DEBUG) # Override with command line switches
if info:
    log.setLevel(logging.INFO) # Override with command line switches


# Pass through command line switches
if noclean:
    cp.set('global', 'noclean', 'true')
else:
    cp.set('global', 'noclean', 'false')

# Handle hosturi override
if hostsuri_override:
    log.debug("certify-binary.py: Overriding config file hostsuri with %s" % hostsuri_override)
    cp.set('global', 'hostsuris', hostsuri_override)

log.debug("certify-binary.py: Creating Certify().")
certifyobj = Certify(cp)
log.debug("certify-binary.py: Done creating Certify().")
if list:
    print certifyobj.list()
else:
    log.debug("certify-binary.py: Executing Certify.execute()")
    certifyobj.execute()
log.debug("certify-binary.py: Done.")
