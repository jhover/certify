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
from certificateAPI import CertificateAPI

# Default constants & flags
# Change when ready to distrbute as RPM

user = os.environ.pop("USER")
(status, passwdEntry) = commands.getstatusoutput("getent passwd "+ user) 
home = passwdEntry.split(":")[5]
config_file = home + '/.certify/certify.conf'
if not os.path.exists(config_file):
    if os.path.exists("/usr/share/doc/certify/certify.conf"):
        os.system("mkdir " + home + "/.certify; cp /usr/share/doc/certify/certify.conf " + home + "/.certify/certify.conf")
    print "Please configure " + config_file + " before running."
    sys.exit(1)
debug = 0
info = 0
warn = 0
list = 0

usage = """Usage: main.py [OPTIONS]  
OPTIONS: 
    -h --help                   Print this message
    -l --list                   List hosts needing certificate renewal
    -d --debug                  Debug messages
    -v --verbose                Verbose information
 """

# Handle command line options
argv = sys.argv[1:]
try:
    opts, args = getopt.getopt(argv, 
                               "hldv", 
                               ["help", 
                                "list", 
                                "debug", 
                                "verbose"
                                ])
except getopt.GetoptError, error:
    print str(error)
    print usage                          
    sys.exit(1)
for opt, arg in opts:
    if opt in ("-h", "--help"):
        print usage                     
        sys.exit()            
    elif opt in ("-l", "--list"):
        list = 1
    elif opt in ("-d", "--debug"):
        debug = 1
    elif opt in ("-v", "--verbose"):
        info = 1
 
log = logging.getLogger()

# Read in config file
cp=ConfigParser()
cp.read(config_file)

# Set up logging. 
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
ch = logging.StreamHandler()
formatter = logging.Formatter("%(levelname)s: %(message)s")
ch.setFormatter(formatter)
log.addHandler(ch)

# Run VDT setup script and set environmental variables.
vdt_location = cp.get('global','vdtLocation')
vdtsetup = "%s/setup.sh" % vdt_location
if not os.path.exists(vdtsetup):
        print "Couldn't find vdt setup file: "+vdtsetup
        sys.exit(1)
log.debug("vdtsetup path is %s" % vdtsetup)
(status, output) = commands.getstatusoutput("source %s; env" % vdtsetup)
log.debug("status is : %s" % status)
log.debug("output is : %s" % output)
log.debug("environ is : %s" % os.environ)
lines = output.split("\n")
for l in lines:
    pairs = l.split("=")
    var = pairs[0]
    val = pairs[1]
    os.environ[var] = val
if cp.has_option('global','proxy'):
    os.environ['http_proxy'] = cp.get('global','proxy')
    os.environ['https_proxy'] = cp.get('global','proxy')
log.debug("new environ is : %s" %  os.environ)

# ask user for admin certificate password
if not list:
    password = getpass.getpass("Enter admin certificate password: ")

# get hosts file from URI
hostsURIs = cp.get('global','hostsURIs').split(",")
hostsCP=ConfigParser()
count=0
for h in hostsURIs:
	try:
		hostsURI = h.strip()
		if cp.get('global','proxy'):
			proxy_support = urllib2.ProxyHandler({'http': cp.get('global','proxy')})
			opener = urllib2.build_opener(proxy_support)
		else:
			opener = urllib2.build_opener()
		urllib2.install_opener( opener )
		uri = urllib2.urlopen( hostsURI )
		firstLine = uri.readline().strip()
		if firstLine[0] == "<":
			raise Exception()
		hostsUriReader = urllib2.urlopen( hostsURI )
	except Exception:  
	    errMsg = "Couldn't find URI %s (use file://... or http://... format)" % hostsURI
	    log.error(errMsg)
	    raise

	# Prepare file for reading into config parser
	configFormat = True
	for l in hostsUriReader.readlines():
		line = l.strip()
		if line == "":
			continue
		if line[0] == "#":
			continue
		if not line.strip()[0] == "[":
			configFormat = False
		break
	if not configFormat:
		# Convert to config format and write to temporary local file
		hostsFileName = "/tmp/~certify-hosts"+str(count)
		count = count + 1
		hostsFile = open(hostsFileName, "w")
		hostsUriReader = urllib2.urlopen( hostsURI )
		for l in hostsUriReader.readlines():
			line = l.strip()
			if line == "":
				continue
			if line[0] == "#":
				continue
			hostsFile.write("["+line+"]\n")
			hostsFile.write("services=host\n")
		hostsUriReader.close()
		hostsFile.close()
	else:
		if re.search("^file://",hostsURI):
			p = re.compile( '^file://')
			hostsFileName = p.sub("",hostsURI)
		else:
			# download to temporary local file
			hostsFileName = "/tmp/~certify-hosts"+str(count)
			count = count + 1
			hostsUriReader = open(hostsFileName, "w")
			for line in hostsUriReader.readlines():
			    hostsFile.write(line)
			hostsUri.close()
			hostsFile.close()

	# Parse hosts configuration
	hostsCP.read(hostsFileName)

# Loop through hosts in configuration parser
for section in hostsCP.sections():
    if re.search("\d+--\d+",section):
        try:
            p = re.compile('(^.+?)\.')
            domain = "."+p.sub('', section, count=1).strip()
    
            p = re.compile('(\d+\--\d+.*)')
            hostBase = p.sub('', section, count=1).strip()
    
            m = re.match(r'[a-zA-Z]+([\d,--]+)\..*', section)
            range = m.group(1)
            num = range.split("--")[0]
            last = range.split("--")[1]
            width = len(num)
            
            hostList = []
            while num != last:
                hostList += [hostBase + num + domain]
                num = str(int(num)+1).zfill(width)
            hostList += [hostBase + last + domain]
        except Exception, error:
            log.error("Invalid format in hosts file for section %s: %s" % (section, error))
            raise
    else:
        hostList = [section.strip()]
    for o in hostsCP.options(section):
    	option = o.strip()
        servicesList = ["host"] #default in case there is no services option
        if option == "services":
            servicesList = hostsCP.get(section,'services').split(",")
        else:
            log.error("Unknown option %s in hosts file for section %s: %s" % (option, section, error))
    for h in hostList:
        host = h.strip()
        if host == "":
            continue
        for s in servicesList:
            service = s.strip()
            certificateAPI = CertificateAPI(cp=cp)
            try:
                days = certificateAPI.daysUntilExpiration(host, service)
                if days < int(cp.get('global','expThreshDays')):
                    if list == 0:
                        certificateAPI.renew(host, service, password)
                        log.info("Renewed host %s" % host)
                    else:
                        if days < 0:
                            print "%s/%s (expired or nonexistent)" % (host, service)
                        else:
                            print "%s/%s (%s days)" % (host, service, days)
            except Exception, error:
                if error and len(str(error))==0:
                    log.warning("Program aborted")
                    sys.exit(1)
                else:
                    log.error("%s" % error)
