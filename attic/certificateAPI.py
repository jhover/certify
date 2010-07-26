import os
import commands
import re
import logging
import time
import datetime
import sys

import pexpect

from ConfigParser import NoOptionError, ConfigParser

class CertificateAPI:
    "Class with ability to call VDT certificate scripts"
            
    def __init__(self, cp):
        log.debug("Constructing certificateAPI...")
        self.cp = cp
        self.tempDirLocal = self.cp.get('global','tempDirLocal')
        self.tempDirRemote = self.cp.get('global','tempDirRemote')
        self.email = self.cp.get('global','email')
        self.affiliation = self.cp.get('global','affiliation')
        self.vo = self.cp.get('global','vo')
        self.hostCertDir = self.cp.get('global','hostCertDir')
        self.expThreshDays = self.cp.get('global', 'expThreshDays')
        self.adminUserCertDir = self.cp.get('global','adminUserCertDir')
        self.ca = self.cp.get('global','ca')
        self.domains = [d.strip() for d in self.cp.get('global','domains').split(",")]
        self.randomFilePath = self.tempDirRemote+"/rand"
        self.sslConfPathLocal = self.tempDirLocal+"/sslConf"
        self.sslConfPathRemote = self.tempDirRemote+"/sslConf"
        self.reqPathLocal = self.tempDirLocal+"/req"
        self.hostCertBackupPath = self.cp.get('global','hostCertBackupPath')
       
    def renew(self, host, service, password):
        matchedDomainFlag = False
        for d in self.domains:
            if re.search(d+"$", host):
                matchedDomainFlag = True
            if not matchedDomainFlag:
                continue
        if not matchedDomainFlag:
            raise Exception("host %s is not part of allowed domains" % (host));

        log.debug("renewing host %s" % host)

        # setup variables used later
        hostCertPathRemote = self.hostCertDir+"/"+service+"cert.pem"
        hostKeyPath = self.hostCertDir+"/"+service+"key.pem"
        hostCertPathLocal = self.tempDirLocal+"/"+service+"cert.pem"
        tempHostKeyPath = self.tempDirRemote+"/"+service+"key.pem"
        tempHostCertPath = self.tempDirRemote+"/"+service+"cert.pem"
        reqPathRemote = self.hostCertDir+"/"+service+"req"
        if service == 'host':
            cn = host
        else:
            cn = service + "/" + host

        # backup old on remote machine
        dateStr = str(datetime.datetime.now().strftime("_%Y-%m-%d_%H-%M"))
        cmd = "ssh -t root@%s \"if [ ! -d %s ]; then mkdir -p %s;fi; if [ -f %s ]; then cp %s %s/%scert%s.pem;fi; if [ -f %s ]; then cp %s %s/%skey%s.pem;fi;\"" % (host, self.hostCertBackupPath, self.hostCertBackupPath, hostCertPathRemote, hostCertPathRemote, self.hostCertBackupPath, service, dateStr, hostKeyPath, hostKeyPath, self.hostCertBackupPath, service, dateStr)
        log.debug(cmd)
        (status, output) = commands.getstatusoutput(cmd)
        if status:
            raise Exception("Error backing up old certificates on host %s" % host)

        # make certificate directory in case it doesn't exist
        cmd = "ssh -o ConnectTimeout=3 -t root@%s \"if [ ! -d %s ];then mkdir -p %s;fi\"" % (host, self.hostCertDir, self.hostCertDir)
        log.debug(cmd)
        (status, output) = commands.getstatusoutput(cmd)
        log.debug(output)
        if status:
            raise Exception("Error creating certificate directory %s on host %s" % (self.hostCertDir, host))

        # generate random file on remote host
        cmd = "ssh -t root@%s \"date > %s;ps aux >> %s;ls -ln /tmp >> %s\"" % (host, self.randomFilePath, self.randomFilePath, self.randomFilePath)
        log.debug(cmd)
        (status, output) = commands.getstatusoutput(cmd)
        log.debug(output)
        if status:
            raise Exception("Error generating random file on host %s" % host)

        # copy ssl conf to remote host
        self.createSslConf(self.sslConfPathLocal, self.randomFilePath, hostKeyPath, cn)
        cmd = "scp %s root@%s:%s" % (self.sslConfPathLocal, host, self.sslConfPathRemote)
        log.debug(cmd)
        (status, output) = commands.getstatusoutput(cmd) 
        log.debug(output)
        if status:
            raise Exception("Error copying ssl configuration file to host %s" % host)
            
        # generate key and request file on remote host
        cmd = "ssh -t root@%s \"openssl req -new -config %s -out %s -keyout %s; chmod 400 %s\"" % (host, self.sslConfPathRemote, reqPathRemote, tempHostKeyPath, tempHostKeyPath)
        log.debug(cmd)
        (status, output) = commands.getstatusoutput(cmd)
        log.debug(output)
        if status:
            raise Exception("Error generating key and request file on host %s" % host)
            
        # copy request file to my machine
        cmd = "scp root@%s:%s %s" % (host, reqPathRemote, self.reqPathLocal)
        log.debug(cmd)
        (status, output) = commands.getstatusoutput(cmd)
        log.debug(output)
        if status:
            raise Exception("Error copying request file from host %s" % host)    

        # generate certificate from request using cert-gridadmin
        try:
            if os.path.exists(hostCertPathLocal):
                os.remove(hostCertPathLocal)
            cmd = "cert-gridadmin -host %s -request %s -email %s -affiliation %s -vo %s -prefix %s -ca %s -pdir %s -sdir %s" % (host, self.reqPathLocal, self.email, self.affiliation, self.vo, service, self.ca, self.adminUserCertDir, self.tempDirLocal)
            log.debug(cmd)
            process = pexpect.spawn(cmd)
            process.expect(['nter PEM pass phrase:'])
            process.sendline(password)
            process.expect([pexpect.EOF])
            log.debug(process.before)
            if not os.path.exists(hostCertPathLocal):
                raise Exception()
        except Exception:  
            raise Exception("Error executing cert-gridadmin for host %s" % host)
            
        # copy from my machine to remote host within temp dir
        cmd = "scp %s root@%s:%s" % (hostCertPathLocal, host, tempHostCertPath)
        log.debug(cmd)
        (status, output) = commands.getstatusoutput(cmd)
        log.debug(output)
        if status:
            raise Exception("Error copying certificate to host %s" % host)
        
        # move cert and key from temp dir to certificate directory
        cmd = "ssh -t root@%s \"mv %s %s;mv %s %s;\"" % (host, tempHostCertPath, hostCertPathRemote, tempHostKeyPath, hostKeyPath)
        log.debug(cmd)
        (status, output) = commands.getstatusoutput(cmd)
        log.debug(output)
        if status:
            raise Exception("Error copying from temporary directory to certificate directory on host %s" % host)        
        
         # change permissions
        if service != "host":
            cmd = "ssh -t root@%s \"chown %s %s;chown %s %s;\"" % (host, service, tempHostCertPath, service, tempHostKeyPath)
            log.debug(cmd)
            (status, output) = commands.getstatusoutput(cmd)
            log.debug(output)
            if status:
                raise Exception("Warning changing ownership to %s on %s" % (service, host))
        
    def daysUntilExpiration(self, host, service):
        matchedDomainFlag = False
        for d in self.domains:
            if re.search(d+"$", host):
                matchedDomainFlag = True
            if not matchedDomainFlag:
                continue
        if not matchedDomainFlag:
            raise Exception("host %s is not part of allowed domains" % (host))

        log.debug("checking host %s" % host)

        # set variables used later
        hostCertPathRemote = self.hostCertDir+"/"+service+"cert.pem"
        hostCertPathLocal = self.tempDirLocal+"/"+service+"cert.pem"

        (status, output) = commands.getstatusoutput("rm -f %s" % hostCertPathLocal)
        (status, output) = commands.getstatusoutput("scp -o ConnectTimeout=3 root@%s:%s %s" % (host, hostCertPathRemote, hostCertPathLocal)) 
        log.debug(output)
        if output.find("No such file") != -1:
           return -1
        if output.find("Connection timed out") != -1:
           raise Exception("could not ssh to host %s" % (host))
        if output.find("man-in-the-middle attack") != -1:
           raise Exception("incorrect key in known_hosts for %s" % (host))
        if output.find("Name or service not known") != -1:
           raise Exception("%s doesn't appear to exist" % (host))
        if status and output.find("continue connecting") == -1:
           raise Exception("Could not copy certificate from host %s: %s" % (host, output.strip()))

        (status,output) = commands.getstatusoutput("openssl x509 -in %s -enddate -noout" % hostCertPathLocal) 
        log.debug(output)
        if status:
           raise Exception("Error determining certificate expiration for host %s" % host)

        (key, expiration_str) = output.split("=")
        log.debug("openssl cert expiration string is %s" % expiration_str)
        (mon, day, time_, year, zone) = expiration_str.split()
        log.debug("Cert expiration mon=%s day=%s time=%s year=%s zone=%s" % (mon, day, time_, year, zone))

        # Format that openssl prints dates in e.g. "Jun 12 19:07:47 2008 GMT"
        openssl_date_format='''%b %d %H:%M:%S %Y %Z'''

        # Get and convert now to datetime object
        (year, mon, mday, hour, min, sec, wday, yday, isdst) = time.localtime()
        nowdatetime = datetime.datetime(year,mon,mday)

        # Parse and convert certificate expiration to datetime object
        (year, mon, mday, hour, min, sec, wday, yday, isdst) = time.strptime(expiration_str, openssl_date_format )
        expdatetime = datetime.datetime(year,mon,mday)

        # Subtract to get timedelta object
        daysLeft = expdatetime - nowdatetime

        log.debug("Certificate appears to have %s days until expiration..." % daysLeft.days)

        return int(daysLeft.days)
        
    def createSslConf(self, sslConfPath, randomFilePath, keyPath, cn):
        out_file = open(sslConfPath, "w")
        out_file.write("RANDFILE = %s\n" % randomFilePath)
        out_file.write("policy = policy_match\n")
        out_file.write("[ req ]\n")
        out_file.write("default_bits = 2048\n")
        out_file.write("default_keyfile = %s\n" % keyPath)
        out_file.write("distinguished_name = req_distinguished_name\n")
        out_file.write("attributes = req_attributes\n")
        out_file.write("encrypt_key = no\n")
        out_file.write("prompt = no\n")
        out_file.write("[ req_attributes ]\n")
        out_file.write("[ req_distinguished_name ]\n")
        out_file.write("1.DC = org\n")
        out_file.write("2.DC = doegrids\n")
        out_file.write("OU = Services\n")
        out_file.write("CN = "+cn+"\n")
        out_file.write("[ x509v3_extensions ]\n")
        out_file.write("nsCertType = 0x40\n")
        out_file.close()