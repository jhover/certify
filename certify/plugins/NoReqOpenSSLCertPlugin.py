import os
import sys
import time
import datetime
import logging
import commands

try:
    import OpenSSL
    from OpenSSL import crypto
    vers = OpenSSL.version.__version__
    major, minor = str(vers).split('.')[:2]
    intmajor = int(major)
    intminor = int(minor)
    if intmajor < 1 and intminor < 7:
        print "This plugin requires pyOpenSSL >= 0.7"
        sys.exit(0)   
except ImportError:
    print  "This plugin requires pyOpenSSL >= 0.7"
    sys.exit(0)
    
from certify.core import CertifyCertInterface

class NoReqOpenSSLCertPlugin(CertifyCertInterface):
    '''
     Uses the openssl command line program to handle certificates. But does not create requests.  
    
    '''
      
    def __init__(self, certhost):
        super(NoReqOpenSSLCertPlugin, self).__init__(certhost)
        self.log = logging.getLogger()
        self.certhost = certhost
        self.log.debug("[%s:%s] Begin..." % ( self.certhost.hostname, self.certhost.service))
        self.pkey = None  # X509.PKey object
        # Put the ssl conf file wherever the cert file will go:
        (self.certdir, basename) = os.path.split(self.certhost.certfile)
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))


    def __str__(self):
        s = "NoReqOpenSSLCertPlugin [%s:%s]: " % (self.certhost.hostname, self.certhost.service)
        return s

            
    def loadCertificate(self):
        '''
        However necessary, read public certificate into self.certificate from temp dir.
        
        '''
        self.log.debug("[%s:%s] Begin..." % ( self.certhost.hostname, self.certhost.service))
        if os.path.exists(self.certhost.tempcertfile):
            self.log.debug("[%s:%s] Loading cert from %s" % (self.certhost.hostname, 
                                                             self.certhost.service, 
                                                          self.certhost.tempcertfile))
            self._pubcertbuffer = open(self.certhost.tempcertfile).read()
            self.certhost.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                                                self._pubcertbuffer)

        else:
            self.log.debug("[%s:%s] Cert file %s not found." % ( self.certhost.hostname, 
                                                                 self.certhost.service, 
                                                                 self.certhost.tempcertfile))
            self.certhost.certificate = None

    
    def dumpCertificate(self):
        '''
        Write out self.certificate to self.tempcertfile in temp dir.
         
        '''
        self.log.debug("[%s:%s] Start..." % ( self.certhost.hostname, self.certhost.service))
        # Handle public key
        if self.certhost.certificate and self.certhost.certfile:
            self.log.debug("[%s:%s] Dumping cert to %s" % (self.certhost.hostname,
                                                           self.certhost.service,  
                                                        self.certhost.tempcertfile))    
            (filepath, tail) = os.path.split(self.certhost.certfile)
            if not os.path.exists(filepath):
                os.makedirs(filepath)
            cf = open(self.certhost.tempcertfile, 'w')
            cf.write(crypto.dump_certificate(crypto.FILETYPE_PEM, 
                                             self.certhost.certificate))            
            self.log.debug('[%s:%s] Loaded cert object is %s' % (self.certhost.hostname, 
                                                                 self.certhost.service, 
                                                              self.certhost.certificate))
        else:
            self.log.debug("[%s:%s] Cert = None or no certfile set." % ( self.certhost.hostname, self.certhost.service))
        
        # Handle private key
        if self.certhost.privatekey and self.certhost.keyfile:
            self.log.debug("[%s:%s] Dumping key to %s" % (self.certhost.hostname,
                                                          self.certhost.service,  
                                                       self.certhost.keyfile))    
            (filepath, tail) = os.path.split(self.certhost.keyfile)
            if not os.path.exists(filepath):
                os.makedirs(filepath)
            cf = open(self.certhost.keyfile, 'w')
            cf.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, 
                                            self.certhost.keypair))            
            #self.log.debug('[%s:%s] Dumped key to %s' % (self.certhost.hostname, 
            #                                             self.certhost.service, 
            #                                          self.certhost.keyfile))
        else:
            self.log.debug("[%s:%s] Cert = None or no certfile set." % ( self.certhost.hostname, self.certhost.service))

                     
    def validateCert(self):
        '''
        Runs set of tests to validate cert. Failure should trigger renewal/creation.

        '''
        aaa = self._validateCommonName()
        bbb = self._validateCertPair()
        ccc = self._validateCA()
        
        if aaa and bbb and ccc:
            return True
        else:
            return False
        

    def _validateCommonName(self):
        '''
        Checks to be sure that the current certificate for host is in fact 
        what is specified by hosts.conf. 
        
        1) certificate commonName should be "full.hostname.com" for host
        "service/full.hostname.com" for service cert
        
        2) ?
        
        '''
        self.log.debug("[%s:%s] Start..." % ( self.certhost.hostname, self.certhost.service))
        hname = self.certhost.certificate.get_subject().commonName
        self.log.debug("[%s:%s] commonName is %s" % ( self.certhost.hostname, 
                                                      self.certhost.service, 
                                                      hname)
                                                      )
        if hname == self.certhost.commonname:
            retval=True
            self.log.debug("[%s:%s] Cert commonname '%s' matches that desired '%s'." % ( self.certhost.hostname, 
                                                                                         self.certhost.service,
                                                                                         hname,
                                                                                         self.certhost.commonname
                                                                                         ))
        else:
            self.log.info("[%s:%s] Cert commonname doesn't match that desired. Make new cert." % ( self.certhost.hostname, self.certhost.service))
            retval=False
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))
        return retval
    
    def _validateCA(self):
        '''
        Checks to be sure that the CA (Issuer CommonName) of the current certificate for host is in fact 
        what is specified by hosts.conf. 
        e.g., 
        
        DC=com, DC=DigiCert-Grid, O=Open Science Grid, OU=Services, CN=acas0065.usatlas.bnl.gov
        
        Issuer CN: DigiCert Grid CA-1
                
        '''
        caname = self.certhost.certificate.get_issuer().commonName
        self.log.debug("[%s:%s] CA commonName is %s" % ( self.certhost.hostname, 
                                                      self.certhost.service, 
                                                      caname)
                                                      )
        if caname in self.certhost.issuercns:
            retval=True
            self.log.debug("[%s:%s] CA commonname '%s' matches (one) desired '%s'." % ( self.certhost.hostname, 
                                                                                         self.certhost.service,
                                                                                         caname,
                                                                                         self.certhost.issuercns
                                                                                         ))
        else:
            self.log.info("[%s:%s] CA commonname '%s' doesn't match (any) desired. Make new cert." % (caname,
                                                                                              self.certhost.hostname, 
                                                                                              self.certhost.service))
            retval=False
        return retval
        
    
    
    def _validateCertPair(self):
        '''
         Checks to be sure certificate and private key go together. 
        Uses command:
        
        ( /usr/bin/openssl x509 -noout -modulus -in /etc/grid-security/hostcert.pem | /usr/bin/openssl md5 ; \
        /usr/bin/openssl rsa -noout -modulus -in /etc/grid-security/hostkey.pem | /usr/bin/openssl md5 ) | uniq | wc -l
        
                    self.getFile( self.certhost.certfile, 
                           self.certhost.tempcertfile)            
            self.getFile( self.certhost.keyfile, 
                           self.certhost.tempkeyfile)        
       
        '''
        try:
            self.log.debug("Validating cert/key for [%s:%s] at %s and %s" % ( self.certhost.hostname, 
                                                                   self.certhost.service,
                                                                   self.certhost.tempcertfile,
                                                                   self.certhost.tempkeyfile,
                                                                  ) )
            cmda = "/usr/bin/openssl x509 -noout -modulus -in %s | /usr/bin/openssl md5" % self.certhost.tempcertfile
            (s,outa) = commands.getstatusoutput(cmda)
            cmdb = "/usr/bin/openssl rsa -noout -modulus -in /etc/grid-security/hostkey.pem | /usr/bin/openssl md5" % self.certhost.tempkeyfile
            (s,outb) = commands.getstatusoutput(cmdb)
            self.log.debug("Cert modulus is %s" % outa.strip())
            self.log.debug("Key modulus is %s" % outb.strip())
            return True
        except Exception:
            pass
        return True
      
    
                      
    def getExpirationUTC(self):
        '''
        Extracts the certificate expiration date/time and returns an
        equivalent Python datetime object. 
        
        '''
        self.log.debug("[%s:%s] Running..." % ( self.certhost.hostname, self.certhost.service))
        # notAfter String. E.g. 20090731214746Z
        nastr = self.certhost.certificate.get_notAfter()
        if len(nastr) > 12:
            yr=int(nastr[0:4])
            mo=int(nastr[4:6])
            dy=int(nastr[6:8])
            hr=int(nastr[8:10])
            mn=int(nastr[10:12])
            sc=int(nastr[12:14])
            notafter = datetime.datetime(yr, mo, dy, hr, mn,sc,0, tzinfo=None)
            self.log.debug("[%s:%s] Certificate not valid after: %s" % (self.certhost.hostname, self.certhost.service, notafter))
            return notafter
        else:
            self.log.error("[%s:%s] Something horribly wrong with OpenSSL date output: %s" % (self.certhost.hostname,self.certhost.service,  nastr))
               
              
         
    def cleanup(self):
        '''
        Cleans up local temporary files for this host.
        '''
        self.log.debug("[%s:%s] Begin..." % ( self.certhost.hostname, self.certhost.service))
        
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))
          
###################################################################################
#
# Generic methods using IOPlugin methods to perform Request creation.
#
###################################################################################
    def makeRequest(self):
        '''
        Creates standard OpenSSL X509 Request file for use by an admin interface.  
        
        '''
        self.log.debug("[%s:%s] Start..." % ( self.certhost.hostname, self.certhost.service))      
        self._createCertDir()
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))        
               

    def _createCertDir(self):
        self.log.debug('[%s:%s] Making certificate dir %s'% (self.certhost.hostname, 
                                                             self.certhost.service,
                                                             self.certdir))        
        self.certhost.ioplugin.makeDir(self.certdir)
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))


 
