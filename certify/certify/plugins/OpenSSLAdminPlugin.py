import time
import datetime
import logging
import tempfile
import commands
import os
import sys

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
    
   
from certify.core import CertifyAdminInterface

class OpenSSLAdminPlugin(CertifyAdminInterface):
 
    def __init__(self, certhost):
        '''
        All files relevant to CA/Self-signing are generated and kept
        in the root of the global workdir, since they are shared by all
        plugin instances per run. 
        
        Since the global workdir is cleared upon each invocation of Certify,
        we expect a new CA to be generated each time. 
        
        '''
        super(OpenSSLAdminPlugin, self).__init__(certhost)
        self.log = logging.getLogger()
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        self.castring = self.certhost.globalconfig.get('openssladminplugin','castring')
        self.cabits = self.certhost.globalconfig.get('openssladminplugin','cabits')
        self.randomfile = "%s/random.txt" % os.path.expanduser( self.certhost.globalconfig.get('global','workdir') )
        self.casslconf = "%s/caopenssl.conf" % os.path.expanduser( self.certhost.globalconfig.get('global','workdir'))
        self.cacertfile = "%s/cacert.pem" % os.path.expanduser( self.certhost.globalconfig.get('global','workdir'))
        self.cakeyfile = "%s/cakey.pem" % os.path.expanduser( self.certhost.globalconfig.get('global','workdir'))
        self.dbfile = "%s/database" % os.path.expanduser( self.certhost.globalconfig.get('global','workdir'))
        self.serialfile = "%s/serial.txt" % os.path.expanduser( self.certhost.globalconfig.get('global','workdir'))
        self.temptargetdir = "%s%s" % (self.certhost.temproot, self.certhost.targetdir)
        self._getCACert()
        self.log.debug('[%s:%s] Init done.'% (self.certhost.hostname, self.certhost.service))

    def submitRequest(self):
        #self.submitRequestPyOpenSSL()
        self.submitRequestOpenSSL()


    def submitRequestPyOpenSSL(self):
        '''
        For this plugin, submitRequest just creates a self-signed certificate using
        the pyOpenSSL programmatic interface to libssl. 
        
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        #
        # Since this is a self-signing plugin, we just need to create a fake CA cert...
        #
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        cakey = pkey
        careq = crypto.X509Req()
        subj = careq.get_subject()
        setattr(subj, 'CN', self.castring)
        careq.set_pubkey(cakey)
        careq.sign(cakey, 'md5')
        cacert = careq
        
        # So now the CA cert/key is made. Now it can be used to sign request
        # making it a Certificate
        
        cert = crypto.X509()
        cert.set_serial_number(1)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60*60*24*365 )  # One year.
        cert.set_issuer(cacert.get_subject())
        cert.set_subject(self.certhost.request.get_subject())
        cert.set_pubkey(self.certhost.request.get_pubkey())
        cert.sign(cakey, 'md5')
        self.cert = cert
        # AdminInterface self.cert is now signed. 
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))

    def submitRequestOpenSSL(self):
        '''        
        For this plugin, submitRequest just creates a self-signed certificate.
        This method version uses the openssl command line tool. 
        1) uses the openssl program to sign self.certhost.tempreqfile and creates 
        self.certhost.tempcertfile
         
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        #cmd = "openssl x509 -req -days 365 -extfile %s -in %s -CA %s -CAkey %s -set_serial 01 -out %s" % (self.casslconf,
        #                                                                                                 self.certhost.tempreqfile,
        #                                                                                                 self.cacertfile,
        #                                                                                                 self.cakeyfile,
        #                                                                                                 self.certhost.tempcertfile )
        #
        cmd = "openssl ca -batch -notext -config %s -in %s -keyfile %s -outdir %s > %s " % ( self.casslconf,
                                                                    self.certhost.tempreqfile,
                                                                    self.cakeyfile,
                                                                    self.temptargetdir,
                                                                    self.certhost.tempcertfile 
                                                                    )
        #
        
        #cmd = "openssl ca -config %s -in %s -cert %s -keyfile %s -out %s" % (self.casslconf,
        #                                                                     self.certhost.tempreqfile,
        #                                                                    self.cacertfile,
        #                                                                   self.cakeyfile,
        #                                                                   self.certhost.tempcertfile )

        
        self.log.debug("[%s:%s] Executing: %s" % ( self.certhost.hostname, 
                                                   self.certhost.service,
                                                   cmd))        
        (status, output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Output: %s" % ( self.certhost.hostname, 
                                                self.certhost.service,
                                                output.strip()))
        
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))         
    
    
   
    def retrieveCertificate(self):
        '''
        
        
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service)) 
    
                    
    def renewCertificate(self):
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        self.submitRequest()
        self.retrieveCertificate()
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))
      
    def newCertificate(self):
        self.log.debug('[%s:%s] Start new certificate.'% (self.certhost.hostname, self.certhost.service))
        self.submitRequest()
        self.retrieveCertificate()
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))          

    def cleanup(self):
        '''
        Cleans up local temporary files for this host.
        '''
        self.log.debug("[%s:%s] Begin..." % ( self.certhost.hostname, self.certhost.service))
        
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))

###################################################################################################
#
# Private CA-related methods
#
###################################################################################################
        
    def _getCACert(self):
        '''
        If a CA cert doesn't exist, it will create one.
        
        '''
        self.log.debug("[%s:%s] Start..." % ( self.certhost.hostname, self.certhost.service))
        log = logging.getLogger()
        if os.path.exists(self.cacertfile):
            self.log.debug("[%s:%s] Found existing cert file at %s" % ( self.certhost.hostname, 
                                                                        self.certhost.service,
                                                                        self.cacertfile))
            try:
                if OpenSSLAdminPlugin.newrandom:
                    pass
            except AttributeError:
                self._createRandomFile()
                OpenSSLAdminPlugin.newrandom = False
        else:
            self.log.info("[%s:%s] No CA cert found. Creating new self-signing CA. Please wait..." % ( self.certhost.hostname, 
                                                                                                       self.certhost.service))
            cf = self._createCA()
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))
    
    def _createCASslConf(self):
        '''
        Makes a new OpenSSL conf file for this service/host from template.
        
        '''
        self.log.debug("[%s:%s] Start..." % ( self.certhost.hostname, self.certhost.service))
        self.log.debug("[%s:%s] Making CA ssl.conf file at %s" % ( self.certhost.hostname, 
                                                                   self.certhost.service,
                                                                   self.casslconf))
        (path, basename) = os.path.split(self.casslconf)
        if not os.path.exists(path):
            os.makedirs(path)
        out_file = open(self.casslconf, "w")
        sslconftxt = '''RANDFILE = %s
policy = policy_match

[ ca ]
default_ca  = CA_default

[ CA_default ]
certificate = %s
keyfile = %s
database = %s
serial =  %s
default_days  = 365
default_crl_days = 30
default_md = md5
policy = policy_any
email_in_dn =- no
name_opt = ca_default
cert_opt = ca_default
copy_extensions = copyall

[ policy_any ]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional



[ req ]
default_bits = 2048
default_keyfile = %s
distinguished_name = req_distinguished_name
attributes = req_attributes
encrypt_key = no
prompt = no
req_extensions = v3_req

[ req_attributes ]

[ req_distinguished_name ]
CN = %s

[ x509v3_extensions ]
nsCertType = 0x40

[ v3_req ]
''' % (self.randomfile,
       self.cacertfile,
       self.cakeyfile,
       self.dbfile,
       self.serialfile, 
       self.cakeyfile, 
       self.castring )         
        out_file.write(sslconftxt)
        out_file.close()
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, 
                                         self.certhost.service))
    
    def _createCA(self):    
        '''
        Creates a local, temporary CA certificate and returns its filename.
        
        @return filename of temporary CA certificate
        
        '''
        self.log.debug("[%s:%s] Start..." % ( self.certhost.hostname, self.certhost.service))

        self._createCAFiles()
        self._createRandomFile()
        self._createCASslConf()

             
        # Generate CA key
        cmd = "openssl genrsa -des3 -passout pass:asdfg -rand %s -out %s %s" % (self.randomfile, self.cakeyfile, self.cabits)
        self.log.debug("[%s:%s] Executing: %s" % ( self.certhost.hostname, 
                                                   self.certhost.service,
                                                   cmd))        
        (status, output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Output: %s" % ( self.certhost.hostname, 
                                                self.certhost.service,
                                                output.strip()))
        # Generate CA cert
        cmd = "openssl req -new -x509 -config %s -passin pass:asdfg -days 365 -key %s -out %s" % (self.casslconf, 
                                                                                                  self.cakeyfile, 
                                                                                                  self.cacertfile)
        self.log.debug("[%s:%s] Executing: %s" % ( self.certhost.hostname, 
                                                   self.certhost.service,
                                                   cmd))
        (status, output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Output: %s" % ( self.certhost.hostname, 
                                                self.certhost.service,
                                                output.strip()))
        # Remove passphrase from CA keyfile
        cmd = "openssl rsa -passin pass:asdfg -in %s -out %s" % (self.cakeyfile, 
                                                         self.cakeyfile)
        self.log.debug("[%s:%s] Executing: %s" % ( self.certhost.hostname, 
                                                   self.certhost.service,
                                                   cmd))
        (status, output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Output: %s" % ( self.certhost.hostname, 
                                                self.certhost.service,
                                                output.strip()))

        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))

    def _createCAFiles(self):
        '''
        Create database file and serial number file... 
        
        '''
        self.log.debug("[%s:%s] Start..." % ( self.certhost.hostname, self.certhost.service))
        self.log.debug("[%s:%s] Making database %s and serial file %s" % ( self.certhost.hostname, 
                                                             self.certhost.service,
                                                             self.dbfile,
                                                             self.serialfile))
        cmd = "touch %s" % ( self.dbfile )
        (status,output) = commands.getstatusoutput(cmd)
        cmd = "echo 1234 > %s " % (self.serialfile)
        (status,output) = commands.getstatusoutput(cmd)
        cmd = " echo unique_subject = no > %s.attr " % (self.dbfile)
        (status,output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))

        
    def _createRandomFile(self):
        '''
        Create randomfile, fill with text... 
        
        '''
        self.log.debug("[%s:%s] Start..." % ( self.certhost.hostname, self.certhost.service))
        self.log.debug("[%s:%s] Making randomfile %s" % ( self.certhost.hostname, 
                                                   self.certhost.service,
                                                   self.randomfile))
        cmd = "/bin/date > %s; ps aux >> %s ; ls -ln /tmp >> %s" % ( self.randomfile, self.randomfile, self.randomfile)
        (status,output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))
             
