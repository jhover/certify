import logging
import os
import sys
import commands
import getpass
import tempfile

try:
    import pexpect
except ImportError:
    print "This Certify plugin (OSGAdmin) requires pexpect. Please install."
    sys.exit(0)

   
from certify.core import CertifyAdminInterface

class OSGAdminPlugin(CertifyAdminInterface):
    
    def getPassphrase(cls):
        '''
        This is necessary to avoid the user having to type in their cert password for
        *each* hostname:service pair in Certify. 
        This stores the passphrase as a global class attribute available to all instances of 
        this plugin. 
        
        '''
        log = logging.getLogger()
        try:
            pp=OSGAdminPlugin.passphrase
            log.debug("Found passphrase in class.")
            return pp
        except:
            log.debug("Didn't find passphrase in class. Requesting...")
            
            OSGAdminPlugin.passphrase=getpass.getpass("OSGAdminPlugin: Enter user certificate passphrase>")
            if OSGAdminPlugin.checkPassphrase():
                log.debug("Provided passphrase unlocks ~/.globus/userkey.pem. Continuing...")
            else:
                log.error("Provided passphrase does NOT unlock ~/.globus/userkey.pem !! Exitting.")
                sys.exit(0)
            return OSGAdminPlugin.passphrase
    getPassphrase=classmethod(getPassphrase)
    
    def checkPassphrase(cls):
        '''
        Confirms that the provided passphrase really does work on ~/.globus/userkey.pem
        '''
        log = logging.getLogger()
        phraseOK= False
        
        # build command
        userkeypath = os.path.expanduser("~/.globus/userkey.pem") 
        cmd = "/usr/bin/openssl rsa -noout -modulus -in %s" % userkeypath 
        # run it using pexpect        
        process = pexpect.spawn(cmd)
        process.expect(['serkey.pem:'])
        process.sendline(OSGAdminPlugin.passphrase)
        process.expect([pexpect.EOF])
        process.close()
        if process.exitstatus == 0:  # passphrase OK
            phraseOK = True
        log.debug("Command output: %s"% process.before.strip() ) 
        return phraseOK      
    checkPassphrase=classmethod(checkPassphrase)
    
    def __init__(self, certhost):
        super(OSGAdminPlugin, self).__init__(certhost)
        self.log = logging.getLogger()
        self.log.debug("[%s:%s] Init..."% (self.certhost.hostname, 
                                              self.certhost.service)) 
        
        self.passphrase = OSGAdminPlugin.getPassphrase()  
        self.log.debug("[%s:%s] Passphrase set from user input."% (self.certhost.hostname, 
                                              self.certhost.service))           
        self.log.debug("[%s:%s] Init Done"% (self.certhost.hostname, 
                                              self.certhost.service)) 
                
    def _check_gridadmin_command(self):
        cmd = "which osg-cert-request"
        (status,output)=commands.getstatusoutput(cmd)
        if status:
            mesg='''This Certify plugin (OSGAdminPlugin) requires the VDT PPDG-Cert-Scripts to be installed,
and the osg-cert-request command to be in the PATH.'''
            print(mesg)
            sys.exit(0)
    
    
                
    def submitRequest(self):
        '''
        Executes osg-cert-request with the appropriate arguments, using this plugin's request file and
        other information.
                 
        '''
        self.log.debug("[%s:%s] Start." % (self.certhost.hostname, self.certhost.service) )
        # If it exists, remove current cert file from temp (since we're about to make a new one).
        # self.certhost.tempcertfile
        try:
            os.remove(self.certhost.tempcertfile)
        except OSError:
            pass
        
        
        # build command
        cmd = self._buildGridadminCommand()        
        # run it using pexpect        
        process = pexpect.spawn(cmd)
        process.expect(['nter PEM pass phrase:'])
        process.sendline(self.passphrase)
        process.expect([pexpect.EOF])
        self.log.debug("[%s:%s] Command output: %s"% (self.certhost.hostname, 
                                                      self.certhost.service, 
                                                      process.before.strip() )  ) 
        
    
    
    def retrieveCertificate(self):
        self.log.debug("[%s:%s] Start." % (self.certhost.hostname, self.certhost.service) ) 
        # Confirm existence of tmpcertfile
        if not os.path.exists(self.certhost.tempcertfile):
            raise Exception("Certificate has not been issued!!! Failing.")
        self.log.debug("[%s:%s] Done." % (self.certhost.hostname, self.certhost.service) )
    
    def newCertificate(self):
        self.log.debug("[%s:%s] Start." % (self.certhost.hostname, self.certhost.service) )  
        self.submitRequest()
        self.retrieveCertificate()
        self.log.debug("[%s:%s] Done." % (self.certhost.hostname, self.certhost.service) )        
        
    def renewCertificate(self):
        self.log.debug("[%s:%s] Start." % (self.certhost.hostname, self.certhost.service) )
        self.submitRequest()
        self.retrieveCertificate()
        self.log.debug("[%s:%s] Done." % (self.certhost.hostname, self.certhost.service) )

    def cleanup(self):
        '''
        Cleans up local temporary files for this host.
        '''
        self.log.debug("[%s:%s] Begin..." % ( self.certhost.hostname, self.certhost.service))
        
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))

        
    def _buildGridadminCommand(self):
        '''

        OLD
        cmd = "cert-gridadmin 
               -host %s 
               -request %s 
               -email %s 
                -affiliation %s 
                -vo %s 
                -prefix %s 
                -ca %s 
                -pdir %s 
                -sdir %s" % 
                (host, 
                self.reqPathLocal,  
                self.email,  
                self.affiliation, 
                self.vo, 
                service,  
                self.ca, 
                self.adminUserCertDir, 
                self.tempDirLocal) 
        
        NEW
          -c CSR, --csr=CSR     Specify CSR name (default = gennew.csr)
          -o Output Keyfile, --outkeyfile=Output Keyfile
                        Specify the output filename for the retrieved user
                        certificate.  Default is ./hostkey.pem
          -y CC List, --cc=CC List
                        Specify the CC list(the email id's to be CCed). Separate values by ','
          -m Comment, --comment=Comment
                        The comment to be added to the request
          -t CN, --hostname=CN  Specify hostname for CSR (FQDN)
          -e EMAIL, --email=EMAIL
                        Email address to receive certificate
          -n NAME, --name=NAME  Name of user receiving certificate
          -p PHONE, --phone=PHONE
                        Phone number of user receiving certificate
          -v VO, --vo=VO
                        VO name of requested hostname
          -T, --test            Run in test mode
          -q, --quiet           don't print status messages to stdout

Example:

python osg-cert-request -t hostname.domain.com -e emailaddress@domain.com -n "Your Name" -p 9999999999 -y "xyz@domain.com,abc@domain.com" -m "This is my comment"
python osg-cert-request -t hostname.domain.com -e emailaddress@domain.com -n "Your Name" -p 9999999999 -y "xyz@domain.com,abc@domain.com" -m "This is my comment" --csr mycsr.csr

        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        '''
        self.log.debug("[%s:%s] Start." % (self.certhost.hostname, self.certhost.service) )
        cmd = "osg-cert-request "
        cmd += "-host %s " % self.certhost.certhostname
        cmd += "-prefix %s " % self.certhost.prefix
        cmd += "-request %s " % self.certhost.tempreqfile
        cmd += "-email %s "  % self.certhost.config.get(self.certhost.hostname, "cert_email")
        cmd += "-affiliation %s " % self.certhost.globalconfig.get('OSGAdminPlugin', "affiliation")
        cmd += "-vo %s " % self.certhost.globalconfig.get('OSGAdminPlugin', "vo")
        cmd += "-ca %s " % self.certhost.globalconfig.get('OSGAdminPlugin', "ca")
        # cmd += "-pdir %s " %  
        (certbasedir,file) = os.path.split(self.certhost.tempcertfile) 
        
        cmd += "-sdir %s " % certbasedir
        if self.certhost.globalconfig.get('global', 'noclean') == 'true':
            cmd += "-noclean "
        #cmd += "-password %s " % self.passfile
        cmd += "-timeout %s " % self.certhost.globalconfig.get('OSGAdminPlugin', "timeout")                 
        #cmd = "osg-cert-request -V"
        self.log.debug("[%s:%s] Command is %s" % (self.certhost.hostname, self.certhost.service, cmd) )
        self.log.debug("[%s:%s] Done." % (self.certhost.hostname, self.certhost.service) )
        return cmd 

    def _makePassfile(self):
        (fd,pathname) = tempfile.mkstemp(".tmp", "pp", self.certhost.workdir)      
        self.passfile = pathname
        self.log.debug("[%s:%s] File descriptor=%s  File path=%s" % (self.certhost.hostname, 
                                                                     self.certhost.service,
                                                                     fd,
                                                                     self.passfile) )
        f=os.fdopen(fd, 'w')
        f.write(self.passphrase)
        f.close()
        
    
    def _deletePassfile(self):
        os.remove(self.passfile)

'''
   The following is necessary to trigger passphrase input on initial import, not just when class is instantiated 
   (which in this case only happens within a CertifyHost during threaded running.). 

'''
OSGAdminPlugin.getPassphrase()