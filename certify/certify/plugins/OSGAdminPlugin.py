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
        cmd = "which osg-gridadmin-cert-request"
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
              
        
        # change working directory to tmproot
        self.log.debug("[%s:%s] Changing dir to %s" % (self.certhost.hostname, 
                                                       self.certhost.service,
                                                       self.certhost.temproot
                                                       ))
        os.chdir(self.certhost.temproot)
        
        # build command
        cmd = self._buildGridadminCommand() 
       
        
        # run it using pexpect        
        #
        #  Please enter the pass phrase for '/home/jhover/.globus/userkey.pem':
        #Connection object created.
        # About to make request to https://oim.grid.iu.edu:443/oim/rest?action=user_info
        # About to get response...
        # Waiting for response from Quota Check API. Please wait.
        # Beginning request process for griddev02.racf.bnl.gov
        # Generating certificate...
        # Id is: 1129
        # Connecting to server to approve certificate...
        # Issuing certificate...
        # . 
        # Certificate written to ./griddev02.racf.bnl.gov.pem
        #
        #

        self.log.info("[%s:%s] Running request command..." % (self.certhost.hostname,
                                                              self.certhost.service) )
        process = pexpect.spawn(cmd, timeout=300)
        process.expect([".pem':"])
        self.log.debug("[%s:%s] Providing passphrase to command..."% (self.certhost.hostname, 
                                                                      self.certhost.service))
        process.sendline(self.passphrase)
        process.expect([pexpect.EOF])
        self.log.debug("[%s:%s] Command output: %s"% (self.certhost.hostname, 
                                                      self.certhost.service, 
                                                      process.before.strip() )  ) 
        
        if self.certhost.svcprefix:
            certfilename = "%s-%s.pem" % (self.certhost.svcprefix, self.certhost.hostname) 
            keyfilename = "%s-%s-key.pem" % (self.certhost.svcprefix, self.certhost.hostname)
        else:
            certfilename = "%s.pem" % (self.certhost.hostname) 
            keyfilename = "%s-key.pem" % (self.certhost.hostname)            
        self.certhost.tempcertfile = "%s/%s" % (self.certhost.temproot, certfilename) 
        self.certhost.tempkeyfile = "%s/%s" % (self.certhost.temproot, keyfilename) 
        
        self.log.debug("[%s:%s] Reset temp cert filename: %s" % (self.certhost.hostname,
                                                                 self.certhost.service,
                                                                 self.certhost.tempcertfile                                                                 
                                                                 ))
        self.log.debug("[%s:%s] Reset temp key filename: %s" % (self.certhost.hostname,
                                                                 self.certhost.service,
                                                                 self.certhost.tempkeyfile                                                                 
                                                                 ))        
        
        
    def retrieveCertificate(self):
        self.log.debug("[%s:%s] Start." % (self.certhost.hostname, self.certhost.service) ) 
        # Confirm existence of tmpcertfile
        if not os.path.exists(self.certhost.tempcertfile):
            raise Exception("Certificate has not been issued!!! Failing.")
        self.log.debug("[%s:%s] Done." % (self.certhost.hostname, self.certhost.service) )
    
    def newCertificate(self):
        self.log.debug("[%s:%s] Start." % (self.certhost.hostname, self.certhost.service) )  
        self.submitRequest()
        #self.retrieveCertificate()
        self.log.debug("[%s:%s] Done." % (self.certhost.hostname, self.certhost.service) )        
        
    def renewCertificate(self):
        self.log.debug("[%s:%s] Start." % (self.certhost.hostname, self.certhost.service) )
        self.submitRequest()
        #self.retrieveCertificate()
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

    osg-gridadmin-cert-request 
  
    -k PKEY, --pkey=PKEY  Specify Requestor's private key (PEM Format).  If not
                        specified             will take the value of
                        X509_USER_KEY or $HOME/.globus/userkey.pem
    -c CERT, --cert=CERT  Specify Requestor's certificate (PEM Format).  If not
                        specified             will take the value of
                        X509_USER_CERT or $HOME/.globus/usercert.pem
    -v VO name, --vo=VO name
                        Specify the VO for the host request
    -T, --test            Run in test mode
    -t TIMEOUT, --timeout=TIMEOUT
                        Specify the timeout in minutes
    -q, --quiet           don't print status messages to stdout
    -V, --version         Print version information and exit

  Hostname Options:
    Use either of these options. Specify hostname as a single hostname
    using -H/--hostname or specify from a file using -f/--hostfile.

    -H HOSTNAME, --hostname=HOSTNAME
                        Specify the hostname or service/hostname for which you
                        want to request              the certificate for.  If
                        specified -f/--hostfile will be ignored
    -f HOSTFILE, --hostfile=HOSTFILE
                        Filename with one hostname or service/hostname per
                        line

        
        '''
        self.log.debug("[%s:%s] Start." % (self.certhost.hostname, self.certhost.service) )
        cmd = "osg-gridadmin-cert-request "        
        cmd += "--hostname %s " % self.certhost.commonname
        cmd += "--vo %s " % self.certhost.globalconfig.get('osgadminplugin', "vo")
        
       
        self.log.debug("[%s:%s] Command is '%s'" % (self.certhost.hostname, self.certhost.service, cmd) )
        self.log.debug("[%s:%s] Done." % (self.certhost.hostname, self.certhost.service) )
        return cmd 

    #def _makePassfile(self):
    #    (fd,pathname) = tempfile.mkstemp(".tmp", "pp", self.certhost.workdir)      
    #    self.passfile = pathname
    #    self.log.debug("[%s:%s] File descriptor=%s  File path=%s" % (self.certhost.hostname, 
    #                                                                 self.certhost.service,
    #                                                                 fd,
    #                                                                 self.passfile) )
    #    f=os.fdopen(fd, 'w')
    #    f.write(self.passphrase)
    #    f.close()
        
    
    #def _deletePassfile(self):
    #    os.remove(self.passfile)

'''
   The following is necessary to trigger passphrase input on initial import, not just when class is instantiated 
   (which in this case only happens within a CertifyHost during threaded running.). 

'''
OSGAdminPlugin.getPassphrase()

