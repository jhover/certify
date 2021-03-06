import logging
import os
import sys
import commands
import getpass
import tempfile
import threading

try:
    import pexpect
except ImportError:
    print "This Certify plugin (OSGAdmin) requires pexpect. Please install."
    sys.exit(0)

   
from certify.core import CertifyAdminInterface

class OSGAdminPlugin(CertifyAdminInterface):
    
    # Used to control access to the process current working directory. 
    # The OSG grid admin command puts files in the current dir. 
    cwdlock = threading.Lock()

  
    def __init__(self, certhost):
        super(OSGAdminPlugin, self).__init__(certhost)
        self.log = logging.getLogger()
        self.log.debug("[%s:%s] OSGAdminPlugin() Begin..." % ( self.certhost.hostname, self.certhost.service))  
        self.passphrase = OSGAdminPlugin.getPassphrase()
        self.log.debug("[%s:%s] Passphrase set from user input."% (self.certhost.hostname, 
                                              self.certhost.service))           
        self.testmode = self.certhost.globalconfig.getboolean('osgadminplugin', 'testmode')
        self.vo = self.certhost.globalconfig.get('osgadminplugin', 'vo')
        self.log.debug("[%s:%s] OSGAdminPlugin() Overriding default local tempfile names..." % ( self.certhost.hostname, 
                                                                                                 self.certhost.service))
        if self.certhost.svcprefix:
            certfilename = "%s-%s.pem" % (self.certhost.svcprefix, self.certhost.certhostname) 
            keyfilename = "%s-%s-key.pem" % (self.certhost.svcprefix, self.certhost.certhostname)
        else:
            certfilename = "%s.pem" % (self.certhost.certhostname) 
            keyfilename = "%s-key.pem" % (self.certhost.certhostname)            
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
        
        self.log.debug("[%s:%s] OSGAdminPlugin initialized: testmode=%s vo=%s" % ( self.certhost.hostname, 
                                                                                   self.certhost.service,
                                                                                   self.testmode,
                                                                                   self.vo)) 

    def __str__(self):
        s = "OSGAdminPlugin [%s:%s]: " % (self.certhost.hostname, self.certhost.service)
        s += "testmode=%s " % self.testmode
        s += "vo=%s" % self.vo
        return s
      
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
        try:
            os.remove(self.certhost.tempcertfile)
            os.remove(self.certhost.tempkeyfile)
        except OSError:
            # We don't care if they already don't exist. 
            pass
              
        # change working directory to tmproot
        self.log.debug("[%s:%s] Changing dir to %s" % (self.certhost.hostname, 
                                                       self.certhost.service,
                                                       self.certhost.temproot
                                                       ))
        cmd = self._buildGridadminCommand() 
        
        # We need to acquire lock so that the following block can only occur in one thread at a time. 
        OSGAdminPlugin.cwdlock.acquire()
        self.log.debug("[%s:%s] Acquired cwd lock." % (self.certhost.hostname,
                                                              self.certhost.service) )
        try:
            os.chdir(self.certhost.temproot)
                  
            self.log.info("[%s:%s] Running request command..." % (self.certhost.hostname,
                                                                  self.certhost.service) )
            process = pexpect.spawn(cmd, timeout=300)
            process.expect([".pem':"])
            self.log.debug("[%s:%s] Providing passphrase to command..."% (self.certhost.hostname, 
                                                                          self.certhost.service))
            process.sendline(self.passphrase)
            process.expect([pexpect.EOF])
            
        except Exception:
            pass
        self.log.debug("[%s:%s] Releasing cwd lock." % (self.certhost.hostname,
                                                                  self.certhost.service) )
        OSGAdminPlugin.cwdlock.release()        
        self.log.debug("[%s:%s] Command output: %s"% (self.certhost.hostname, 
                                                      self.certhost.service, 
                                                      process.before.strip() )  ) 
        
        if os.path.isfile(self.certhost.tempcertfile) and os.path.isfile(self.certhost.tempkeyfile):
            self.log.debug("[%s:%s] Temp cert and key files exist at expected paths." % ( self.certhost.hostname, 
                                                      self.certhost.service))
        else:
            raise Exception("[%s:%s] Serious Error. Request completed, but temp cert and/or key files don't exist." % ( self.certhost.hostname, 
                                                      self.certhost.service))
            
        
        
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
                # Set temp filenames correctly
        if self.certhost.svcprefix:
            certfilename = "%s-%s.pem" % (self.certhost.svcprefix, self.certhost.certhostname) 
            keyfilename = "%s-%s-key.pem" % (self.certhost.svcprefix, self.certhost.certhostname)
        else:
            certfilename = "%s.pem" % (self.certhost.certhostname) 
            keyfilename = "%s-key.pem" % (self.certhost.certhostname)            
        self.certhost.tempcertfile = "%s/%s" % (self.certhost.temproot, certfilename) 
        self.certhost.tempkeyfile = "%s/%s" % (self.certhost.temproot, keyfilename) 
                
        # If it exists, remove current cert file from temp (since we're about to make a new one).
        try:
            os.remove(self.certhost.tempcertfile)
            os.remove(self.certhost.tempkeyfile)
        except OSError:
            pass
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
        cmd += "--vo %s " % self.vo
        if self.testmode:
            cmd += "-T " 
        self.log.debug("[%s:%s] Command is '%s'" % (self.certhost.hostname, self.certhost.service, cmd) )
        self.log.debug("[%s:%s] Done." % (self.certhost.hostname, self.certhost.service) )
        return cmd 

'''
   The following is necessary to trigger passphrase input on initial import, not just when class is instantiated 
   (which in this case only happens within a CertifyHost during threaded running.). 

'''
OSGAdminPlugin.getPassphrase()

