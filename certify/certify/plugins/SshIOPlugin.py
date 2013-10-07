#
#  SSH IO Plugin for Certify
#  uses SSH/SCP to copy files back and forth between run host and target host
#
#
#
import os 
import shutil
import logging
import commands
from certify.core import CertifyIOInterface
from certify.core import IOPluginConnectionException

try:
    import pxssh
except ImportError:
    print "This Certify plugin (SshIOPlugin) requires pexpect (with pxssh). Please install."
    sys.exit(0)




class SshIOPluginConnectionException(IOPluginConnectionException):
    pass



class SshIOPlugin(CertifyIOInterface):
    '''
     Provides IO/Execute interface for a remote host, i.e. executes
     commands via ssh and copies files using scp.
     
     All functionality of this plugin assumes that SSH key access as root (or other login user)
     to remote host has been set up, and ssh-agent with proper identity is running.
    
     If used as a non-root user, it is vital that all paths be writable by that user. 
    
    '''
    def __init__(self, certhost):
        super(SshIOPlugin, self).__init__(certhost)
        self.log = logging.getLogger()
        self.log.debug("[%s:%s] Start..." % ( self.certhost.hostname, self.certhost.service ))        
        self.log.debug("[%s:%s] Targetpath=%s" % (self.certhost.hostname, 
                                                  self.certhost.service,
                                                  self.certhost.certfile )  )
        self.log.debug("[%s:%s] certfile=%s" % (self.certhost.hostname,self.certhost.service, self.certhost.certfile )  )
        self.connecttimeout = self.certhost.globalconfig.get('sshioplugin','connecttimeout')
        self.loginuser = self.certhost.globalconfig.get('sshioplugin','loginuser')
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service )) 

    def __str__(self):
        s = "SshIOPlugin [%s:%s]: " % (self.certhost.hostname, self.certhost.service)
        s += "connecttimeout=%s " % self.connecttimeout
        s += "loginuser=%s" % self.loginuser
        return s

    def checkAccess(self):
        '''
           In this context, check to be sure we are allowed to connect to the host. 
           Need to use pexpect to notice when 'root@<host>'s password:' is returned, and then
           throw exception for no access. 
        '''
        self.log.debug('[%s:%s] Checking access to host using login %s@%s.'% (self.certhost.hostname, 
                                                                              self.certhost.service,
                                                                              self.loginuser,
                                                                              self.certhost.hostname 
                                                                              ))
        try:
            s = pxssh.pxssh()
            s.login(self.certhost.hostname,self.loginuser, login_timeout=15)
            s.sendline('/bin/hostname')
            s.prompt()
            o = s.before
            self.log.debug('[%s:%s] Verified connectivity to %s.'% (self.certhost.hostname, 
                                                                    self.certhost.service,
                                                                    o))
            s.logout()
        except Exception, e:
            raise SshIOPluginConnectionException("No SSH key, or no such host.")
            


    def getCertificate(self):
        '''
            Gets cert and key files however necessary, places them in certhost.tempcertfile
            If cert doesn't exist. Doesn't do anything.
            
            As this is the first command to talk to the remote host, we need to handle any 
            connectivity issues or other SSH-related interaction issues here. 
                        
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))        
        try:
            self.getFile( self.certhost.certfile, 
                           self.certhost.tempcertfile)            
            self.getFile( self.certhost.keyfile, 
                           self.certhost.tempkeyfile)              
        except Exception, e:
            self.log.debug('[%s:%s] No certfile %s and/or keyfile %s on remote host. Exception: %s'% (self.certhost.hostname,
                                                                                    self.certhost.service, 
                                                                   self.certhost.certfile,
                                                                   self.certhost.keyfile,
                                                                   e ))
        self.log.debug('[%s:%s] Retrieved host certificate.'% (self.certhost.hostname, self.certhost.service))
        #self.log.debug('[%s:%s] End.'% (self.certhost.hostname, self.certhost.service))



    def putCertificate(self):
        self.log.debug('[%s:%s] Start...'% ( self.certhost.hostname, self.certhost.service))
        
        try:
            self.putFile(  self.certhost.tempcertfile,
                            self.certhost.certfile)                
        except Exception, e:
            self.log.error('[%s:%s] Error copying certfile to %s on remote host.'% (self.certhost.hostname,
                                                                                    self.certhost.service, 
                                                                                 self.certhost.certfile ))
        # Set perms on cert
        try:
            self.setPerms(self.certhost.certfile, 
                           owner=self.certhost.owneruser, 
                           group=self.certhost.ownergroup)
        except Exception, e:
            self.log.error('[%s:%s] Error fixing permissions on %s on remote host.'% (self.certhost.hostname,
                                                                                    self.certhost.service,
                                                                                    self.certhost.certfile )) 
        
        try:
            self.putFile(  self.certhost.tempkeyfile,
                            self.certhost.keyfile)                
        except Exception, e:
            self.log.error('[%s:%s] Error copying keyfile to %s on remote host.'% (self.certhost.hostname,
                                                                                    self.certhost.service, 
                                                                                 self.certhost.keyfile ))

        # Set perms on key                                                                          
        try:
            self.setPerms(self.certhost.keyfile, 
                           owner=self.certhost.owneruser, 
                           group=self.certhost.ownergroup,
                           mode=600)
        except Exception, e:
            self.log.error('[%s:%s] Error fixing permissions on %s on remote host.'% (self.certhost.hostname,
                                                                                      self.certhost.service, 
                                                                                      self.certhost.certfile ))        
        self.log.debug('[%s:%s] End.'% ( self.certhost.hostname, self.certhost.service))               



    def putCertificateOld(self):
        self.log.debug('[%s:%s] Start...'% ( self.certhost.hostname, self.certhost.service))
        
        try:
            self.putFile(  self.certhost.tempcertfile,
                            self.certhost.certfile)                
        except Exception, e:
            self.log.error('[%s:%s] Error copying certfile to %s on remote host.'% (self.certhost.hostname,
                                                                                    self.certhost.service, 
                                                                                 self.certhost.certfile ))
        # Set perms on cert
        try:
            self.setPerms(self.certhost.certfile, 
                           owner=self.certhost.owneruser, 
                           group=self.certhost.ownergroup)
        except Exception, e:
            self.log.error('[%s:%s] Error fixing permissions on %s on remote host.'% (self.certhost.hostname,
                                                                                    self.certhost.service,
                                                                                    self.certhost.certfile )) 
        
        # Move <keyfile>.new to <keyfile>
        try:
            cmd = "mv -f %s.new %s" % ( self.certhost.keyfile, self.certhost.keyfile)
            self.executeCommand(cmd)
        except Exception, e:
            self.log.error('[%s:%s] Error moving keyfile %s from .new to final.'% (self.certhost.hostname,
                                                                                    self.certhost.service,
                                                                                    self.certhost.keyfile )) 

        # Set perms on key                                                                          
        try:
            self.setPerms(self.certhost.keyfile, 
                           owner=self.certhost.owneruser, 
                           group=self.certhost.ownergroup)
        except Exception, e:
            self.log.error('[%s:%s] Error fixing permissions on %s on remote host.'% (self.certhost.hostname,
                                                                                    self.certhost.service, 
                                                                                 self.certhost.certfile ))        
        self.log.debug('[%s:%s] End.'% ( self.certhost.hostname, self.certhost.service))  



    def getRequest(self):
        '''
            Gets request into temp area. 
                        
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        try:
            self.getFile( self.certhost.reqfile, 
                           self.certhost.tempreqfile)                
        except Exception, e:
            self.log.debug('[%s:%s] No request %s on remote host. Exception: %s'% (self.certhost.hostname,
                                                                                    self.certhost.service, 
                                                                   self.certhost.reqfile,
                                                                   e ))
        self.log.info('[%s:%s] Retrieved request %s.'% (self.certhost.hostname, 
                                                        self.certhost.service,
                                                        self.certhost.reqfile))
        self.log.debug('[%s:%s] End.'% (self.certhost.hostname, self.certhost.service))



    def executeCommand(self, cmd):
        '''
        Executes given command on remote host. 
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        cmd = 'ssh -q -n %s@%s "bash -l -c \\"%s\\""' % (self.loginuser,
                                                         self.certhost.hostname, 
                                                         cmd)
                
        self.log.debug("[%s:%s] Executing remote command: %s " % (self.certhost.hostname, 
                                                                 self.certhost.service, 
                                                                 cmd))
        (s, o) = commands.getstatusoutput(cmd)
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))
        return (s,o)


    def getFile(self, srcpath, destpath):
        '''
        Creates local parent directories and copies specified file from remote host at srcpath
        to local host at destpath. 
        
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))

        # make local directory path in case it doesn't exist
        self.log.debug("[%s:%s] Creating local directories..." % ( self.certhost.hostname, self.certhost.service))
        (rootpath, tail) = os.path.split(destpath)
        if not os.path.exists(rootpath):
            os.makedirs(rootpath)
        # erase current file, so that if it isn't retrieved we know about it.
        try:
            os.remove(destpath)
        except:
            pass
        # prepare command to copy to local        
        cmd = "scp -q -o ConnectTimeout=%s %s@%s:%s %s" % (self.connecttimeout,
                                                           self.loginuser,
                                                           self.certhost.hostname, 
                                                           srcpath, 
                                                           destpath)                                                                                 
        self.log.debug("[%s:%s] Executing remote command: %s" % (self.certhost.hostname,
                                                                 self.certhost.service,
                                                                 cmd))
        (status, output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Remote command output: %s" % (self.certhost.hostname,
                                                              self.certhost.service,
                                                               output.strip() ))
        if status:
            raise Exception("Error getting file %s from host %s" % (remotepath,
                                                                    self.certhost.hostname))
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))


    def putFile(self, srcpath, destpath):
        '''
          Creates remote parent directories as needed with ssh.
          Copies file via scp from local host at srcpath to remote host at destpath, creating 
          parent directories as needed.
        
          Return values for various conditions
          scp
          0   OK
          1   No such file
          1   Host key checking failed. 
          
          
          ssh
          0   OK
          127   No such file/directory
          255 ? Host key checking failed?
                        
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))

        (rootpath, tail) = os.path.split(destpath)
        # make remote directory in case it doesn't exist
        cmd = "ssh -n -q -f %s@%s mkdir -p %s " % ( self.loginuser,
                                                    self.certhost.hostname, 
                                                    rootpath)
        self.log.debug("[%s:%s] Executing remote command: %s" % (self.certhost.hostname,
                                                                 self.certhost.service,
                                                                 cmd))
        (status, output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Remote command output: %s" % (self.certhost.hostname,
                                                              self.certhost.service,
                                                              output.strip()))
        # prepare copy command        
        cmd = "scp -q -o ConnectTimeout=%s %s %s@%s:%s " % (self.connecttimeout,
                                                                 srcpath,
                                                                 self.loginuser,
                                                                 self.certhost.hostname, 
                                                                 destpath)
        self.log.debug("[%s:%s] Executing remote command: %s" % (self.certhost.hostname,
                                                                 self.certhost.service,
                                                              cmd))
        (status, output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Remote command output: %s" % (self.certhost.hostname,
                                                              self.certhost.service,
                                                           output.strip() ))
        if status:
            raise Exception("[%s:%s] Error putting file %s." % (self.certhost.hostname, 
                                                                self.certhost.service,
                                                                destpath ))
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))



    def makeDir(self, path):
        '''
        Make directory and parent directories at path.
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        cmd = "mkdir -p %s" % path
        o = self.executeCommand(cmd)
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))
        return o


    
    def setPerms(self, path, owner, group, mode=644):
        '''
        
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        # adjust ownership of file...
        cmd = 'ssh -n -f -q %s@%s "chown %s:%s %s " ' % ( self.loginuser,
                                                          self.certhost.hostname,
                                                          owner,
                                                          group, 
                                                          path  )
        self.log.debug("[%s:%s] Executing remote command: %s" % (self.certhost.hostname,
                                                                 self.certhost.service,
                                                                 cmd))
        (status, output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Remote command output: %s" % (self.certhost.hostname,
                                                              self.certhost.service,
                                                              output.strip()))  
        # Adjust mode
        cmd = 'ssh -n -f -q %s@%s "chmod %s %s " ' % ( self.loginuser,
                                                       self.certhost.hostname,
                                                       mode,
                                                       path  )
        self.log.debug("[%s:%s] Executing remote command: %s" % (self.certhost.hostname,
                                                                 self.certhost.service,
                                                                 cmd))
        (status, output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Remote command output: %s" % (self.certhost.hostname,
                                                              self.certhost.service,
                                                              output.strip())) 
                
        
        
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))
         
 
    def removeFile(self, path):
        '''
        Remove file on target host at path.
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        # adjust ownership of file...
        cmd = 'ssh -n -f -q %s@%s "rm -f %s" ' % ( self.loginuser,
                                                   self.certhost.hostname, 
                                                   path  )
        self.log.debug("[%s:%s] Executing remote command: %s" % (self.certhost.hostname,
                                                                 self.certhost.service,
                                                                 cmd))
        (status, output) = commands.getstatusoutput(cmd)
        self.log.debug("[%s:%s] Remote command output: %s" % (self.certhost.hostname,
                                                              self.certhost.service,
                                                              output.strip()))  
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))

    def cleanup(self):
        '''
        Cleans up local temporary files for this host.
        '''
        self.log.debug("[%s:%s] Begin..." % ( self.certhost.hostname, self.certhost.service))
        
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))
