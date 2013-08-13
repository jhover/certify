#
# Local IO Plugin for Certify
# 
# Places all certificates in a local working directory. Typically ~/certificates, with one
# directory per host, creating system root paths from there. 
#
#
import os
import shutil
import logging
import commands
from certify.core import CertifyIOInterface, prettyObjectPrint

class LocalIOPlugin(CertifyIOInterface):
    '''
     Provides IO/Execute interface for local host, i.e. executes
     commands directly and copies files using shutil. 
     
     By "local" we mean that all files are placed in a hierarchy under
     the specified '[localioplugin] targetroot' value in certify.conf, 
     by hostname. E.g. ~/certificates/<hostname>/<normal-target-path> 
     
     Since the assumption is that Certify is running as a normal user
     no file ownership/permission changes are attempted under this dir. 
       
    '''

    def __init__(self, certhost):
        super(LocalIOPlugin, self).__init__(certhost)
        self.log = logging.getLogger()
        self.log.debug("[%s] Start..." % self.certhost.hostname )
        self.certhost = certhost
               
        # The full path and name to files on target host:
        tr = certhost.globalconfig.get('localioplugin','targetroot')
        self.targetroot= os.path.expanduser(tr)

        if not os.path.exists(self.targetroot):
            os.makedirs(self.targetroot)

        self.hostroot= "%s/%s" % (self.targetroot, self.certhost.hostname)
        if not os.path.exists(self.hostroot):
            os.makedirs(self.hostroot)        
        
        # For local io, rewrite all file paths relative to hostroot. 
        self.certhost.certfile = "%s%s" % (self.hostroot, self.certhost.certfile)
        self.log.debug('[%s:%s] Rewriting certfile: %s'% (self.certhost.hostname, 
                                                         self.certhost.service,
                                                         self.certhost.certfile))
        self.certhost.keyfile = "%s%s" % (self.hostroot, self.certhost.keyfile)
        self.log.debug('[%s:%s] Rewriting keyfile: %s'% (self.certhost.hostname, 
                                                         self.certhost.service,
                                                         self.certhost.keyfile))
        self.certhost.reqfile = "%s%s" % (self.hostroot, self.certhost.reqfile)
        self.log.debug('[%s:%s] Rewriting reqfile: %s'% (self.certhost.hostname, 
                                                         self.certhost.service,
                                                         self.certhost.reqfile))
        self.log.debug("[%s] Done." % self.certhost.hostname ) 

    def checkAccess(self):
        '''
        No need to verify connectivity for local.
        '''
        pass


    def getCertificate(self):
        '''
            Gets cert and key data however necessary, places them in a file, and
            sets certhost.certfile and certhost.keyfile
            
            If cert doesn't exist. Doesn't do anything.
                        
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        self.getFile(self.certhost.certfile, self.certhost.tempcertfile, )
        self.log.debug('[%s:%s] End.'% (self.certhost.hostname, self.certhost.service))

        
    def putCertificate(self):
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        self.putFile(self.certhost.tempcertfile, self.certhost.certfile )
        self.putFile(self.certhost.tempkeyfile, self.certhost.keyfile )
        self.log.debug('[%s:%s] End.'% (self.certhost.hostname, self.certhost.service))


    def putCertificateOld(self):
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        self.putFile(self.certhost.tempcertfile, self.certhost.certfile )
        self.log.debug('[%s:%s] End.'% (self.certhost.hostname, self.certhost.service))

    def getRequest(self):
        '''
            Gets request into temp area.  
                        
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        self.getFile(self.certhost.reqfile, self.certhost.tempreqfile, )
        self.log.debug('[%s:%s] End.'% (self.certhost.hostname, self.certhost.service))
 

    def executeCommand(self, cmd):
        '''
        Executes provided command on the target host.
        
        For this plugin, the paths relevant to this plugin have been modified to prepend
        the localIOplugin /<targetroot>/<hostname>. 
        
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        self.log.debug('[%s:%s] Executing command "%s" '% (self.certhost.hostname, 
                                                        self.certhost.service,
                                                        cmd))
        so = commands.getstatusoutput(cmd)
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))
        return so


    def makeDir(self, path):
        '''
        Makes directory <path> under self.hostroot.
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        self.log.debug('[%s:%s] Making directory at %s'% (self.certhost.hostname, 
                                                          self.certhost.service,
                                                          path))
        if not os.path.exists(path):
            os.makedirs(path)
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))
 

    def getFile(self, srcpath, targetpath):
        '''
        Retrieves file from cert area to temporary area. 
        '''
        self.log.debug('[%s:%s] Copying file %s to %s.'% (self.certhost.hostname, 
                                                          self.certhost.service,
                                                          srcpath,
                                                          targetpath))
        if os.path.exists(srcpath):
            (path, basename) = os.path.split(targetpath)
            if not os.path.exists(path):
                self.log.debug("[%s:%s] Directory %s doesn't exist, creating..."% (self.certhost.hostname, 
                                                                                   self.certhost.service,
                                                                                   path))
                os.makedirs(path)
            self.log.debug('[%s:%s] Copying %s to %s...'% (self.certhost.hostname, 
                                                           self.certhost.service,
                                                           srcpath,
                                                           targetpath))       
            shutil.copy(srcpath, targetpath)
        else:
            self.log.debug("[%s:%s] File %s doesn't exist. Removing..."% (self.certhost.hostname, 
                                                              self.certhost.service,
                                                              srcpath))
            try:
                os.remove(targetpath)
            except OSError:
                pass        
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))
 

    def putFile(self, srcpath, targetpath):
        '''
        Puts file from temp area to cert area. 
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        if os.path.exists(srcpath):
            (path, basename) = os.path.split(targetpath)
            if not os.path.exists(path):
                self.log.debug("[%s:%s] Directory %s doesn't exist, creating..."% (self.certhost.hostname, 
                                                                                   self.certhost.service,
                                                                                   path))
                os.makedirs(path)
            self.log.debug('[%s:%s] Copying %s to %s...'% (self.certhost.hostname, 
                                                           self.certhost.service,
                                                           srcpath,
                                                           targetpath))       
            shutil.copy(srcpath, targetpath)
        else:
            self.log.debug("[%s:%s] File %s doesn't exist."% (self.certhost.hostname, 
                                                              self.certhost.service,
                                                              srcpath))
            
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))
 
    def setPerms(self, path, owner, group, mode):
        '''
        Because this IO is local, we are assuming it can't and doesn't need to set 
        ownership or permissions. 
        
        '''
        self.log.debug("[%s:%s] Local IO Plugin doesn't need to adjust permissions."% (self.certhost.hostname, 
                                                                                       self.certhost.service))


    def removeFile(self, path):
        '''
        Removes file at path.
        '''
        self.log.debug('[%s:%s] Start...'% (self.certhost.hostname, self.certhost.service))
        if os.path.exists(path):
            self.log.debug("[%s:%s] Removing file %s " % (self.certhost.hostname, 
                                                self.certhost.service,
                                                path))
            try:
                os.remove(path)
            except OSError:
                pass 
        else:
            self.log.debug("[%s:%s] File %s doesn't exist" % (self.certhost.hostname, 
                                                self.certhost.service,
                                                path))
        self.log.debug('[%s:%s] Done.'% (self.certhost.hostname, self.certhost.service))
        
    def cleanup(self):
        '''
        Cleans up local temporary files for this host.
        '''
        self.log.debug("[%s:%s] Begin..." % ( self.certhost.hostname, self.certhost.service))
        
        self.log.debug("[%s:%s] Done." % ( self.certhost.hostname, self.certhost.service))

    