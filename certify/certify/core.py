import os
import commands
import re
import logging
import time
import datetime
import socket
import urllib2
import sys
import threading
import traceback
from StringIO import StringIO

from ConfigParser import NoOptionError, ConfigParser, MissingSectionHeaderError
try:
    from email.mime.text import MIMEText
except:
    from email import MIMEText

class Certify(object):
    '''
    Top-level program object. Contains configs, lists of all hosts, and a ThreadManager to run.
    Each Thread  is a CertifyHost (which represents a host). 
    
    '''
    def __init__(self, config):
        self.log = logging.getLogger()
        # Establish this instance as global
        Certify.instance = self

        self.config = config
        self.hosts_config = ConfigParser()      
        
        # Counters for final summary
        self.lock = threading.Lock()
        self.numerror = 0
        self.numrenewed = 0
        self.numchecked = 0
        
        if self.config.get('global', 'noclean') == 'true':
            self.noclean = True
        else:
            self.noclean = False

        urilist = self._parseURIs()            
        for u in urilist:
            try:
                self.hosts_config.readfp(u)
            except MissingSectionHeaderError :
                self.log.debug("Encountered non-ini file config file %s, attempting conversion..." % u)
                #
                # This was tricky. ConfigParser doesn't throw exception until after reading some of the 
                # addinfourl object. Which means the seek pointer needs to be put back to the beginning of
                # the file:
                #                
                u.fp.seek(0)
                newreader = self._processSimple(u)
                self.log.debug("Processed non-ini config file %s. Contents: %s" % (u, newreader.readlines()))
                #
                # Likewise, the pointer on the StringIO object also must be set back to 0
                #               
                newreader.seek(0)
                self.hosts_config.readfp(newreader)
                
        self.workdir = self.config.get('global','workdir')
        self.workdir = os.path.expanduser(self.workdir)   
        if os.path.exists(self.workdir):
            pass
        else:
            os.mkdir(self.workdir)

        self.maxthreads = int(self.config.get('global', 'maxthreads'))
        self.maxmanagers = int(self.config.get('global', 'maxmanagers'))
        
        self.certhostinfolist = []
        self.certhostlist = []
        self.log.debug("About to process all sections in merged hosts config.") 
        self.log.debug('Hosts config: \n%s' % _safePrintConfig(self.hosts_config))
        for sect in self.hosts_config.sections():
            self.log.debug("Processing config for section/host '%s'..." % sect)
            self.nodelist = self._expandSectionHosts(sect)
            if len(self.nodelist) > 1:
                # add copies of configuration info from the range in section to a section only for
                # that host. 
                for h in self.nodelist:
                    allitems = self.hosts_config.items(sect)
                    #print allitems
                    self.hosts_config.add_section(h)
                    for (key,value) in allitems:
                        self.hosts_config.set(h, key,value)
                        
            for h in self.nodelist: 
                svclist=self.hosts_config.get(h,'services').split(',')
                for s in svclist:
                    #t = CertifyHost(self.config, self.hosts_config,sect,h,s)
                    # Make a tuple containing all info necessary per host/service
                    chinfo = (self.config, self.hosts_config,sect,h,s)
                    self.log.debug("Created CertifyHostInfo tuple for host '%s' and service '%s'" %(h,s))
                    self.certhostinfolist.append(chinfo)
                    self.certhostlist.append(chinfo)
        self.log.info('Processed configuration containing %d host/service items...' % len(self.certhostinfolist))        
        self.numhosts = len(self.certhostinfolist)
        
        # Allocate host/service items to one or more threadmanagers.
        self.threadmanagers = []
        tnum = 0
        while len(self.certhostinfolist) > 0:
            sublist = self.certhostinfolist[:self.maxthreads]
            self.certhostinfolist = self.certhostinfolist[self.maxthreads:]
            tm = CertifyThreadManager(sublist, config, tnum)
            self.log.debug("Threadmanager created with %d threads..." % len(sublist))
            self.threadmanagers.append(tm)
            tnum += 1
        
        self.log.info('%d Threadmanagers with %d maxthreads each.' % (len(self.threadmanagers), 
                                                                                                self.maxthreads)) 
        self.log.info('Will run %d threadmanagers concurrently. Max %d concurrent threads.' % (self.maxmanagers,
                                                                                               self.maxmanagers * self.maxthreads
                                                                                               ))
        self._loadPlugins()
        self.log.debug('Done.')
    
    def _loadPlugins(self):
        '''
        Do a module load of all plugins to allow them to do pre-processing work at module level if necessary.
        
        '''
        from certify.plugins import *
    
    def _processSimple(self, r):
        '''
        Takes file-like reader object 'reader' and reads it. Converting single entries, to ConfigParser
        sections:    host.domain.com  -> [host.domain.com]
        
        Returns new file-like object with converted contents. 
        
        '''
        nf = StringIO()
        for line in r.readlines():
            self.log.debug("_processSimple(): Handling line %s" % line)
            s = line.strip()
            if len(s) > 0 and s[0] != '#':
                ff = s.split()[0]
                self.log.debug("Creating host entry from simple hosts: %s " % ff)
                nf.write('[%s]\n' % ff)
        nf.seek(0)
        return nf
    
    
    def _expandSectionHosts(self, section):
        '''
        Parses host entries of the form 'host03--05.mydomain.com', returning a list:
        [ host03.mydomain.com, host04.mydomain.com, host05.mydomain.com ]
        
        '''
        if re.search("\d+--\d+",section):
            try:
                p = re.compile('(^.+?)\.')
                domain = "."+p.sub('', section, count=1).strip()
        
                p = re.compile('(\d+\--\d+.*)')
                hostBase = p.sub('', section, count=1).strip()
        
                #m = re.match(r'[a-zA-Z]+([\d,--]+)\..*', section)
                m = re.match(r'[a-zA-Z-]+([\d,--]+)\..*', section)
                range = m.group(1)
                num = range.split("--")[0]
                last = range.split("--")[1]
                width = len(num)
                
                hostList = []
                while num != last:
                    hostList += [hostBase + num + domain]
                    num = str(int(num)+1).zfill(width)
                hostList += [hostBase + last + domain]
                return hostList
            except Exception, error:
                self.log.error("Invalid format in hosts file for section %s: %s" % (section, error))
                raise
        else:
            hostList = [section.strip()]
            return hostList
        
        
    def _parseURIs(self):
        '''
        Looks at this Certify's hostURIs config, and returns a list of filelike objects
        for processing by ConfigParser. 
        
        '''
        self.log.debug('Begin...')
        hostsURIs = self.config.get('global','hostsuris').split(",")
        self.hostsCP=ConfigParser()
        count=0
        readerlist = []
        for h in hostsURIs:
            reader = self._convertURItoReader(h)
            readerlist.append(reader)
        self.log.debug('Returning list of %d reader(s).' % len(readerlist))
        return readerlist
    
            
    def _convertURItoReader(self, uri):
        '''
        Takes a URI string, opens it, and returns a filelike object of its contents.
        
        '''
        self.log.debug("Converting %s ..." % uri)        
        use_proxy=False
        try:
            p = self.config.get('global','proxy')
            use_proxy=True
        except:
            pass     
        try:
            hostsURI = uri.strip()
            if use_proxy:
                proxy_support = urllib2.ProxyHandler({'http': self.config.get('global','proxy')})
                opener = urllib2.build_opener(proxy_support)
            else:
                opener = urllib2.build_opener()
            urllib2.install_opener( opener )
            uri = urllib2.urlopen( hostsURI )
            firstLine = uri.readline().strip()
            if firstLine[0] == "<":
                raise Exception("First character was '<'. Probably a Proxy error.")
            hostsUriReader = urllib2.urlopen( hostsURI )
        
        except Exception:  
            errMsg = "Couldn't find URI %s (use file://... or http://... format)" % hostsURI
            self.log.error(errMsg)
            sys.exit(0)
        self.log.debug("Success. Returning reader." )
        return hostsUriReader
    
    def incrementError(self):
        '''
        Method to allow thread-safe tracking of outcomes.
        
        '''
        self.lock.acquire()
        self.numerror += 1
        self.lock.release()
    
    def incrementChecked(self):
        '''
        Method to allow thread-safe tracking of outcomes.
        
        '''
        self.lock.acquire()
        self.numchecked += 1        
        
        self.lock.release()        
    
    def incrementRenewed(self):
        '''
        Method to allow thread-safe tracking of outcomes.
        
        '''
        self.lock.acquire()
        self.numrenewed += 1
        self.lock.release()
    
    
    def execute_old(self):
        '''
        Pull out up to <maxmanagers> threadmanagers and run them simultaneously
                 
        '''
        self.log.debug('Certify.execute(): Begin...')
        self.log.info('Running...')
        alltms = self.threadmanagers
        while len(alltms) > 0:
            sublist = alltms[:self.maxmanagers]
            alltms = alltms[self.maxmanagers:]
            self.log.debug("Certify.execute(): Running %d Threadmanagers." % len(sublist))
            for tm in sublist:
                tm.start()
            for tm in sublist:
                tm.join()
            self.log.debug("Certify.execute(): %d Threadmanagers joined." % len(sublist))
        self.cleanup()
        
        self.log.info("Handled %d hosts. %d Checked. %d Created or renewed. %d Errors." % ( self.numhosts,
                                                                                self.numchecked,
                                                                                self.numrenewed,
                                                                                self.numerror))
        self.log.debug('Certify.execute(): Done.')

    def execute(self):
        '''
        Pull out up to <maxmanagers> threadmanagers and run them simultaneously, 
        replacing and starting finished threadmanagers. 
                 
        '''
        self.log.debug('Certify.execute(): Begin...')
        self.log.info('Running...')
        alltms = self.threadmanagers
        sublist = alltms[:self.maxmanagers]
        alltms = alltms[self.maxmanagers:]
        self.log.debug("Certify.execute(): Running %d Threadmanagers." % len(sublist))
        for tm in sublist:
            tm.start()
        while len(sublist) > 0:
            for tm in sublist:
                if not tm.isAlive():
                    self.log.debug("Certify.execute(): Threadmanager found finished. Replacing...")
                    tm.join()
                    sublist.remove(tm)
                    try:
                        newtm = alltms.pop()
                        sublist.append(newtm)
                        newtm.start() 
                    except IndexError:
                        self.log.debug("Certify.execute(): Last Threadmanager pop()ed...")
            time.sleep(1)  
        self.log.debug("Certify.execute(): %d Threadmanagers joined." % len(sublist))    
            
            
            
            
        self.cleanup()
        self.log.info("Handled %d hosts. %d Checked. %d Created or renewed. %d Errors." % ( self.numhosts,
                                                                                self.numchecked,
                                                                                self.numrenewed,
                                                                                self.numerror))
        self.log.debug('Certify.execute(): Done.')


    def list(self):
        '''
        Creates simple text representation of all host:service pairs in this Certify object. 
        
        '''
        # format of info tuple same as certhostinfolist: (config, config, section, host, service)
        self.log.debug('Begin...')
        stringlist = []
        for i in range(0,len(self.certhostlist)):
            (c1,c2,sec,h,svc) =self.certhostlist[i]
            s="%s:%s" %(h,svc)
            stringlist.append(s)
        stringlist.sort()
        s = '\n'.join(stringlist)
        self.log.debug('End.')
        return s


    def cleanup(self):
        '''
        Removes all contents of local temporary working directory.
        
        '''
        self.log.debug("Begin...")      
        if self.noclean : 
            self.log.info("Cleanup disabled.") 
        else:
            self.log.info("Performing post-run cleanup...")
            for h in self.hosts_config.sections():
            #for h in self.nodelist:
                hosttemproot = "%s/%s" % (self.workdir,h)
                self.log.debug("Removing all files below %s" % (hosttemproot))
                for (dirpath, dirnames, filenames) in os.walk(hosttemproot, False):
                    for fname in filenames:
                        df = os.path.join(dirpath, fname)
                        self.log.debug("Removing %s" % df)
                        try:
                            os.remove(df)
                        except OSError:
                            pass
                    
                    for dname in dirnames:
                        dd =  os.path.join(dirpath, dname)
                        self.log.debug("Removing %s" % dd)
                        try:
                            os.rmdir(dd)
                        except OSError:
                            pass
                try:
                    os.rmdir(hosttemproot)
                except OSError:
                    pass
                                                  
        self.log.debug("End.")        
    
    
    def _create_userconfig(self):
        user = os.environ.pop("USER")
        (status, passwdEntry) = commands.getstatusoutput("getent passwd "+ user) 
        home = passwdEntry.split(":")[5]
        config_file = os.path.expanduser("~/.certify/certify.conf")
        if not os.path.exists(config_file):
            if os.path.exists("/usr/share/doc/certify/certify.conf"):
                os.system("mkdir " + home + "/.certify; cp /usr/share/doc/certify/certify.conf " + home + "/.certify/certify.conf")
                print "Please configure " + config_file + " before running."
            sys.exit(1)


    def getCertify(cls):
        '''
        This class is a singleton. This method allows any running code to get a referenece to the single
        instance, in order to collect statistics. 
        
        '''
        if Certify.instance != None:
            return Certify.instance
        else:
            raise Exception("Something very wrong. Global Certify instance not set.")
    getCertify=classmethod(getCertify)


class CertifyThreadManager(threading.Thread):
    '''
        Class to handle multi-threaded operation. 

    '''
    def __init__(self, infolist, config, num=0):
        self.log = logging.getLogger()
        self.log.debug('Start...')
        threading.Thread.__init__(self)
        self.name = "TM-%d" % num
        self.config = config
        self.infolist = infolist
        self.threads = []
        
        self.log.debug("Threadmanager %s : initialization done." % self.name)        
        
    def run(self):
        '''
        Runs all contained threads and blocks until they all finish. 
        
        This is awkward, in the sense that the final join() loop will block until all the threads have
        finished (which is why we run multiple threadmanagers. 
        
        It would be better if we could simply define a max-threads, and when one finishes, immediately
        create another and run it.  
                
        '''
        self.log.debug('ThreadManager %s : Start...' % self.name)    
        for ch in self.infolist:
            (c,hc,se,h,s) = ch
            t = CertifyHost(c, hc,se,h,s)
            self.threads.append(t)
        for t in self.threads:
            t.start()        
        for t in self.threads:
            t.join()
        self.log.debug('ThreadManager %s : All threads joined. Done.' % self.name)



##############################################################################
#
# These are provided as a guide to implementing plugins. 
#
##############################################################################

class CertifyAdminInterface(object):
    '''
    Class with methods defining how requests get signed.
    Default implementation does self-signing. 
    
    1) Take a cert request and submit it to 3rd party (or self sign)
    2) Retrieve signed certificate. 
    
    '''

    def __init__(self, certhost):
        self.certhost = certhost
        
    def submitRequest(self):
        raise NotImplementedError
        
    def retrieveCertificate(self):
        raise NotImplementedError      
                    
    def renewCertificate(self):
        raise NotImplementedError

    def cleanup(self):
        raise NotImplementedError



class CertifyIOInterface(object):
    '''
    Class with methods to handle copying files and running commands. 

    '''
    def __init__(self, certhost):
        self.certhost = certhost

    def getCertificate(self):
        raise NotImplementedError

    def getRequest(self):
        raise NotImplementedError
        
    def putCertificate(self):
        raise NotImplementedError
    
    def executeCommand(self):
        raise NotImplementedError

    def makeDir(self, path):
        raise NotImplementedError

    def getFile(self, srcpath, destpath):
        raise NotImplementedError

    def putFile(self, srcpath, destpath):
        raise NotImplementedError
    
    def removeFile(self, path):
        raise NotImplementedError
        
    def setPerms(self, path, owner, group, mode):
        raise NotImplementedError

    def cleanup(self):
        raise NotImplementedError

    def checkAccess(self):
        raise NotImplementedError
    

class CertifyCertInterface(object):
    '''
    Class with methods defining how to generate certificate requests. 
    
    Any implementation must:
    1) Check to see if a certificate is expired/expiring. 
    2) trigger the generation of a new certificate request
    3) Generate certificate signing request. 
    4) Accept back signed cert. 
      
    '''
    
    def __init__(self, certhost):
        self.certhost = certhost
    
    def isCertExpired(self):     
        raise NotImplementedError

    def loadCertificate(self):
        raise NotImplementedError

    def dumpCertificate(self):
        raise NotImplementedError
                   
    def getExpirationUTC(self):
        raise NotImplementedError
    
    def createRequest(self):
        raise NotImplementedError

    def cleanup(self):
        raise NotImplementedError


class CertifyHost(threading.Thread):
    '''
        Class containing methods to handle a single host/service certificate.
        
        To function, needs one of each:
        CertifyAdminInterface -- to handle request signing.
        CertifyCertInterface -- to handle cert/request generation.
        CertifyIOInterface -- to handle local/remote file movement and command execution.
                
    '''
          
    def __init__(self, globalconfig, config, section, host, service ):
        '''
        Represents all the information and logic for handling a single unique certificate, i.e. a 
        particular Subject.
        
        '''
        self.log = logging.getLogger()
        self.log.debug("[%s:%s] Setting up..." % (host, service))
        threading.Thread.__init__(self)
        self.topcertify = Certify.getCertify()
        self.globalconfig = globalconfig
        self.config = config
        self.section = section 
        self.hostname = host
        try:
            self.certhostname = self.config.get(section, 'certhostname')
        except NoOptionError:
            self.certhostname = self.hostname
        
        try:
            self.subjectaltnames = self.config.get(section, 'subjectaltnames')
        except NoOptionError:
            self.subjectaltnames = "DNS:%s" % self.certhostname    
                
        self.service = service
        self.renewthreshold = int(self.config.get(section, 'renewthreshold'))
        
        #<prefix>,<owneruser>,<ownergroup>,<dir>,<[service|none]>
        (self.prefix, 
         self.owneruser,
         self.ownergroup,
         self.targetdir,
         self.svcprefix) = self.config.get(section,service).split(',')
        
        if self.svcprefix.lower() == "none":
            self.svcprefix=None
        
        self.commonname = ""
        if self.svcprefix:
            self.commonname += "%s/%s" % (self.svcprefix, self.certhostname)
        else:
            self.commonname += "%s" % self.certhostname
               
        # Capture "noclean" setting.
        if self.globalconfig.get('global', 'noclean') == 'true':
            self.noclean = True
        else:
            self.noclean = False 
        
        # Gather notification preferences
        self.email_on_replacement =  self.config.get(section, 'email_on_replacement')
        if self.email_on_replacement:
            self.email_from = self.config.get(section, 'email_from')
            self.email_to = self.config.get(section, 'email_to')
            self.email_subject = self.config.get(section, 'email_subject')
            self.smtp_host = self.config.get(section, 'smtp_host')
        
        # Establish "remote" target dir and paths to files for this host/service
        self.reqfile = "%s/%sreq.pem" % (self.targetdir, self.prefix)
        self.certfile = "%s/%scert.pem" % (self.targetdir, self.prefix)
        self.keyfile = "%s/%skey.pem" % (self.targetdir, self.prefix)

        # Establish local temporary working directory
        workdir = self.globalconfig.get('global','workdir')
        workdir = os.path.expanduser(workdir)
        self.temproot = "%s/%s" % ( workdir, self.hostname )        

        self.tempcertfile = "%s%s" % (self.temproot, self.certfile)
        self.tempreqfile = "%s%s" % (self.temproot, self.reqfile)
        self.tempkeyfile = "%s%s" % (self.temproot, self.keyfile)
              
        # In-memory X509 objects...
        self.certificate = None # This should be an X509 object.
        
        # This should point to the certificate object IFF it contains a private key.
        self.privatekey = None 
        
        self.keypair = None # X509 PKey object.
        self.request = None # X509 object
        
        # Load Plugin classes    
        ioklass = self._get_class_object(config, section, 'ioclass')
        self.ioplugin = ioklass(self)
        
        cklass = self._get_class_object(config, section, 'certclass')
        self.certplugin = cklass(self) 

        aklass =  self._get_class_object(config, section, 'adminclass')
        self.adminplugin = aklass(self)
        
        self.log.debug("[%s:%s] Done."% (host, service))    


    def run(self):
        '''
        This is the main functional loop of the Certify system for this CertifyHost. 
        
        '''
        self.log.debug("[%s:%s] Start..."% (self.hostname,self.service))
        try:
            self.log.debug("[%s:%s] Getting and loading cert."% (self.hostname,self.service))
            self.ioplugin.checkAccess()
            self.log.debug("[%s:%s] Access checked."% (self.hostname,self.service))
            self.ioplugin.getCertificate()
            self.certplugin.loadCertificate()
            self.log.debug("[%s:%s] Certificate retrieved and loaded."% (self.hostname,self.service))
            if self.certificate and self.certplugin.validateCert():
                exp = self.certplugin.getExpirationUTC()
                now = datetime.datetime.utcnow()
                ren = datetime.timedelta(self.renewthreshold) # timedelta in days    
                self.log.debug("[%s:%s] Expiration = %s Now = %s Threshold = %s" % ( self.hostname, 
                                                                                     self.service, 
                                                                                     exp, 
                                                                                     now, 
                                                                                     ren))            
                tdiff = exp - now
                if tdiff < ren:
                    self.log.info("[%s:%s] Expiration: (%s days) < threshold (%s days). Renewing..."% ( self.hostname, 
                                                                                                         self.service, 
                                                                                                         tdiff.days,
                                                                                                         ren.days))
                    self._newCertificate()
                    self.topcertify.incrementRenewed()
                    self._notifyreplacement()

                else:
                    self.log.info("[%s:%s] Expiration (%s days) > threshold (%s days). No renewal necessary."% (self.hostname, 
                                                                                                                 self.service, 
                                                                                                                 tdiff.days,
                                                                                                                 ren.days))
                    self.topcertify.incrementChecked()
            else:
                self.log.info("[%s:%s] No certificate or mismatched cert. Make new certificate..."% (self.hostname,self.service))
                self._newCertificate()
                self.topcertify.incrementRenewed()
                self._notifyreplacement()
        except Exception, e:
            self.log.error("[%s:%s] Significant error encountered. Aborting handling of this host. Message: %s " % (self.hostname,
                                                                                                                    self.service, 
                                                                                                                    e))
            self.topcertify.incrementError()
            #lstraceback.print_exc(file=sys.stdout)
        
        if not self.noclean:
            for p in [self.certplugin, self.ioplugin, self.adminplugin]:
                p.cleanup()
            self.cleanup()
        else:
            self.log.info("[%s:%s] Post run cleanup disabled (noclean). Leaving temp files intact." % (self.hostname,self.service))     
        self.log.debug("[%s:%s] Done." % (self.hostname,self.service))

    def _newCertificate(self):
        self.log.debug("[%s:%s] Start..."% (self.hostname,self.service))
        self.certplugin.makeRequest()
        self.log.info("[%s:%s] Creating new certificate."% (self.hostname,self.service))
        self.adminplugin.newCertificate()
        self.log.debug("[%s:%s] CertifyHost.certificate is %s."% (self.hostname, self.service, self.certificate))
        #self.log.debug("[%s:%s] Dumping certificate to temp."% (self.hostname,self.service))
        #self.certplugin.dumpCertificate()
        self.log.info("[%s:%s] Putting certificate to host/filesystem."% (self.hostname,self.service))
        self.ioplugin.putCertificate()
                
        self.log.debug("[%s:%s] Done."% (self.hostname,self.service))

    def _send_message(self, subject, messagestring):
        msg = MIMEText.MIMEText(messagestring)
        
        # me == the sender's email address
        # you == the recipient's email address
        msg['Subject'] = subject 
        msg['From'] = self.email_from
        msg['To'] = self.email_to
        
        # Send the message via our own SMTP server, but don't include the
        # envelope header.
        s = smtplib.SMTP(self.smtp_host)
        self.log.info("Sending email: %s" % msg.as_string())
        s.sendmail(self.email_from , [self.email_to], msg.as_string())
        s.quit()

    def _notifyreplacement(self):
        msgsub = "Certificate replaced on %s"
        msgtxt = "Certify replaced the %s certificate at %s on host %s." % (self.service,
                                                                           self.certfile,
                                                                           self.hostname)
        msgtxt += "Please take whatever action is needed to enable cert usage."
        self._send_message(msgsub, msgtxt)
        self.log.info("Sent notification of replacement to %s." % self.email_to)

    def __str__(self):
        return prettyObjectPrint(self)

        
    def _get_class_object(self, cfg, section, kind ):
        klass = cfg.get(section, kind)
        klassname = "certify.plugins.%s.%s" % (klass,klass)
        self.log.debug("Loading plugin class '%s'" % klassname)
        classobj = _get_class(klassname)
        return classobj

    def cleanup(self):
        self.log.debug("[%s:%s] Performing post-run cleanup..."% (self.hostname,self.service))

        #self.log.debug("[%s:%s] Done."% (self.hostname,self.service))        
        

#
# Dynamic class loader for plugins from Robert Brewer
# From http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/223972
#
import types

def _get_mod(modulePath):
    try:
        aMod = sys.modules[modulePath]
        if not isinstance(aMod, types.ModuleType):
            raise KeyError
    except KeyError:
        # The last [''] is very important!
        aMod = __import__(modulePath, globals(), locals(), [''])
        sys.modules[modulePath] = aMod
    return aMod


def _get_func(fullFuncName):
    """Retrieve a function object from a full dotted-package name."""
    
    # Parse out the path, module, and function
    lastDot = fullFuncName.rfind(u".")
    funcName = fullFuncName[lastDot + 1:]
    modPath = fullFuncName[:lastDot]
    
    aMod = _get_mod(modPath)
    aFunc = getattr(aMod, funcName)
    
    # Assert that the function is a *callable* attribute.
    assert callable(aFunc), u"%s is not callable." % fullFuncName
    
    # Return a reference to the function itself,
    # not the results of the function.
    return aFunc


def _get_class(fullClassName, parentClass=None):
    """Load a module and retrieve a class (NOT an instance).
    
    If the parentClass is supplied, className must be of parentClass
    or a subclass of parentClass (or None is returned).
    """
    aClass = _get_func(fullClassName)
    
    # Assert that the class is a subclass of parentClass.
    if parentClass is not None:
        if not issubclass(aClass, parentClass):
            raise TypeError(u"%s is not a subclass of %s" %
                            (fullClassName, parentClass))
    
    # Return a reference to the class itself, not an instantiated object.
    return aClass


def _safePrintConfig(c):
    '''
        Pretty-prints a ConfigParser object, and masks potential password options. 
    '''   
    s = ""
    seclist = c.sections()
    seclist.sort()
    for section in seclist:
        s +="[%s]\n" % section
        optionslist = c.options(section)
        optionslist.sort()
        for option in optionslist:
            if option.lower().find("pass") != -1:
                s += "   %s=%s\n" % ( option, "XXXXXXX")
            else:
                s += "   %s=%s\n" % ( option, c.get(section,option))   
    s += "\n"
    return s   


# other useful utilites for logging
def prettyObjectPrint(obj):
    '''
    Creates string representation of arbitrary complex objects. 
    From http://code.activestate.com/recipes/137951/
    '''    
    import types

    # There seem to be a couple of other types; gather templates of them
    MethodWrapperType = type(object().__hash__)
    
    objclass  = None
    objdoc    = None
    objmodule = '<None defined>'
    methods   = []
    builtins  = []
    classes   = []
    attrs     = []
    for slot in dir(obj):
        attr = getattr(obj, slot)
        if   slot == '__class__':
            objclass = attr.__name__
        elif slot == '__doc__':
            objdoc = attr
        elif slot == '__module__':
            objmodule = attr
        elif (isinstance(attr, types.BuiltinMethodType) or 
              isinstance(attr, MethodWrapperType)):
            builtins.append( slot )
        elif (isinstance(attr, types.MethodType) or
              isinstance(attr, types.FunctionType)):
            methods.append( (slot, attr) )
        elif isinstance(attr, types.TypeType):
            classes.append( (slot, attr) )
        else:
            attrs.append( (slot, attr) )
    
    # Organize them
    methods.sort()
    builtins.sort()
    classes.sort()
    attrs.sort()

    s = "[%s]\n" % objclass
    
    if attrs:
        for (attr, val) in attrs:
            if attr[0] != '_':
                s+="  %s = %s\n" %( attr,str(val))
    return s
