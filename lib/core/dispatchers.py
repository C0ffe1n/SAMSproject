# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import logging
import datetime
import os
import ldap
import shutil
import time
from lib.config import Config
from lib.core.postman import PostMaster
from lib.core.analyzers import AnalyzerMalware
from lib.exceptions import SAMSPostMasterConnectError, SAMSPostMasterLoginError, SAMSPostMasterFetchError, SAMSAnalysisError, SAMSDatabaseError
from lib.core.mailfilter import MailFilterManager
from lib.core.dbmanager import DBManager
from lib.core.reporter import Reporter
from lib.common.constants import _ANALYSIS_DIR, _TMP_DIR, _QUEUE_DIR, _BACKUP_DIR

log = logging.getLogger(__name__)

class EventDispatcher(object):
    """
        Base class Dispatcher
    """
    def __init__(self, *args, **kwargs):
        pass

    def status(self, *args, **kwargs):
        return self.state

    def start(self, *args, **kwargs):
        pass

    def notify(self, *args, **kwargs):
        pass


class AnalysisDispatcher(EventDispatcher):
    """
        Base class - email analysis
    """
    def __init__(self, postmaster):
        log.setLevel(logging.INFO)
        log.info('Initialize static analysis manager')
        self.postman = postmaster.postman
        self.cfg = Config()
        self.report = Reporter(self.cfg)
        self.db = DBManager()
        self.sample = None
        data = self.db.initialize('samsdb')

    def start(self, message):
        log.info('Start analysis manager')
        self.processing(message)

    def processing(self, event_task):
        msg = None
        fileobj = None
        log.info('Prepare incidents to analysis')
        task_list = self.db.get_task('status','new')
        for task in task_list:
            self.prepare_task(task)

        log.info('Start procedure analysis')            
        task_list = self.db.get_task('status','panding')
        for task in task_list:
            self.run_task(task)
            

    def prepare_task(self, task):
        try:
            profile_path = os.path.join(_ANALYSIS_DIR,'malware', str(task['_id']))
            os.makedirs(profile_path)
            fname = os.path.basename(task['file'])
            shutil.move(task['file'], os.path.join(profile_path, fname))
            self.db.update_field_task(task['_id'],
                                      'file', 
                                      os.path.join(profile_path, fname),
                                      'panding')
            return True
        except IOError as e:
            log.error('File processing: %s' % e)
            log.info(task)
            self.db.update_status_task(task['_id'], 'fail')
            return False
        
    def run_task(self, task):
        analyzer = AnalyzerMalware(self.cfg)
        result = ''
        try:
            log.info('[Analysis attachment]')
            result = analyzer.run(task)
            if result == 'success':
                log.info('Build report!')
                rep_evt = self.report.build_report(task,
                                                   analyzer.MalM,
                                                   analyzer.sb_tasks)
                log.info('Send report!')
                self.postman.send_report(task, rep_evt)
                
                #if len(analyzer.MalM.recipient) < 2 and (analyzer.MalM.recipient[0]['email']!=''):
                    #print self.get_userinfo_ldap(analyzer.MalM.recipient[0]['email'])
                
                send_notify = self.check_user_notify(analyzer.MalM.recipient)
                if not send_notify is None:
                    rep_evt = self.report.build_user_notify(analyzer.MalM,
                                                            task['attachment'],
                                                            str(task['_id']))
                    self.postman.send_report_user(send_notify,
                                                  rep_evt,
                                                  str(task['_id']))
            else:
                self.db.update_status_task(task['_id'], 'fail')
        except IOError as e:
            log.error('File processing: %s' % e)
            log.info(task)
            result = 'fail'
            self.db.update_status_task(task['_id'], 'fail')
            
        if result == 'success':
            return True
        return False
    
    def build_data(self, data, analyzer, _parent):
        return dict(type_attach=data.attach_ftype,
                    type_samples=data.files_type,
                    hashes=data.attach_hashes,
                    mta=data.geo_mta,
                    parent=_parent,
                    received=data.trace_received,
                    recipient=data.recipient,
                    samples_desc=data.report,
                    sandbox_tasks=analyzer.sb_tasks,
                    sender=data.sender,
                    status='done',
                    subject=data.subject,
                    user_agent=data.uagent,
                    verdict=data.detect,
                    detect=dict(yara=data.YA_result,
                                loc_av=data.LAV_result,
                                agreg_ioc=dict(vt=data.detailinfoVT,
                                               te=dict(detect=None,
                                                       list_detect=None,
                                                       link=None),
                                               th=dict(detect=None,
                                                       list_detect=None,
                                                       link=None),
                                               date_req=None),
                                sb_report=dict(api_list=None,
                                               proc_list=None,
                                               file_list=None,
                                               reg_list=None,
                                               network=dict(domain_list=None,
                                                            ip_list=None))))

    def get_userinfo_ldap(self, email):
        user = email + '*'
        l = ldap.initialize(self.cfg.ldap.server1)
        try:
            l.protocol_version = ldap.VERSION3
            l.set_option(ldap.OPT_REFERRALS, 0)
            l.set_option(ldap.OPT_NETWORK_TIMEOUT, 2.0)
            bind = l.simple_bind_s(self.cfg.ldap.user1, self.cfg.ldap.passw1)
            base = 'dc=corp, dc=domain1, dc=ru'
            criteria = '(&(objectClass=user)(mail='+user+'))'
            attributes = ['displayName', 'company']
            result = l.search_s(base, ldap.SCOPE_SUBTREE, criteria, attributes)
            l.unbind()

            if result[0][0] is None:
                l = ldap.initialize(self.cfg.ldap.server2)
                l.protocol_version = ldap.VERSION3
                l.set_option(ldap.OPT_REFERRALS, 0)
                l.set_option(ldap.OPT_NETWORK_TIMEOUT, 2.0)
                bind = l.simple_bind_s(self.cfg.ldap.user2, self.cfg.ldap.passw2)
                base = 'dc=corp, dc=domain2, dc=ru'
                criteria = '(&(objectClass=user)(mail='+user+'))'
                attributes = ['displayName', 'company']
                result = l.search_s(base, ldap.SCOPE_SUBTREE, criteria, attributes)
                if result[0][0] is None:
                    user = '@'.join([user.split('@')[0],'domain2.ru'])
                    criteria = '(&(objectClass=user)(mail='+user+'))'
                    attributes = ['displayName', 'company']
                    result = l.search_s(base, ldap.SCOPE_SUBTREE, criteria, attributes)
                    l.unbind()
                return result[0]
            else:
                return result[0]                 
        except ldap.LDAPError as e:
            log.error(e)
        finally:
            l.unbind()
        return None

    def search_users_notify(self, recipient):
        self.users_notify = ['user3@sams.ru']
        for u in self.users_notify:
            if recipient.find(u) >= 0:
                return True
        return False
    
    def check_user_notify(self, recipients):
        for k in recipients:
            if self.search_users_notify(k['email']):
                return k['email']
        return None

    def notify(self, message):
        if message == 'email_task':
            # sample =self.postman.fetch('notdel')
            self.start(message)

class PostDispatcher(EventDispatcher):
    """
        Base class - email monitor
    """
    def __init__(self, manager):
        self.observ = manager
        self.indexQ = 0
        self.limitUpdate = 1
        self.countUpdate = 0
        self.curDate = datetime.date.today()
        self.test = None
        self.cfg = Config()
        self.postman = PostMaster(self.cfg.mail)
        self.eml_amount = 0
        log.setLevel(logging.INFO)
        log.info('Initialize module Email Monitor')

    def initialize(self):
        self.db = DBManager()
        data = self.db.initialize('samsdb')
        self.indexQ = data['FIndex']
        ff = datetime.datetime.strptime(data['Day'], '%Y-%m-%d')
        self.curDate = ff.date()

    def user_notify(self, message, user):
        self.postman.send_report_user(message, user)

    def inc_coll_fid(self):
        day = datetime.date.today()
        if self.curDate < day:
            self.curDate = day
            self.indexQ = 1
            self.countUpdate = 0
            self.db.update_coll_fid(self.indexQ, self.curDate.isoformat())
            return self.indexQ
        else:
            self.indexQ += 1
            self.countUpdate += 1
        if self.countUpdate > self.limitUpdate:
            self.db.update_coll_fid(self.indexQ, self.curDate.isoformat())
            self.countUpdate = 0
        return self.indexQ

    def save_msg(self, msg):
        fid = self.inc_coll_fid()
        filename = datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S')+'_'+str(fid)
        filename = os.path.join(_QUEUE_DIR, filename+'.eml')
        try:
            if msg:
                if len(msg) > 1:
                    sfile = open(filename, 'a')
                    sfile.write(msg)
                    sfile.close()
        except IOError as e:
            log.error('File processing: %s' % e)
            return False
        return True
        
    def fetch(self, count, command):
        item_count = 10
        if self.eml_amount == 0:
            self.eml_amount = count
        if self.eml_amount > 0:
            if self.eml_amount - item_count <= 0:
                item_count = self.eml_amount
            ind_eml = 0
            while ind_eml < item_count:
                ind_eml += 1
                msg = self.postman.get_post(ind_eml)
                if (not msg is None) and (len(msg)> 0):
                    if not self.save_msg(msg):
                        return False
            if command == 'del':
                try:
                    while not self.postman.del_post('1:'+str(item_count)):
                        log.error('Unable to delete emails from the mailbox!')
                        time.sleep(5)
                except imaplib.IMAP4.error as e:
                    log.error(e)
                    self.postman.init_postman()
            self.eml_amount -= item_count
        return True

    def check_post(self):
        try:
            count = self.postman.run()
            if count:
                if self.fetch(count, 'del'):
                    return True
        except imaplib.IMAP4.error as e:
            log.error(e)
        return False

    def start(self):
        self.initialize()
        try:
            while True:
                if self.check_post():
                    self.observ.update('email')
                else:
                    time.sleep(5)
        except SAMSPostMasterConnectError as e:
            log.error(e)
        except SAMSPostMasterLoginError as e:
            log.error(e)
        except SAMSPostMasterFetchError as e:
            log.error(e)

    def notify(self, message):
        if message == 'check_mail':
            log.info('Check mail')
            self.start()
        if message == 'stop':
            self.db.update_coll_fid(self.indexQ, self.curDate.isoformat())
            self.postman.close_mbox()


class PostGrader(EventDispatcher):
    """
        Base class - filter emails
    """
    def __init__(self, *args, **kwargs):
        self.observ = args[0]
        self.initialize()
        
        #log.info('Email Flter: Start of the interrupted tasks')
        #self.start('email_task')

    def initialize(self):
        log.setLevel(logging.INFO)
        log.info('Initialize module Email Filters')
        self.cfg = Config()
        self.postgrader = MailFilterManager(_TMP_DIR)
        self.db = DBManager()
        data = self.db.initialize('samsdb')

    def post_filters(self, sfile):
        log.info('New email for check')
        try:
            if self.postgrader.check(sfile):
                log.info('This suspicious email')
                return True
            else:
                log.info('No suspicious, deleted')
                self.del_post_file(sfile)
                return False
        except:
            return False

    def del_post_file(self, sfile):
        log.info('File delete: %s' % sfile)
        dfname = os.path.basename(sfile)
        dpath = os.path.normpath(os.path.join(os.path.dirname(sfile), '..'))
        shutil.move(sfile, os.path.join(_BACKUP_DIR,dfname))
        log.info('File move: %s' % os.path.join(_BACKUP_DIR,dfname))
        #os.remove(sfile)

    def start(self, message):
        listf = os.listdir(_QUEUE_DIR)
        for sfile in listf:
            filename = os.path.join(_QUEUE_DIR, sfile)
            if self.post_filters(filename):
                timestamp = datetime.datetime.now()
                query = {'file':filename,
                        'samples_desc':'',
                        'status':'new',
                        'type':'mail',
                        'timestamp':timestamp
                }
                self.db.add_in_coll('analysis', query)
                self.observ.update(message)
            log.info('analysis procedure completed')
            
    def notify(self, message):
        if message == 'email':
            self.start('email_task')
