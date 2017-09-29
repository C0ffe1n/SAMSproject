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
import imaplib

from lib.core.postman import PostManager
from lib.core.dbmanager import DBManager
from lib.common.constants import _ANALYSIS_DIR, _TMP_DIR, _QUEUE_DIR, _BACKUP_DIR, WORK_MODE_USERFEED, WORK_MODE_NORMAL
from lib.common.exceptions import SAMSPostMasterConnectError, SAMSPostMasterLoginError, SAMSPostMasterFetchError, SAMSAnalysisError, SAMSDatabaseError

log = logging.getLogger(__name__)

class EmailMonitor(object):
    """
        Module email monitor
        Features:        
        - Monitors the mailbox
        - Fetch e-mails and queues on the check
    """
    def __init__(self, ctrl, cfg):
        self.ctrl = ctrl
        self.cfg = cfg.get('mail')
        self.indexQ = 0
        self.limitUpdate = 1
        self.countUpdate = 0
        #self.curDate = datetime.date.today()
        #self.test = None
        self.eml_amount = 0
        log.setLevel(logging.INFO)
        log.info('Initialize module Email Monitor')

    def initialize(self):
        self.postman = PostManager(self.cfg)
        self.db = DBManager()
        data = self.db.initialize('samsdb')
        self.indexQ = data['FIndex']
        ff = datetime.datetime.strptime(data['Day'], '%Y-%m-%d')
        self.curDate = ff.date()

    def counter_emails(self):
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

    def save_email(self, data):
        fid = self.counter_emails()
        filename = datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S')+'_'+str(fid)
        filename = os.path.join(_QUEUE_DIR, filename+'.eml')
        try:
            if data:
                if len(data) > 1:
                    sfile = open(filename, 'a')
                    sfile.write(data)
                    sfile.close()
        except IOError as e:
            log.error('File processing: %s' % e)
            return False
        return True
        
    def fetch_emails(self, count, command):
        item_count = 10
        if self.eml_amount == 0:
            self.eml_amount = count
        if self.eml_amount > 0:
            if self.eml_amount - item_count <= 0:
                item_count = self.eml_amount
            ind_eml = 0
            while ind_eml < item_count:
                ind_eml += 1
                msg = None
                while not msg:
                    msg = self.postman.get_post(ind_eml)
                if (not msg is None) and (len(msg)> 0):
                    if not self.save_email(msg):
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
                if self.fetch_emails(count, 'del'):
                    return True
        except imaplib.IMAP4.error as e:
            log.error(e)
        return False

    def start(self):
        self.initialize()
        try:
            self.ctrl.update('email_check')
            while True:
                if self.check_post():
                    self.ctrl.update('email_check')
                else:
                    self.ctrl.update('update_run_task')
                    time.sleep(5)
        except SAMSPostMasterConnectError as e:
            log.error(e)
        except SAMSPostMasterLoginError as e:
            log.error(e)
        except SAMSPostMasterFetchError as e:
            log.error(e)

    def notify(self, message, data):
        if message == 'stop':
            if self.db:
                self.db.update_coll_fid(self.indexQ, self.curDate.isoformat())
            if self.postman:
                self.postman.close_mbox()
