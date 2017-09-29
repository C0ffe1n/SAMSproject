# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import os
import datetime
import email
import errno
import mimetypes
import magic
import logging
import re
import shutil
import uuid
import md5

from email.header import Header

from lib.common.exceptions import SAMSAnalysisError
from lib.common.objects import ArchFileExt, SuspectFileExt
from lib.core.filemanager import FileManager
from lib.core.dbmanager import DBManager
from lib.common.constants import _TMP_DIR, _QUEUE_DIR, _BACKUP_DIR, _ANALYSIS_DIR
from lib.common.constants import FILTER_IDENT_ATTACH_TYPE, FILTER_CHK_SUBJECT, FILTER_CHK_LIMIT_FSIZE, FILTER_EML_FROM

log = logging.getLogger(__name__)


class MailFilter(object):
    """
        Base class - filter manager
    """
    def __init__(self):
        self.arch = ArchFileExt()
        self.exe = SuspectFileExt()
        self.chkflag = False
        self.struct = []
        self.fm = FileManager()
    
    def run_filter(self, filter_id, filename):
        score = 0

        data = self.fm.filemsg_read(filename)
        addr_from = email.utils.getaddresses(data.get_all('from', [])).pop()
        sndr_name = addr_from[1].split('@')[0]
        if sndr_name.lower() in self.l_sndr_pass:
            return dict(code=-100)
        if filter_id and FILTER_CHK_LIMIT_FSIZE:
            if not self.chk_limit_fsize(filename):
                return dict(code=-1)

        if filter_id and FILTER_IDENT_ATTACH_TYPE:
            attached_list = self.ident_attach_type(data)
            if attached_list:
                if attached_list['eml_attached']:
                    if len(attached_list['attachment_type_list']) > 1:
                        return dict(addr_from=addr_from,
                                    code=101)
                    else:
                        data = self.fm.get_attached_eml(data)
                        attached_list = self.ident_attach_type(data, True)
                        if attached_list:
                            if  not attached_list['f_unknown']:
                                return dict(attached_list,
                                            addr_from=addr_from,
                                            type='file',
                                            code=200)
                            else:
                                return dict(addr_from=addr_from,
                                            code=101)
                elif not attached_list['f_unknown']:
                    return dict(attached_list,
                                addr_from=addr_from,
                                type='file',
                                code=200)
        return dict(addr_from=addr_from,
                    code=100)

    def ident_attach_type(self, data, second_iter=False):
        # all filtered files with no name
        # not data.get_filename() is None
        unknown_attachment_type = False
        eml_attachment_type = second_iter
        attachment_type_list = []
        try:
            if email.message.Message.is_multipart(data):
                for part in data.walk():
                    maintype = part.get_content_maintype()
                    subtype = part.get_content_subtype()

                    filename = self.fm.normalize(part.get_filename())
                    if filename:
                        if subtype in [u'rfc822',u'x-message-display']:
                            return dict(attachment_type_list=attachment_type_list,
                                        eml_attached=True)
                        elif self.fm.get_attache(_TMP_DIR, filename, part):
                            ftype = self.fm.get_file_type(_TMP_DIR, filename, subtype)
                            if not ftype:
                                unknown_attachment_type = True
                            id_file = str(uuid.uuid1())
                            attachment_type_list.append(dict(fname=filename,
                                                            mtype=maintype,
                                                            stype=subtype,
                                                            type=ftype,
                                                            id_file=id_file))
                if len(attachment_type_list) > 0:
                    return dict(attachment_type_list=attachment_type_list,
                                f_unknown=unknown_attachment_type,
                                eml_attached=eml_attachment_type)
                else:
                    log.info('No attachments')
                    return None
            else:
                log.info('No attachments')
            return None
        except SAMSAnalysisError as e:
            log.error(e)
            return None

    """ Check by size email"""
    def chk_limit_fsize(self, sfile):
        sizef = os.path.getsize(sfile)/1024/1024
        if sizef > 1:
            log.info('Filtered by size: ' + str(sizef)+'MB')
            return False
        return True

class MailFilterManager(MailFilter):
    """
        Module email filter
        Features:        
        - Monitoring a email queue on the check
        - Initialize tasks filtering and analysis
    """

    def initialize(self, ctrl, cfg):
        log.setLevel(logging.INFO)
        log.info('Initialize module Email Filters')
        self.ctrl = ctrl
        self.cfg = cfg
        self.work_mode = self.cfg.mail['work_mode']
        self.l_sndr_pass = self.cfg.mail['sender_pass'].split(',')
        #self.postman = PostManager(self.cfg)
        self.mtp_relay_list = ['dozor@dozor.ru']
        self.db = DBManager()
        data = self.db.initialize('samsdb')
        self.db.remove_coll('analysis')
        self.score = 0

    def start(self):
        listf = os.listdir(_QUEUE_DIR)
        ec = 0
        for sfile in listf:
            filename = os.path.join(_QUEUE_DIR, sfile)
            log.info('New email for check')

            try:
                result = self.apply_filters(filename)
                if result:
                    ec += 1
                else:
                    log.error('File processing: %s' % filename)
                    log.info(filename)
            except:
                log.error('Error occurred while processing e-mails')
        if ec > 0:
            self.ctrl.update('email_task')

        log.info('analysis procedure completed')

    def del_post_file(self, sfile):
        log.info('File delete: %s' % sfile)
        dfname = os.path.basename(sfile)
        dpath = os.path.normpath(os.path.join(os.path.dirname(sfile), '..'))
        shutil.move(sfile, os.path.join(_BACKUP_DIR,dfname))
        log.info('File move: %s' % os.path.join(_BACKUP_DIR,dfname))
        #os.remove(sfile)

            
    def notify(self, message, data):
        if message == 'email_check':
            self.start()
    
    def assessment(self, score, value):
        if value:
            return score + 10
        else:
            return score - 10

    def create_task(self, inc_id, filename):
        try:
            profile_path = os.path.join(_ANALYSIS_DIR,'malware', str(inc_id))
            os.makedirs(profile_path)
            fname = os.path.basename(filename)
            shutil.move(filename, os.path.join(profile_path, fname))
            return os.path.join(profile_path, fname)
        except IOError as e:
            log.error('File processing: %s' % e)
            log.info(filename)
            return False

    def apply_filters(self, filename):
        result = self.run_filter(5, filename)
        if result['code'] >= 200:
            log.info('This suspicious email')

            inc_id = uuid.uuid4()
            path = self.create_task(inc_id, filename)
            if path:
                timestamp = datetime.datetime.now()
                query = {
                        '_id': inc_id,
                        'addr_from': result['addr_from'][1],
                        'analyzed_attachments_info' : None,
                        'analyzed_samples_info' : None,
                        'attached_list': result['attachment_type_list'],
                        'eml_attached': result['eml_attached'],
                        'eml_headers': None,
                        'verdict': None,
                        'target': path,
                        'status': u'new',
                        'type': result['type'],
                        'timestamp' : timestamp
                }
            else:
                return False
            self.db.add_in_coll('analysis', query)
            return True
        
        elif result['code'] == 100:
            log.info('No suspicious, deleted')
            return False
        elif result['code'] == 101:
            return False
        elif result['code'] < 0:
            if result['code'] == -100:
                self.del_post_file(filename)
            return False


    def clear(self):
        for file in os.listdir(_TMP_DIR):
            os.remove(os.path.join(_TMP_DIR, file))
        return True
