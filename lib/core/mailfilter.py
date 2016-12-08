# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import os
import email
import errno
import mimetypes
import magic
import logging
import re
from email.header import Header

from lib.categoryfilters import ExtDocFilters, ExtOfficeFilters, WhiteListEmailFilters, ExtArchFilters, ExtExecFilters
from lib.core.filemanager import ArchiveManager

log = logging.getLogger(__name__)

class MailFilter(object):
    """
        Base class - filter manager
    """
    def __init__(self, store):
        log.setLevel(logging.INFO)
        self.store = store
        self.whitelist = WhiteListEmailFilters()
        self.arch_type = ExtArchFilters()
        self.exe = ExtExecFilters()
        self.office = ExtOfficeFilters()
        self.scan = ExtDocFilters()
        self.chkflag = False
        self.struct = []
        log.info('Initialize filter manager')

    """ Get payload (attachments)"""
    def get_payload(self, content):
        return content.get_payload()
    
    """ Check if msg content contains only text"""
    def chk_is_spam(self, content):
        if content.get_content_maintype() == 'text':
            return True
        else:
            return False

    """ Check by subject"""
    def chk_subject(self, msg):
        subject = msg.get('subject')
        subject = email.header.decode_header(subject)[0][0]
        if subject.find('Ссылка')>=0:
            return False
        return False

    """ Check by whitelist """
    def chk_whitelist(self, msg):
        for k in self.whitelist.list:
            from_str = msg.get('from')
            if not from_str is None:
                if k in from_str:
                    return True
        return False

    def express_chk_content(self, data, contencode):
        if data.get_filename():
            filename = self.normal_str(data.get_filename(), contencode)
            if self.get_attache(os.path.join(self.store, filename), data):
                res = self.chk_file_is_arch(os.path.join(self.store, filename))
                if res:
                    return dict(is_arch=True,file_type=res,filename=os.path.join(self.store, filename))
                res = self.chk_file_is_other(os.path.join(self.store, filename))
                if res:
                    return dict(is_arch=False,file_type=res,filename=os.path.join(self.store, filename))
        return dict(is_arch=False,file_type='',filename='')

    """ Get attachment """
    def get_attache(self, filename, part):
        try:
            fp = open(filename, 'wb')
            fp.write(part.get_payload(decode=True))
            fp.close()
        except:
            return False
        return True

    def chk_file_is_other(self, filename):
        try:
            # python magic
            fileinfo = magic.from_file(filename)
            if 'Rich' in fileinfo:
                return 'doc'
            if filename.endswith('.docm'):
                return 'doc'
            if filename.endswith('.dotm'):
                return 'doc'
            if filename.endswith('.dot'):
                return 'doc'
            if filename.endswith('.lnk'):
                return 'doc'
        except Exception as e:
            log.error('Check file is other extensions: %s' % e)
            return False
        return False

    def chk_limit_fcount(self, flist):
        if len(flist) > 5:
            log.info('Limit files exceeded')
            return False
        log.info('Limit files norm')
        return True

    def chk_limit_fsize(self, sfile):
        sizef = os.path.getsize(sfile)/1024/1024
        if sizef > 5:
            log.info('Filtered by size: ' + str(sizef)+'MB')
            return False
        return True
        
    def chk_file_type(self, flist):
        if len(flist) == 0:
            return True #heandling file error
        else:
            if self.chk_limit_fcount(flist):
                for f in flist:
                    if f[f.rfind('.')+1:] in self.exe.list:
                        return True
                    if not re.search(self.arch_type.pattern_end, f) is None:
                        return True
            else:
                return False
    
    def chk_file_is_arch(self, filename):
        try:
            # python magic
            fileinfo = magic.from_file(filename)
            for archtype in self.arch_type.list:
                if fileinfo.find(archtype) >= 0:
                    return archtype
            if filename.endswith('.ace'):
                return 'ace'
            if filename.endswith('.arj'):
                return 'arj'
            if filename.endswith('.cab'):
                return 'cab'
        except Exception as e:
            log.error('Сrash attachment processing: %s' % e)
            return False
        return False
    
    def normal_str(self, str, method):
        if method == 'base64':
            try:
                tmp = email.header.decode_header(str)
                if tmp[0][1]:
                    nstr = tmp[0][0].decode(tmp[0][1])
                else:
                    nstr = tmp[0][0]
            except:
                nstr = str
        else:
            nstr = str
        return nstr
    
    def check(self):
        pass


class MailFilterManager(MailFilter):

    def filemsg_read(self, path):
        sfile = open(path, 'r')
        msg = email.message_from_string(sfile.read())
        sfile.close()
        return msg
    
    def check(self, sfile):
        if self.chk_limit_fsize(sfile):
            msg = self.filemsg_read(sfile)
            
            if 'dozor@dozor.ru' in msg.get('from'):
                data = self.get_payload(msg)
                tmp = data[1].get_payload()
                data = tmp[0]
            else:
                data = msg
            self.chk_subject(msg)
            if self.chk_whitelist(data):
                log.info('Not analysed, whitelist')
                return False        
            if self.chk_is_spam(data):
                log.info('Not analysed, SPAM')
                return False
            if self.enum_attachment(data):
                log.info('Email contains suspicious files')
                return True
        log.info('No filter matches')
        return False

    def enum_attachment(self, data):
        arcMgr = ArchiveManager()
        for part in data.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            contencode = part['Content-Transfer-Encoding']
            if contencode == 'base64':
                res = self.express_chk_content(part, contencode)
                if res['is_arch']:
                    res = self.chk_file_type(arcMgr.explore_arch(res['file_type'], res['filename']))
                    if res:
                        return True
                elif res['file_type']=='doc':
                    return True
        return False

    def clear(self):
        for file in os.listdir(self.store):
            os.remove(os.path.join(self.store, file))
        return True
