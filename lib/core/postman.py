# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import os
import smtplib
import imaplib
import socket
import email
import socket
import mimetypes
import logging
import time

from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText

from lib.common.exceptions import SAMSPostMasterConnectError, SAMSPostMasterLoginError, SAMSPostMasterFetchError

log = logging.getLogger(__name__)


class PostManager(object):

    def __init__(self, cfg):
        log.setLevel(logging.INFO)
        log.info('Initializing the PostManager')
        imaplib._MAXLINE = 2000000
        self.sizef = 0
        self.cfg = cfg
        self.emailto = [self.cfg.mon_account]
        self.emailfrom = [self.cfg.send_account]
        self.target = None
        self.mon_box = None
        self.name = 'email.eml'
        self.init_postman()
        
    def init_postman(self):
        self.mon_box = self.init_mbox()
        if self.mon_box:
            self.mon_box.login(self.cfg.mon_account, self.cfg.mon_password)
            self.mon_box.select('Inbox')
            log.info('PostManager initialized successfully')
            return True
        return False

    def init_mbox(self):
        if self.cfg.imaps:
            log.info('IMAP_SSL')
            try:
                return imaplib.IMAP4_SSL(self.cfg.mon_srv, self.cfg.port_imaps)  # port 993
            except socket.error as e:
                raise SAMSPostMasterConnectError('Initialize connect IMAPS to server %s: %s' % (self.cfg.mon_srv, e))
                return False
        else:
            log.info('IMAP')
            try:
                return imaplib.IMAP4(self.cfg.mon_srv, self.cfg.port_imap)      # port 143
            except imaplib.IMAP4.error as e:
                raise SAMSPostMasterConnectError('Initialize connect IMAP to server %s: %s' % (self.cfg.mon_srv, e))
                return False
            except socket.error as e:
                log.error('Connection failed: %s' % e)
                return False            

    def run(self):
        try:
            typ, data = self.mon_box.search(None, 'ALL')
            count = len(data[0].split())
            if count > 0:
                return count
        except imaplib.IMAP4.error as e:
            raise SAMSPostMasterFetchError('Processing the message in a mailbox %s: %s' % (self.cfg.mon_account, e))
        except socket.error as e:
            log.error('Connection failed: %s' % e)
            return False

    def get_post(self, index):
        data = None
        resp, data = self.mon_box.fetch(index, '(RFC822)')
        if resp == 'OK':
            if len(data[0][1].strip()) > 0:
                return data[0][1]
            else:
                return None
        else:
            return None

    def del_post(self, msg_l):
        try:
            self.mon_box.store(msg_l, '+FLAGS', '\\Deleted')
            if self.mon_box.expunge()[0] == 'OK':
                return True
            else:
                return False
        except imaplib.IMAP4.error as e:
            log.error('Deleting message from mailbox %s: %s' % (self.cfg.mon_account, e))
            self.init_postman()
            return False
        except socket.error as e:
            log.error('Connection failed: %s' % e)
            self.init_postman()
            return False

    def close_mbox(self):
        self.mon_box.close()
        self.mon_box.logout()

    def initialize(self, subject, _context, path_attachments):
        self.deetsurl = smtplib.SMTP(self.cfg.send_srv, self.cfg.send_port)
        self.deetsurl.starttls()
        self.message = MIMEMultipart()
        self.message['To'] = self.cfg.name_to+','+self.cfg.name_to_adv
        self.message['From'] = self.cfg.name_from
        self.message['Subject'] = subject
        self.message['Importance'] = 'high'
        self.message['X-Priority'] = '1'
        self.message['X-MSMail-Priority'] = 'High'
        
        # Added attach sample file
        path = os.path.join(path_attachments, 'sample.zip')
        ctype, encoding = mimetypes.guess_type(path)
        if ctype is None or encoding is not None:
            ctype = 'application/octet-stream'
        maintype, subtype = ctype.split('/', 1)
        filename = 'sample.zip'
        try:
            fp = open(path, 'rb')
            self.message.attach(MIMEApplication(
                                fp.read(),
                                Content_Disposition='attachment; filename="%s"' % filename,
                                Name=filename)
                                )
            fp.close()
        except IOError as e:
            log.error('The file was not attached ' + path + '\n%s' % e)
            
        # Adding mail file as an attachment
        path = os.path.join(path_attachments, 'mails.zip')
        if os.path.isfile(path):
            self.sizef = os.path.getsize(path)/1024/1024
        
        ctype, encoding = mimetypes.guess_type(path)
        if ctype is None or encoding is not None:
            ctype = 'application/octet-stream'
        maintype, subtype = ctype.split('/', 1)
        filename = 'mails.zip'
        try:
            fp = open(path, 'rb')
            self.message.attach(MIMEApplication(
                                fp.read(),
                                Content_Disposition='attachment; filename="%s"' % filename,
                                Name=filename))
            fp.close()
        except IOError as e:
            log.error('The file was not attached ' + path + '\n%s' % e)
        # Creating your plain text message
        # Adding context message - caption
        
        HTML_BODY = MIMEText(_context, 'html', _charset='utf-8')
        TXT_BODY = MIMEText(_context,  _charset='utf-8')
        
        if '<html>' in _context:
            self.message.attach(HTML_BODY)
        else:
            self.message.attach(TXT_BODY)
        
        return True

    def send_report(self, subject, text, path_attachments):
        state = self.initialize(subject, text, path_attachments)
        
        if (self.sizef > 2):
            self.deetsurl.login(self.cfg.send_account, self.cfg.send_password)
            self.deetsurl.sendmail(self.cfg.name_from, self.cfg.name_to, self.message.as_string())
        else:
            tot = [self.cfg.name_to, self.cfg.name_to_adv]
            self.deetsurl.login(self.cfg.send_account, self.cfg.send_password)
            self.deetsurl.sendmail(self.cfg.name_from, tot, self.message.as_string())
        log.info('Email sent to SOC')
        self.deetsurl.quit()

    def send_report_user(self, user, _context, _subject):
        message = MIMEMultipart()
        message['To'] = user
        message['From'] = 'noreplay@domain1.net'
        message['Subject'] = '★'+_subject
        message['Importance'] = 'high'
        message['X-Priority'] = '1'
        message['X-MSMail-Priority'] = 'High'
        
        HTML_BODY = MIMEText(_context, 'html', _charset='utf-8')
        TXT_BODY = MIMEText(_context,  _charset='utf-8')
        
        if '<html>' in _context:
            message.attach(HTML_BODY)
        else:
            message.attach(TXT_BODY)
            
        self.deetsurl = smtplib.SMTP(self.cfg.send_srv, self.cfg.send_port)
        self.deetsurl.starttls()
        self.deetsurl.login(self.cfg.send_account, self.cfg.send_password)
        self.deetsurl.sendmail(self.cfg.name_from, user, message.as_string())
        log.info('Email sent to User')
        self.deetsurl.quit()
