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
from lib.exceptions import SAMSPostMasterConnectError, SAMSPostMasterLoginError, SAMSPostMasterFetchError
from lib.core.mailfilter import MailFilterManager

log = logging.getLogger(__name__)

class PostMaster(object):

    def __init__(self, cfg):
        log.setLevel(logging.INFO)
        log.info('Initialize Postmaster')
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
            log.info('Postman initialization done!')
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
            return data[0][1]
        else:
            return False

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

    def initialize(self, task, subject, targetinfo):
        ferro = False
        self.deetsurl = smtplib.SMTP(self.cfg.send_srv, self.cfg.send_port)
        self.deetsurl.starttls()
        self.message = MIMEMultipart()
        self.message['To'] = self.cfg.name_to+','+self.cfg.name_to_adv
        self.message['From'] = self.cfg.name_from
        _id = str(task['_id'])
        self.message['Subject'] = '★[SAMS-ID#'+_id+'] - '+subject
        self.message['Importance'] = 'high'
        self.message['X-Priority'] = '1'
        self.message['X-MSMail-Priority'] = 'High'
        
        # Added attach sample file
        path = os.path.join(os.path.dirname(task['file']), 'sample.zip')
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
            ferro = True
            caption_err = '\nThe file was not attached ' + path + '\n%s' % e
            targetinfo = '\n\r'.join([targetinfo, caption_err.encode('utf-8')])
        
        # Adding mail file as an attachment
        path = os.path.join(os.path.dirname(task['file']), 'mails.zip')
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
                                Name=filename)
                                )
            fp.close()
        except IOError as e:
            caption_err = '\nThe file was not attached ' + path + '\n%s' % e
            ferro = True
            targetinfo = '\n\r'.join([targetinfo, caption_err.encode('utf-8')])
            log.error('The file was not attached ' + path + '\n%s' % e)
        # Creating your plain text message
        # Adding context message - caption
        HTML_BODY = MIMEText(targetinfo, 'html', _charset='utf-8')
        self.plaintextemailmessage = targetinfo
        self.storeplain = MIMEText(self.plaintextemailmessage,  _charset='utf-8') #cp1251
        if '<html>' in targetinfo:
            self.message.attach(HTML_BODY)
        else:
            self.message.attach(self.storeplain)
        return ferro

    def send_report(self, task, context):
        state = self.initialize(task, 'Вредоносная рассылка', context)
        
        if (self.sizef > 2):
            self.deetsurl.login(self.cfg.send_account, self.cfg.send_password)
            self.deetsurl.sendmail(self.cfg.name_from, self.cfg.name_to, self.message.as_string())
        else:
            tot = [self.cfg.name_to, self.cfg.name_to_adv]
            self.deetsurl.login(self.cfg.send_account, self.cfg.send_password)
            self.deetsurl.sendmail(self.cfg.name_from, tot, self.message.as_string())
        log.info('Email sent to SOC')
        self.deetsurl.quit()

    def send_report_user(self, user, _context, _id):
        #sign = '\nBest regards,\n-------------------------\nSecurity operations center\nemail: soc@domain1.ru\nтел: 8(499)555-55-55 (12345)'
        subject = 'Внимание! Вам пришло подозрительное письмо!'
        message = MIMEMultipart()
        message['To'] = 'User'
        message['From'] = 'soc@domain1.ru'
        message['Subject'] = '★'+subject+' - [SAMS-ID#'+_id+']'
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
