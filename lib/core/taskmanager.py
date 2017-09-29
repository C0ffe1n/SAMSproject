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

from lib.core.analyzer import Analyzer
from lib.core.filemanager import FileManager
from lib.core.dbmanager import DBManager
from lib.common.objects import Sample, SampleEmail
from lib.common.objects import ArchFileExt, SuspectFileExt
from lib.common.constants import _ANALYSIS_DIR, _TMP_DIR, _QUEUE_DIR, _BACKUP_DIR, WORK_MODE_USERFEED, WORK_MODE_NORMAL

log = logging.getLogger(__name__)


class Task(object):
    
    def __init__(self, _data):
        self.data = _data
        self.id_inc = _data['_id']
        self.analyzer = Analyzer(_data)
        self.status = 'panding'
        self.analyzed_samples = []
        self.analyzed_attachments = []
        self.EML_headers = None
        #self.sample = Sample(_data['sample'])

    def initialize(self):
        fm = FileManager()
        profile_path = os.path.dirname(self.data['target'])
        _attach_dir = os.path.join(profile_path, 'attachments')
        _samples_dir = os.path.join(profile_path, 'samples')
        try:
            os.makedirs(_attach_dir)
            os.makedirs(_samples_dir)
        except OSError as e:
            log.error('Directory \'sample\' or \'attachments\' exist')
            
        _data = fm.filemsg_read(self.data['target'])
        attached_list = []
        if self.data['eml_attached']:
            _data = fm.get_attached_eml(_data)
            eml_obj = SampleEmail(_data)
            print eml_obj.get_headers()
            self.EML_headers = eml_obj.get_headers()
        for item in self.data['attached_list']:
            attached_list.append(dict(fname=item['fname'],
                                      type=item['type'],
                                      id_file=item['id_file']))
        for part in _data.walk():
            filename = fm.normalize(part.get_filename())
            if filename:
                for item in attached_list:
                    if item['fname'] == filename:
                        attached_list.pop(attached_list.index(item))
                        fm.get_attache(_attach_dir, item['id_file'], part)
                        break

        dirlist = os.listdir(_attach_dir)
        for item in dirlist:
            self.analyzed_attachments.append(Sample(os.path.join(_attach_dir,item)))
        
        exec_obj = SuspectFileExt()
        for fname in dirlist:
            for item in self.data['attached_list']:
                if item['id_file'] == fname:
                    if item['type'] in exec_obj.list:
                        _fname = '.'.join((fname,item['type'].lower()))
                        fm.copy_to(os.path.join(_attach_dir,fname),
                                   os.path.join(_samples_dir,_fname))
                    else:
                        fm.extract_files(item['type'], _samples_dir, os.path.join(_attach_dir,fname))
                    break

        fm.mail_pack(self.data['target'], 'infected')
        fm.sample_pack(profile_path, 'infected')

        dirlist = os.listdir(_samples_dir)
        for item in dirlist:
            self.analyzed_samples.append(Sample(os.path.join(_samples_dir,item)))
        
    def start(self):
        log.info('Run task ID: %s' % self.data['_id']) 
        self.initialize()
        
        self.status = 'analyzed'
        result = self.analyzer.run(self.analyzed_attachments, self.analyzed_samples)
        if result:
            print "FINISH"
            self.status = 'completed'
            if result['detected']:
                self.data['verdict'] = u'detected'
            else:
                self.data['verdict'] = u'clean'
            _list = []
            for item in self.analyzed_attachments:
                _list.append(item.get_info())    
            self.data['analyzed_attachments_info'] = _list
            _list = []
            for item in self.analyzed_samples:
                _list.append(item.get_info())
            self.data['analyzed_samples_info'] = _list
            self.data['eml_headers'] = self.EML_headers
        else:
            self.status = 'failed'
        self.data['status'] = self.status
        return self.data
        
    
    def get(self, field):
        if field == 'status':
            return self.status
        if field == 'id_inc':
            return self.id_inc
        if field == 'addr_from':
            return self.data['addr_from']
        

class TaskManager(object):
    
    def __init__(self, ctrl, cfg):
        log.setLevel(logging.INFO)
        log.info('Initialize static analysis manager')
        self.ctrl = ctrl
        self.cfg = cfg
        self.work_mode = self.cfg.mail['work_mode']
        self.db = DBManager()
        self.run_task_list = []
        data = self.db.initialize('samsdb')
        

    def start(self, message, data):
        
        msg = None
        fileobj = None
        
        log.info('Start analysis manager')
        #log.info('Prepare incidents to analysis')
        
        new_tasks_list = self.db.get_task('status','new')
        for item in new_tasks_list:
            self.run_task_list.append(Task(item))

        for item in self.run_task_list:
            result = item.start()
            self.db.update_data_task(item.get('id_inc'), result)
            self.ctrl.update('user_notify',
                             dict(event=u'response_team',
                                  data_inc=result))
        self.update_run_task()            
        return True
    
    def update_run_task(self):
        for item in self.run_task_list:
            if item.get('status') in ['completed','finish']:
                self.db.update_status_task(item.data['_id'], 'completed')
                #self.db.update_data_task(task['_id'], self.build_data(analyzer))
                
        self.run_task_list = filter(lambda item: not item.get('status') in ['completed','finish'], self.run_task_list)

    def notify(self, message, data):
        if message == 'email_task':
            # sample =self.postman.fetch('notdel')
            self.start(message, data)
        if message == 'update_run_task':
            self.update_run_task()
