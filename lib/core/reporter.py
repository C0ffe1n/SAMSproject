# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
from lib.core.postman import PostManager
from lib.common.exceptions import SAMSAnalysisError
from lib.common.constants import WHITE_LIST_FLAG, INCIDENT_TRUE_FLAG, AMOUNT_ITEMS_FLAG, AV_DETECT_FLAG, IOC_DETECT_FLAG, YARA_DETECT_FLAG
from lib.common.constants import _TEMPLATES_DIR, _MSG_NOTIFY
try:
    from jinja2 import Template, Environment, FileSystemLoader
    J2_INIT = True
except ImportError:
    J2_INIT = False
    
log = logging.getLogger(__name__)    

class ReportManager(object):
    def __init__(self, ctrl, cfg):
        self.ctrl = ctrl
        self.cfg = cfg
        self.postman = PostManager(cfg.get('mail'))
        log.setLevel(logging.INFO)
        if J2_INIT:
            self.env = Environment(loader=FileSystemLoader(_TEMPLATES_DIR))
        
        self.sign = ['\nBest regards',
                '\n-------------------------',
                '\nSecurity operations center',
                '\nemail: soc@domain1.ru',     
                '\nтел: 8(499)555-55-55 (12345)']
        
        log.info('Initialize module Reporter')

    def init_template(self, _template):
        return self.env.get_template(_template)

    def start(self, data):
        if u'response_team' in data['event']:
            subject = '★[SAMS-ID#'+str(data['data_inc']['_id'])+'] - Вредоносная рассылка'
            text = self.build_report(data['data_inc'], _MSG_NOTIFY)
            path_attachments = os.path.dirname(data['data_inc']['target'])
            self.postman.send_report(subject,
                                     text,
                                     path_attachments)

    def build_report(self, data, template):
        try:
            template = self.init_template(template)
            block_public_info = list()
            block_detect_av = list()
            block_detect_yara = list()
            block_title = list()
            block_header = list()
            #Title info
            samples = data['analyzed_samples_info']
            block_detect_av.append('Local AntiVirus:\r\n')
            block_detect_yara.append('YARA:\r\n')
            
            block_public_info.append('\r\nResult VirusTotal:\r\n')
            
            for item in samples:
                if item['loc_av']:
                    block_detect_av.append('\t'+item['fname']+': '+item['loc_av'])
                    block_detect_av.append('\r\n')
                if len(block_detect_av) <= 2:
                    block_detect_av = list()

                if item['yara']:
                    block_detect_yara.append('\t'+item['fname']+': '+item['yara'])
                    block_detect_yara.append('\r\n')
                if len(block_detect_yara) <= 2:
                    block_detect_yara = list()
                    
                agreg = item['public_info']['agreg_ioc']
                block_public_info.append(agreg['vt']['link'])
                block_public_info.append('\r\n')
                for item2 in agreg['vt']['list_detect']:
                    block_public_info.append(item2+': ')
                    block_public_info.append(agreg['vt']['list_detect'][item2]['result'])
                    block_public_info.append('\r\n')
                
            block_title.append('SAMS-ID#'+str(data['_id'])+ '\r\n')
            for item in samples:
                block_title.append(item['fname']+'\t'+item['hashes']['md5'])
                block_title.append('\r\n')
            block_title.append('http://'+self.cfg.analyzer.webui_domain+':'+
                                str(self.cfg.analyzer.webui_port)+'/webui/detail_id/'+
                                str(data['_id'])+ '\r\n')
            
            if data['eml_headers']:
                headers = data['eml_headers']['raw']
                block_header.append('From: '+data['eml_headers']['sender'][0])
                block_header.append(' ['+data['eml_headers']['sender'][1]+']'+'\r\n')
                block_header.append('Subject: '+data['eml_headers']['subject'])
                
                for item in headers:
                    if 'X-KLMS' in item[0]:
                        block_header.append(item[0]+': ')
                        block_header.append(item[1])
                        block_header.append('\r\n')
            if J2_INIT:
                context = template.render(dict(block_detect_av=''.join(block_detect_av).decode('utf-8'),
                                                block_detect_yara=''.join(block_detect_yara).decode('utf-8'),
                                                block_title=''.join(block_title).decode('utf-8'),
                                                block_header=''.join(block_header),
                                                block_public_info=''.join(block_public_info).decode('utf-8')))
            log.info('Build report: OK')
            return context
        except Exception as e:
            raise SAMSAnalysisError('Report building error')
            log.error('Build report fail: %s' % e)
            return ''

    def notify(self, message, data):
        if message == 'user_notify':
            self.start(data)
