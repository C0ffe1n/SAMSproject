# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
from lib.exceptions import SAMSAnalysisError
from lib.common.constants import WHITE_LIST_FLAG, INCIDENT_TRUE_FLAG, AMOUNT_ITEMS_FLAG, AV_DETECT_FLAG, IOC_DETECT_FLAG, YARA_DETECT_FLAG
from lib.common.constants import _TEMPLATES_DIR, _MSG_NOTIFY, _MSG_NOTIFY_USER
try:
    from jinja2 import Template, Environment, FileSystemLoader
    J2_INIT = True
except ImportError:
    J2_INIT = False
    
log = logging.getLogger(__name__)    

class Reporter():
    def __init__(self, cfg):
        self.cfg = cfg
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
    
    def build_report(self, task, MalM, run_tasks):
        try:
            template = self.init_template(_MSG_NOTIFY)
            report_sb = list()
            block_detect = list()
            block_title = list()
            block_header = list()
            #Title info
            if (MalM.verdict & AMOUNT_ITEMS_FLAG) and AMOUNT_ITEMS_FLAG:
                block_detect.append('WARNING: High amount of such incidents!\r\n\r\n')
            if (MalM.verdict & AV_DETECT_FLAG) and AV_DETECT_FLAG:
                block_detect.append('WARNING: Local AntiVirus detection!\r\n')
                for i in MalM.LAV_result:
                    block_detect.append(i['name']+': '+i['result'])
                    block_detect.append('\r\n')
                block_detect.append('\r\n')
            if (MalM.verdict & YARA_DETECT_FLAG) and YARA_DETECT_FLAG:
                block_detect.append('WARNING: YARA rules detection!\r\n')
                for i in MalM.YA_result:
                    block_detect.append(i['name']+': '+i['result'])
                    block_detect.append('\r\n')
                block_detect.append('\r\n')
            if (MalM.verdict & IOC_DETECT_FLAG) and IOC_DETECT_FLAG:
                block_detect.append('WARNING: Detection by IOCs DB!\r\n\r\n')
            block_title.append('SAMS-ID#'+str(task['_id'])+ '\r\n')
            block_title.append('http://'+self.cfg.analyzer.webui_domain+':'+str(self.cfg.analyzer.webui_port)+'/webui/detail_id/'+str(task['_id'])+ '\r\n')
            block_header.append(MalM.report + '\r\n' + MalM.headers +'\r\n')
            report_sb.append('Sandbox Task:' + '\r\n')
            if not run_tasks is None:
                for item in run_tasks:
                    if not item['id_task'] is None:
                        report_sb.append('http://'+self.cfg.analyzer.sb_domain+'/analysis/'+str(item['id_task']) + '\r\n')
                    else:
                        report_sb.append('Failed sample sending to the Sandbox.\r\n')
            report_sb.append('\r\nResult VirusTotal:')
            if not MalM.detailinfoVT is None:
                
                for item in MalM.detailinfoVT:
                    if not item is None:
                        if not item.get('detect') is None:
                            if item['detect'] > 0:
                                report_sb.append('\r\n' + item['link'])
                                for key in item['list_detect']:
                                    if item['list_detect'][key]['detected']:
                                        report_sb.append('\r\n'+ key+': '+item['list_detect'][key]['result'])
                            else:
                                report_sb.append('\r\n' + item['link'])
                                report_sb.append('\r\nNot detected by any anti-virus')
                        else:
                            report_sb.append('\r\nData not available')
            
            if J2_INIT:
                context = template.render(dict(block_detect=''.join(block_detect).decode('utf-8'),
                                                block_title=''.join(block_title).decode('utf-8'),
                                                block_header=''.join(block_header),
                                                report_sb=''.join(report_sb).decode('utf-8')))
            else:
                log.info('No Jinja2')
                result = []
                for item in [block_detect, block_title, block_header, report_sb]:
                    result.extend(item)
                context = ''.join(result).decode('utf-8')
            log.info('OK')
            return context
        except Exception as e:
            raise SAMSAnalysisError('Report building error')
            log.error('Build report fail: %s' % e)
            return ''

    def build_user_notify(self, MalM, attachments, _id):
        try:
            _from = MalM.sender[0]['full_name']+' ['+MalM.sender[0]['email']+']'
            _attachments = []
            _id_incident = 'SAMS-ID#'+_id
            for item in attachments:
                _attachments.append(item['attach_name'])
                _attachments.append('\r\n')
            template = self.init_template(_MSG_NOTIFY_USER)
            context = ''
            
            if J2_INIT:
                context = template.render(dict(from_name=''.join(_from),
                                            subject=''.join(MalM.subject),
                                            attachments=''.join(_attachments).decode('utf-8'),
                                            id_incident=''.join(_id_incident).decode('utf-8')))
            else:
                context = 'Вам пришло подозрительное письмо, возможно, содержащее вирусы. Просим ни при каких обстоятельствах не открывать вложение!\n'
                context = context + '\nЕсли Вы открыли вложение или уверены, что письмо безопасно, Вам необходимо связаться с нами для уточнения дальнейших действий.\nСпасибо.'
                context = context+ '\n\nПодозрительное письмо содержит:\n'
                context = context+ '\nОтправитель: '+MalM.sender[0]['full_name']+' ['+MalM.sender[0]['email']+']'
                context = context+ '\nТема: RE:'
                context = context + '\nИдентификатор инцидента - SAMS-ID#'+_id+'\n'
                context = context + ''.join(self.sign)
            log.info('OK')
            return context
        except:
            raise SAMSAnalysisError('Report building error')
            log.error('User notify build failed: %s' % e)
            return ''
