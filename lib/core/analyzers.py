# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is a part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' file for copying permission.

import hashlib
import os
import logging
import uuid
import datetime
#from parseexres import ParseTE
#from parseexres import ParseTH
from lib.extsrc import VirusTotal
from lib.core.malwareprofile import MalwareManager
from lib.core.filemanager import FileManager
from lib.core.dbmanager import DBManager
from lib.core.avscan import AVScanner,YARAScanner
from lib.core.sandbox import SandBox
from lib.categoryfilters import ExtExecFilters
from lib.common.constants import WHITE_LIST_FLAG, INCIDENT_TRUE_FLAG, AGRINFO_POSITIVE_FLAG, AV_DETECT_FLAG, YARA_DETECT_FLAG, SUSPECT_FTYPE_FLAG, NET_ACTIVITY_FLAG, AMOUNT_ITEMS_FLAG, IOC_DETECT_FLAG

log = logging.getLogger(__name__)

try:
    import yara
    YARA_INIT = True
except ImportError:
    YARA_INIT = False

try:
    import pyclamd
    AV_INIT = True
except ImportError:
    AV_INIT = False
    
class Analyzer(object):
    """
        Base class - analyzer samples
    """
    def __init__(self, cfg):
        log.setLevel(logging.INFO)
        log.info('Initialize dynamic analysis manager')
        self.exe = ExtExecFilters()
        self.cfg = cfg
        self.FM = FileManager(cfg)
        self.MalM = MalwareManager(cfg.analyzer)
        self.sandbox = SandBox(cfg.analyzer)
        self.db_ioc = DBManager()
        self.db = DBManager()
        self.sb_tasks = {}
        data = self.db_ioc.init_db_ioc('ioc_db_stat')
        data = self.db.initialize('samsdb')
        #self.add_ioc_item_db(None)

    def status(self):
        return self.state

    def run(self):
        pass
    
    def notify(self):
        pass

class AnalyzerMalware(Analyzer):
    """Malware Analyzer.

    """

    def run(self, task):
        result = self.FM.run(task)
        if not result:
            return 'fail'
        self.db.update_field_task(task['_id'],'attachment', self.FM.attachname, 'analysis')
        task['attachment'] = self.FM.attachname
        
        result = self.MalM.run(task)
        if not result:
            return 'fail'
        
        parent_incident = task
        # Check in incidents DB
        hdata = self.db.get_task('hashes.md5', self.MalM.attach_md5)
        if hdata.count() > 0:
            log.info('takoy est!')
            parent_incident = hdata.next()
            hdata.rewind()
            self.MalM.verdict = self.verd_calc(MalM, hdata, INCIDENT_TRUE_FLAG)
            
            # Check amount items in incidents DB 
            if hdata.count() > 10:
                self.MalM.verdict = self.verd_calc(MalM, None, AMOUNT_ITEMS_FLAG)
            
            # Check the status of the previous existing incident in incidents DB
            if not parent_incident['verdict'] in ['malware', 'suspect']:
                if parent_incident['verdict'] == 'undefined' and ((self.MalM.verdict & AMOUNT_ITEMS_FLAG) and AMOUNT_ITEMS_FLAG):
                    self.MalM.detect = 'suspect'
                    return 'success'
            else:
                self.MalM.detect = parent_incident['verdict']
            return 'success'

        self.vt = VirusTotal(self.cfg)
       #self.te = ParseTE()
       #self.th = ParseTH()
        if self.static_analysis(parent_incident):
            return 'success'
        self.sb_tasks = self.dynamic_analysis()
        return 'success'
    
    def interpret_verdict(self, verdict_status):
        if (verdict_status & INCIDENT_TRUE_FLAG) and INCIDENT_TRUE_FLAG:
            return True
        
    def static_analysis(self, parent_incident):
        self.detect = False
        log.info('Check indicator by IOC DB')
        if self.check_ioc_db(self.MalM.hashes):
            self.MalM.verdict = self.verd_calc(self.MalM, None, IOC_DETECT_FLAG)
            self.MalM.detect = 'malware'
            self.detect = True
            log.info('[!] IOC DB matches')
            return self.detect
        log.info('IOC DB not matches')    
        avMgr = AVScanner()
        yaraMgr = YARAScanner()
        
        rscan = avMgr.scan_dir(self.MalM.sample_path)
        log.info('Local antivirus scanning')
        if not rscan is None:
            self.MalM.LAV_result = []
            for item in rscan:
                self.MalM.LAV_result.append(dict(name=os.path.basename(str(item)),
                                                  result=str(rscan[item][1])))
            self.MalM.verdict = self.verd_calc(self.MalM, None, AV_DETECT_FLAG)
            self.MalM.detect = 'malware'
            self.detect = True
            log.info('[!] Local antivirus detect')
            return self.detect
        log.info('Local antivirus - Clean')

        rscan = yaraMgr.match(self.MalM.listf)
        log.info('YARA scanning')
        if not rscan is None:
            self.MalM.YA_result = []
            for item in rscan:
                self.MalM.YA_result.append(dict(name=os.path.basename(str(item)),
                                                  result=str(rscan[item])))
            self.MalM.verdict = self.verd_calc(self.MalM, None, YARA_DETECT_FLAG)
            self.MalM.detect = 'malware'
            self.detect = True
            log.info('[!] YARA detect')
            return self.detect
        log.info('YARA - Clean')

        log.info('VirusTotal request')
        self.MalM.detailinfoVT = []
        req_str = dict(detect=None,
                       list_detect=None,
                       link=None)
        for item in self.MalM.hashes:
            for k in item:
                res = self.vt.run(item[k])
                if not res is None:
                    if res.get('scans'):
                        self.MalM.detailinfoVT.append(dict(detect=res['positives'],
                                                            list_detect=res['scans'],
                                                            link=res['permalink']))
                        log.info('[!] VirusTotal positives: '+str(res['positives']))
                    else:
                        self.MalM.detailinfoVT.append(req_str)
                        log.info('VirusTotal - no data')
                else:
                    self.MalM.detailinfoVT.append(req_str)
                    log.info('VirusTotal - no data')
        return self.detect
    
    def verd_calc(self, profile_malware, incidents, set_flag):
        if incidents is None:
            result = profile_malware.verdict | set_flag
        else:
            for item in incidents:
                if item['_id'] != 'whitelist':
                    result = profile_malware.verdict | set_flag
                    break        
        return result
    
    def check_ioc_db(self, hashes):
        for item in hashes:
            for k in item:
                hdata = self.db_ioc.get_coll('ioc_coll', {'_id': uuid.uuid3(uuid.NAMESPACE_DNS, item[k])})
                if hdata.count() > 0:
                    return True
        return False        
        
    def dynamic_analysis(self):
        self.detect = False
        res = []
        log.info('Start dynamic analysis')
        for item in self.MalM.listf:
            if item[item.rfind('.')+1:] in self.exe.list:
                id_task = self.analysisSB(item)
                if not id_task is None:
                    res.append({'sample': item, 'id_task': id_task, 'status': 'Sending'})
                    log.info('Sample: '+item)
                    log.info('Task: '+str(id_task))
                else:
                    res.append({'sample': item, 'id_task': id_task, 'status': 'Failed'})
            else:
                res.append({'sample': item, 'id_task': None, 'status': 'Not sending'})
                log.info('Not sending: '+item)
        return res

    def add_ioc_item_db(self, _data):
        ioc_name = 'a67e1aa6347d9d501458db3000eeab8e'
        _id = uuid.uuid3(uuid.NAMESPACE_DNS, ioc_name)
        hdata = self.db_ioc.get_coll('ioc_coll', {'_id': uuid.uuid3(uuid.NAMESPACE_DNS, ioc_name)})
        if hdata.count() == 0:
            timestamp = datetime.datetime.now()
            query = {'_id': _id,
                    'ioc': ioc_name,
                    'ioc_type': 'hash',
                    'ioc_source': 'sams',
                    'ioc_author': 'coffein',
                    'ioc_date_add': timestamp
            }
            self.db_ioc.add_in_coll('ioc_coll', {'_id': _id,'ioc': ioc_name,'ioc_type': 'hash','ioc_source': 'sams','ioc_author': 'coffein','ioc_date_add':timestamp})
            hdata = self.db_ioc.get_coll('ioc_coll', {'_id': uuid.uuid3(uuid.NAMESPACE_DNS, ioc_name)})
        return

    def analysisSB(self, sample):
        log.info('File analysis in Sandbox...')
        return self.sandbox.start(sample)
