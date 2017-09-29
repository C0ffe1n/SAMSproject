# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import datetime

from lib.core.aggregators import VTAPI, TEAPI, THAPI
from lib.core.checker import Checker
from lib.core.scanners import AVScanner,YARAScanner
from lib.common.objects import SuspectFileExt

log = logging.getLogger(__name__)

class BaseAnalysis(object):

    def static_analysis(self):
        raise NotImplementedError

    def dynamic_analysis(self):
        raise NotImplementedError

class FileAnalysis(BaseAnalysis):
    
    def get_public_info(self, hashes):
        print hashes
        list_detect = dict()
        #vt = VirusTotal()
        vt_info = None
        te_info = None
        th_info = None
        #te = ParseTE()
        #th = ParseTH()
        timestamp = datetime.datetime.now()
        result = VTAPI().run(hashes['md5'])
        if not result is None:
            if result.get('scans'):
                log.info('[!] VirusTotal positives: '+str(result['positives']))
                for item in result['scans']:
                    if result['scans'][item]['detected']:
                        list_detect[item] = result['scans'][item]
                vt_info = dict(detect=result['positives'],
                               list_detect=list_detect,
                               link=result['permalink'])
        #result = te.run(hashes['md5'])
        #if result:
            #print result
        #result = th.run(hashes['sha1'])
        #if result:
            #print result
        
        return dict(agreg_ioc=dict(vt=vt_info,
                                   te=te_info,
                                   th=th_info,
                                   date_req=timestamp))

    def av_scan(self, sample_path):
        avMgr = AVScanner()
        rscan = avMgr.scan_file(sample_path)
        log.info('Local antivirus scanning')
        if not rscan is None:
            log.info('[!] Local antivirus detect')
            for item in rscan:
                return rscan[item][1]            
        log.info('Local antivirus - Clean')
        return None
        
    def yara_scan(self, sample_path):    
        yaraMgr = YARAScanner()
        list_detect = []
        rscan = yaraMgr.match_file(sample_path)
        log.info('YARA scanning')
        if not rscan is None:
            log.info('[!] YARA detect')
            for item in rscan:
                list_detect.append(str(item))
            return list_detect
        log.info('YARA - Clean')
        return None

    def check_ioc(self, _data):
        checker = Checker()
        _verdict = None
        query_data = dict(field='analyzed_samples_info',
                          subfield='hashes.md5',
                          value=_data['hashes']['md5'],
                          elem_match=True)
        # req_type: db_inc or db_ioc
        result = checker.run('db_inc', query_data)
        if result:
            for item in result['analyzed_samples_info']:
                if item['hashes']['md5'] == _data['hashes']['md5']:
                    _verdict = item['verdict']
                    break
            return dict(id_inc=result['_id'],
                        verdict=_verdict)
        return None

    def static_analysis(self, obj):
        exec_obj = SuspectFileExt()
        detection = False
        log.setLevel(logging.INFO)
        log.info('Static analysis file')
        info_obj_list = []
        
        for item in obj:
            _info = item.get_info()
            _info['primary_inc'] = None
            _info['verdict'] = None
            
            #self.check_ioc_db(_info['hashes'])
            result = self.check_ioc(_info)
            if result:
                _info['primary_inc'] = result['id_inc']
                _info['verdict'] = result['verdict']
                detection = True
            else:
                _info['yara'] = None
                _info['loc_av'] = None 
                result = self.av_scan(_info['path'])
                if result:
                    _info['loc_av'] = result
                    detection = True
                result = self.yara_scan(_info['path'])
                if result:
                    _info['yara'] = result
                    detection = True
                _public_info = self.get_public_info(_info['hashes'])
                _info['public_info'] = _public_info
                if _public_info['agreg_ioc'].get('vt'):
                    detection = True
                if detection:
                    _info['verdict'] = u'malware'
                else:
                    result = exec_obj.identity(_info['path'])
                    if result:
                        _info['verdict'] = u'suspect'
        return detection

    def dynamic_analysis(self):
        log.info('Dynamic analysis file')

class LinkAnalysis(BaseAnalysis):
    def static_analysis(self, obj):
        log.info('Static analysis link')

    def dynamic_analysis(self):
        log.info('Dynamic analysis link')
        
class Analyzer(object):
    _mapping = {
                'file': FileAnalysis,
                'link': LinkAnalysis}
    
    def __init__(self, data):
        self.data = data
        
    def run(self, analyzed_attachments, analyzed_samples):
        _type = self.data['type']
        result = self.static_analysis(_type, analyzed_samples)
        if not result:
            result = self.static_analysis(_type, analyzed_attachments)
        return dict(status=True,
                    detected=result)
    
    def static_analysis(self, _type, obj):
        return self._mapping[_type]().static_analysis(obj)

    def dynamic_analysis(self):
        raise NotImplementedError
    
    def decide(self, data):
        raise NotImplementedError
