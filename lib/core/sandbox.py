# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import os
import re
import time
import subprocess
import Queue
import threading
import json
import requests
import logging
#from futils import File
#from lib.profilemalware import ProfileMalware
#from lib.monitorsb import MonitorSB

log = logging.getLogger(__name__)

class SandBox(object):

    """Base class for Sandbox."""

    def __init__(self, cfg):
        log.setLevel(logging.INFO)
        log.info("Initialize Sandbox")
        self.sb_name = "Sandbox ***"
        self.cmd = "curl"
        self.sb_ip = cfg.sb_ip
        self.sb_host = "http://"+self.sb_ip+":"+str(cfg.sb_port)
        self.sb_target = "file=@"
        self.api_send = "/tasks/create/file"
        self.api_status = "/tasks/view"
        self.api_report = "/tasks/report"
        self.sb_options = "-F"
        self.sb_store = "/home/kav/develop/Cuckoo/cuckoo-master/storage/analyses/"
        self.sb_param = "/home/kav/Desktop/share/Infected/Virus/blank.exe"
        self.FILE_SCAN = self.sb_host+self.api_send
        self.status = None
        self.target = None
        #self.loop = MonitorSB()
        self.fabort = False
        self.reportSB = None
        self.complete = False
        self.id_task = None

    def _request_json(self, url, **kwargs):
        try:
            r = requests.post(url, timeout=60, **kwargs)
            return r.json() if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            log.error( "Unable to fetch Sandbox results: %r" % e.message)

    def file_scan(self, filepath):
        """Submit a file to be scanned.
        @param filepath: file path
        """
        files = {"file": open(filepath, "rb")}
        r = self._request_json(self.FILE_SCAN, files=files)
        if r is None:
            return None
        else:
            return r.get("task_id")

    def get_report(self):
        proc = subprocess.Popen([self.cmd,
                                 self.sb_host+self.api_report+"/"+self.id_task
                                ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        output, err = proc.communicate()
        if(output):
            self.reportSB = json.loads(output)
            return "success"
        else:
            return "aborted"
              

    def get_status(self, id_task):
        proc = subprocess.Popen([self.cmd,
                                 self.sb_host+self.api_status+"/"+id_task
                                ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        output, err = proc.communicate()
        if(output):
            ask = json.loads(output)
            return ask["task"]["status"]
        else:
            return 'aborted'    

    def start(self, target):
        self.target = target
        return self.file_scan(self.target)

    def parseReport(self):
        trueTestAV = False;
        fname_report = self.sb_store+str(self.target.id_task)+'/reports/report.json'
        try:
            fd = open(fname_report, 'r').read()
            report = {}
            report = json.loads(fd)
            doc = {}
            if 'info' in report:
                doc["info"] = report['info']
            if 'target' in report:
                doc["target"] = report['target']
            if 'dropped' in report:
                doc["dropped"] = report['dropped']
#            if 'strings' in report:
#                doc["strings"] = report['strings']
            doc["behavior"] = {}
            if 'behavior' in report:
                if 'summary' in report['behavior']:
                    doc["behavior"]["summary"] = report['behavior']['summary']
            doc["virusdetect"] = {}
            if 'virustotal' in report:
                if 'scan_id' in report['virustotal']:
                    doc["virusdetect"]["scan_id"]=report['virustotal']['scan_id']
                if 'sha1' in report['virustotal']:
                    doc["virusdetect"]["sha1"]=report['virustotal']['sha1']
                if 'sha256' in report['virustotal']:
                    doc["virusdetect"]["sha256"]=report['virustotal']['sha256']
                if 'md5' in report['virustotal']:
                    doc["virusdetect"]["md5"]=report['virustotal']['md5']
                if 'resource' in report['virustotal']:
                    doc["virusdetect"]["resource"]=report['virustotal']['resource']
                if 'permalink' in report['virustotal']:
                    doc["virusdetect"]["permalink"]=report['virustotal']['permalink']
                if 'positives' in report['virustotal']:
                    doc["virusdetect"]["positives"]=report['virustotal']['positives']
                doc["virusdetect"]["scans"] ={}
                if 'scans' in report['virustotal']:
                    for key in report['virustotal']['scans']:
                        if str(report['virustotal']['scans'][key]['detected']) == "True":
                            doc["virusdetect"]["scans"][key] = report['virustotal']['scans'][key]
                            trueTestAV = True
                        if str(key) == "McAfee":
                            doc["virusdetect"]["scans"][key] = report['virustotal']['scans'][key]
                        if str(key) == "McAfee-GW-Edition":
                            doc["virusdetect"]["scans"][key] = report['virustotal']['scans'][key]
                        if str(key) == "Kaspersky":
                            doc["virusdetect"]["scans"][key] = report['virustotal']['scans'][key]
            self.target.detailsb = doc
        except Exception as e:
            log.error("Processing failed: %s" % e)
