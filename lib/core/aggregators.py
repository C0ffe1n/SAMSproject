# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import urllib
import urllib2
import json
import re
import time
import requests
import logging

log = logging.getLogger(__name__)

"""
https://www.reasoncoresecurity.com/knowledgebase_resource.aspx?sha1=
"""


"""
ThreatExpert
"""
class TEAPI(object):
    """Basic file object class with all useful utilities."""

    def __init__(self):
        """@param file_path: file path."""
        self.url = 'http://www.threatexpert.com/report.aspx'
        self.params = '?md5='
        log.setLevel(logging.INFO)

    def initialize(self):
        self.init_avinfo = False
        self.info = {}

    def run(self, hash):
	"""hash md5"""
        self.initialize() 
        self.params = self.params+hash 
        print self.url+self.params
        link = urllib.urlopen(self.url+self.params)
        #print link
        reportdone=0
        for line in link:
            line = line.strip("\n")
            if reportdone == 0:
                if line.find("<meta name=\"description\"")>-1:
                    reportdone = 1
                    strtmp = line[line.find("content="):]
                    strtmp = strtmp[strtmp.find("\"")+1:]
                    strtmp = strtmp[:strtmp.find("\"")]
                    namereport = strtmp[:strtmp.find(":")]
                    strtmp = strtmp[strtmp.find(":")+2:-2]
                    #self.info['ThreatName'] = strtmp.split(", ")
            if reportdone == 1:
                if line.find("Submission details:")>-1:
                    reportdone = 2
                    self.info['AVDetect'] = []
                    continue
            if reportdone == 2:
                if line.find("Submission received:")>-1:
                    strtmp = line[line.find(":")+2:line.find("</")]
                    self.info['Received'] = strtmp
                elif line.find("Filesize:")>-1:
                    strtmp = line[line.find(":")+2:line.find("</")]
                    self.info['Filesize'] = strtmp
                elif (line.find("[")>-1) and (line.find("]")>-1):
                    if re.search("\<li\>.*\<\/li\>", line):#line[:4] == '<li>':
                        p = re.compile('(\<li\>)|(\<ul\>)|(\<\/li\>)|(\<a.*\"\>)|(\<img.*\/a\>)')
                        strtmp = p.sub('',line)
                        self.info['AVDetect'].append(strtmp)
                if line.find("Summary of the findings:")>-1:
                    reportdone = 3
                    break;
        return self.info

"""
TotalHash
"""
class THAPI(object):
    """Basic file object class with all useful utilities."""

    def __init__(self):
        """@param file_path: file path."""
        self.url = 'http://totalhash.com/analysis/'
        self.params = ''
        log.setLevel(logging.INFO)

    def initialize(self):
        self.init_avinfo = False
        self.info = {}

    def run(self, hash):
	"""hash sha1"""
        self.initialize() 
        self.params = hash
        link = urllib.urlopen(self.url+self.params)
        reportdone=0
        for line in link:
            line = line.strip("\n")
            if re.search("\<table class\=\"analysis\"\>.*", line):
                p = re.compile('(\<\/tr\>)|(\<\/p\>)')  #|(\<\/li\>)|(\<a.*\"\>)|(\<img.*\/a\>)') 
                line = p.sub('\n',line)
                p = re.compile('(\<\/th\>)|(\<a.*\"\>)')  #|(\<\/li\>)|(\<a.*\"\>)|(\<img.*\/a\>)') 
                line = p.sub('\t',line)
                p = re.compile('(\<tr\>)|(\<th\>)|(\<td\>)|(\<td.*\"\>)|(\<\/td\>)|(\<\/span\>)|(\<\/table.*\/b\>)|(\<.*class\=\".*\"\>|(\<\/a\>))|(Screen.*\<img.*\/\>)|(\<table class=.*\<br \/\>|(\<\/html\>))')
                line = p.sub('',line)
                self.info = line.split('\n')                
                break
        return self.info

"""
VirusTotal
"""
VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/vtapi/v2/file/report"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/vtapi/v2/url/report"

class VTAPI(object):
    """Gets antivirus signatures from VirusTotal.com"""
    def __init__(self):
        """@param file_path: file path."""
        self.key = "virustotal"
        self.api_key = "73b3eef349c6c98875b784dcae13fb16f4f25ec3c70ac80c365015f0e1d8d68e"
        log.setLevel(logging.INFO)

    def _request_json(self, url, **kwargs):
        try:
            r = requests.post(url, timeout=60, **kwargs)
            return r.json() if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            log.error(e)
    
    def run(self, hash):
        """Runs VirusTotal processing
        @return: full VirusTotal report.
        hash md5
        """
        self.virustotal = []
        self.task = []
        #self.hash = hash
        #VT API key 73b3eef349c6c98875b784dcae13fb16f4f25ec3c70ac80c365015f0e1d8d68e
        if not self.api_key:
            log.info("VirusTotal API key not configured, skip")

        #resource = self.hash
        url = VIRUSTOTAL_FILE_URL

        data = dict(resource=hash, apikey=self.api_key)
        return self._request_json(url, data=data)
