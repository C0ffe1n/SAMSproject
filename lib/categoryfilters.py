# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

class ExtExecFilters():
    """Executable files filters ."""
    def __init__(self, *args, **kwargs):
        self.list = ('exe','scr','pif','js','vbs','bat','cmd','com','class','jar','epf','lnk', 'hta', 'ps1', 'wsf', 'svg', 'html')
    
class ExtArchFilters():
    """Archive files filters."""
    def __init__(self, *args, **kwargs):
        self.list = ('gzip','bzip2','bz2','Zip','tgz','RAR','cab','arj','7-zip','tar','ace','JAR','epf')
        self.pattern_arch = 'rar|zip|jar|tar|gzip|tgz|7z|bz2|cab|arj|ace|gz|z|uue|epf'
        self.pattern_end = '\.('+self.pattern_arch+')$'
        self.pattern_part = '(.*\.part[\d]{1,3}\.('+self.pattern_arch+')$)|(.*\.zip\.[\d]{1,3}$)|(.*\.7z\.[\d]{1,3}$)'
        self.pattern_magic = ''

class WhitePostDomainFilters():
    """Postdomain whitelist filters."""
    def __init__(self, *args, **kwargs):
        self.list = ('domain1.ru','domain2.com')

class WhiteListEmailFilters():
    """Mailbox whitelist filters."""
    def __init__(self, *args, **kwargs):
        self.list = ['skp@domain2.ru', 'soc@domain1.ru']

class ExtOfficeFilters():
    """Office doc files filters."""
    def __init__(self, *args, **kwargs):
        self.list = ('doc','docx','dot','dotm','docm','xls','xlsx','xlsm','ppt','pptx')
    
class ExtDocFilters():
    """Scan doc files filters."""
    def __init__(self, *args, **kwargs):
        self.list = ('pdf')
    
    
