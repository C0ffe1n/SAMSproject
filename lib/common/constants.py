# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import os

_VERSION = '0.2-beta'
_CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
_ROOT = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..'))
_QUEUE_DIR = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..', 'queue'))
_TMP_DIR = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..', 'tmp'))
_LOG_DIR = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..', 'log'))
_ANALYSIS_DIR = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..', 'analysis'))
_BACKUP_DIR = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..', 'backup'))
_DATA_DIR = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..', 'data'))
_TEMPLATES_DIR = os.path.normpath(os.path.join(_DATA_DIR, 'templates'))

_MSG_NOTIFY ='default_msg.html'
_MSG_NOTIFY_USER ='user_notify.html'
_MSG_NOTIFY_USER_GOOD =''
_MSG_NOTIFY_USER_BAD =''
_MSG_NOTIFY_USER_INCORR =''

INIT_DATA               =   0b000000000
WHITE_LIST_FLAG         =   0b100000000
INCIDENT_TRUE_FLAG      =   0b010000000
IOC_DETECT_FLAG         =   0b001000000
AGRINFO_POSITIVE_FLAG   =   0b000100000
YARA_DETECT_FLAG        =   0b000010000
AV_DETECT_FLAG          =   0b000001000
SUSPECT_FTYPE_FLAG      =   0b000000100
NET_ACTIVITY_FLAG       =   0b000000010
AMOUNT_ITEMS_FLAG       =   0b000000001

DETECT_MALWARE          =   0b0100000
DETECT_SUSPECT          =   0b0010000
DETECT_ANOMALY          =   0b0001000

STATUS_CRITICAL         =   0b0111111
STATUS_HIGH             =   0b0011111
STATUS_MEDIUM           =   0b0001111
STATUS_LOW              =   0b0000111

WORK_MODE_USERFEED = u'userfeed'
WORK_MODE_NORMAL = u'normal'

PUBLIC_STRUCT = {
                  'detect': '',
                  'list_detect': '',
                  'link': ''
                }

SANDBOX_DETECT_STRUCT = {
                          'api_list': None,
                          'proc_list': None,
                          'file_list': None,
                          'reg_list': None,
                          'domain_list': None,
                          'ip_list': None
                        }

AGREG_DETECT_STRUCT = {
                        'yara': None,
                        'loc_av': None,
                        'agreg_ioc': {
                                       'vt': PUBLIC_STRUCT,
                                       'te': PUBLIC_STRUCT,
                                       'th': PUBLIC_STRUCT,
                                       'date_req': None
                                     },
                        'sb_report': SANDBOX_DETECT_STRUCT
                      }
                        
TAXONOMY = {
                    'type_attach': '',
                    'type_samples': '',
                    'hashes': '',
                    'mta': '',
                    'parent': '',
                    'received': '',
                    'recipient': '',
                    'samples_desc': '',
                    'sandbox_tasks': '',
                    'sender': '',
                    'status': '',
                    'subject': '',
                    'user_agent': '',
                    'verdict': '',
                    'detect': AGREG_DETECT_STRUCT
                }


FILTER_CHK_LIMIT_FSIZE = 0b000000001
FILTER_CHK_SUBJECT = 0b000000010
FILTER_IDENT_ATTACH_TYPE = 0b000000100
FILTER_EML_FROM = 0b000001000
