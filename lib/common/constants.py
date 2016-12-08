# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import os

_CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
_ROOT = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..'))
_QUEUE_DIR = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..', 'queue'))
_TMP_DIR = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..', 'tmp'))
_ANALYSIS_DIR = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..', 'analysis'))
_BACKUP_DIR = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..', 'backup'))
_DATA_DIR = os.path.normpath(os.path.join(_CURRENT_DIR, '..', '..', 'data'))
_TEMPLATES_DIR = os.path.normpath(os.path.join(_DATA_DIR, 'templates'))

_MSG_NOTIFY ='default_msg.html'
_MSG_NOTIFY_USER ='user_notify.html'

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
