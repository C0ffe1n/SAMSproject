# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import email

from email.header import Header
from lib.common.exceptions import SAMSAnalysisError

def decode_str(string, default="ascii"):
    for i, (text, charset) in enumerate(email.header.decode_header(string.strip())):
        return unicode(text, charset or default, errors='replace')
    
def normalize(data, default="ascii"):
    try:
        buf = []
        if data:
            if data[:2] == '=?':
                for item in data.split('\r\n'):
                    substr_list = item.split('?==?')
                    if len(substr_list) > 1:
                        for substr in substr_list:
                            if substr[:2] != '=?' and substr[-2:] != '?=':
                                buf.append(decode_str('=?'+substr+'?=', default))
                            elif substr[:2] == '=?' and substr[-2:] != '?=':
                                buf.append(decode_str(substr+'?=', default))
                            elif substr[:2] != '=?' and substr[-2:] == '?=':
                                buf.append(decode_str('=?'+substr, default))
                    else:
                        buf.append(decode_str(item, default))
            else:
                buf.append(data)
        return u''.join(buf)
    except Exception as e:
        raise SAMSAnalysisError('Data processing error: %s' % data)
