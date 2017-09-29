# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import os
import logging

from lib.common.constants import _ROOT
from lib.core.dbmanager import DBManager


log = logging.getLogger(__name__)


class Checker(object):
    """
        Checker
    """
    def __init__(self):
        log.setLevel(logging.INFO)
        log.info('Initialize module Checker')
        self.db = DBManager()
        self.collection = None
        self.detect = None

    def initialize(self, db_name):
        """
            ioc_db_stat - DB Threat Intelligence
            samsdb - DB incidents
        """
        self.db.initialize(db_name)
        self.collection = 'analysis'
    
    def build_query(self, query_data):
        query = dict()
        if query_data['subfield']:
            if query_data['elem_match']:
                query[query_data['field']] = {'$elemMatch': 
                                                  {query_data.get('subfield'): query_data.get('value')}}
            else:
                query[query_data['field']] = {query_data.get('subfield'): query_data.get('value')}
        else:
            query[query_data['field']] = query_data.get('value')
        return query
        
    def run(self, req_type, query_data):
        self.detect = False
        self.initialize('samsdb')
        log.info('Check indicator by DB incidents')
        _data = self.db.check_item_coll('analysis', self.build_query(query_data))
        if _data:
            log.info('[!] DB incidents matches')
            return _data
        log.info('DB incidents not matches')
        return None
