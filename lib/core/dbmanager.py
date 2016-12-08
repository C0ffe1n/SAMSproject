# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import pymongo
import datetime


class DBManager(object):
    """
        Base class - works with DB (MongoDB, ElasticSearch and etc)
    """
    def __init__(self):
        self.session = None
        self.db = None
        self.dbname = ''
        # self.initialize()

    def init_db_ioc(self, dbname):
        self.dbname = dbname
        self.connect_to_db(self.dbname)
        return True
    
    def initialize(self, dbname):
        self.dbname = dbname
        return self.init_data_coll()

    def init_data_coll(self):
        self.connect_to_db(self.dbname)
        #self.db.analysis.remove()
        coll = self.db.fid.find_one({})
        self.close_session()
        if coll is None:
            self.create_coll_fid()
        return coll

    def create_coll_fid(self):
        day = datetime.date.today()
        doc = {"FIndex": 0, "Day": day.isoformat()}
        self.connect_to_db(self.dbname)
        self.db.fid.insert(doc)
        self.close_session()
        return True

    def add_in_coll(self, collname, data):
        self.connect_to_db(self.dbname)
        doc = data
        res = self.db[collname].insert(doc)
        self.close_session()
        
    def get_coll(self, collname, key_search):
        self.connect_to_db(self.dbname)
        coll = self.db[collname].find(key_search)
        self.close_session()
        return coll

    def update_coll_fid(self, index, day):
        self.connect_to_db(self.dbname)
        coll = self.db.fid.find_one({})
        if not coll is None:
            self.db.fid.update({'_id': coll['_id']}, {'FIndex': index, 'Day': day})
        else:
            self.close_session()
            return False
        return True

    def update_status_task(self, _id, status):
        res = self.update_field_coll('analysis',
                               _id,
                               {
                                   'status': status
                               })
        if res:
            return True
        else:
            return False

    def update_data_task(self, _id, data):
        res = self.update_field_coll('analysis',
                                  _id,
                                  data)
        if res:
            return True
        else:
            return False

    def update_field_task(self, _id, name_field, value, status):
        res = self.update_field_coll('analysis',
                               _id,
                               {
                                   'status': status,
                                   name_field: value
                               })
        if res:
            return True
        else:
            return False

    def get_task(self, field, value):
        res = self.get_coll('analysis', 
                            {
                                field: value
                            })
        return res
                                
    def update_field_coll(self, collname, _id, field):
        self.connect_to_db(self.dbname)
        coll = self.db[collname].find({})
        if not coll is None:
            self.db[collname].update({'_id': _id}, {'$set': field})
        else:
            self.close_session()
            return False
        return True

    def clear_coll_fid(self):
        self.connect_to_db(self.dbname)
        coll = self.db.fid.find_one({})
        self.db.fid.remove({'_id': coll['_id']})
        self.close_session()

    def connect_to_db(self, dbname):
        self.session = pymongo.MongoClient()
        self.db = self.session[dbname]
        return True

    def close_session(self):
        self.session.close()

# Proto func fulltxt_search test 
    def fulltxt_search(self, collname, word):
        # full text search key-word
        print '!!!!!!!!!!!!!!!!!!'
        data = []
        self.connect_to_db(self.dbname)
        #self.db.tfts.remove()
        #coll = self.db.tfts
        #self.db.tfts.create_index([("data","text")])
        #self.db.tfts.insert({"data":"aaa bbb ccc ddd", "author":"user1"})
        #self.db.tfts.insert({"data":"eee fff ggg aaa", "author":"user2"})
        #self.db.tfts.insert({"data":"eee fff ggg bbb", "author":"user3"})
        #print coll
        data = self.db.analysis.find({"$text": {"$search": "sams/analysis/malware/563e79b"}})
        #for k in data:
             #print k["data"]
        self.close_session()
        return data

    def find_func(self, collname, key_search):
        self.connect_to_db(self.dbname)
        coll = self.db[collname].find({})
        #coll = self.db[collname].find(key_search)
        self.close_session()
        return coll
