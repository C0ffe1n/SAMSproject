# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS).
# See the file 'docs/LICENSE' for copying permission.

import copy
import os
import logging
import logging.handlers
from lib.colors import red, green, yellow, cyan
from lib.core.controller import NotificationEvent
from lib.core.dispatchers import PostDispatcher, PostGrader, AnalysisDispatcher
from lib.common.constants import _ROOT

log = logging.getLogger()


class Manager(NotificationEvent):
    """
        Controller
    """

    def initialize(self):
        log.setLevel(logging.INFO)
        log.info('Initialize manager objects')
        self.email_monitor = PostDispatcher(self)
        self.register(self.email_monitor)
        self.post_grader = PostGrader(self)
        self.register(self.post_grader)
        self.analyz_dispatcher = AnalysisDispatcher(self.email_monitor)
        self.register(self.analyz_dispatcher)       

    def start(self):        
        self.initialize()
        log.info('[+] SAMS initialize done') 
        self.email_monitor.start()
        self.analyz_dispatcher.start('init')
        

    def stop(self):
        self.running = False
        self.send_msg('stop')

    def update(self, message):
        self.send_msg(message)


class ConsoleHandler(logging.StreamHandler):
    """Console handler logging."""

    def emit(self, record):
        colored = copy.copy(record)

        if record.levelname == 'WARNING':
            colored.msg = yellow(record.msg)
        elif record.levelname == 'ERROR' or record.levelname == 'CRITICAL':
            colored.msg = red(record.msg)
        else:
            if 'analysis procedure completed' in record.msg:
                colored.msg = cyan(record.msg)
            elif '[+]' in record.msg:
                colored.msg = green(record.msg)
            elif '[!]' in record.msg:
                colored.msg = yellow(record.msg)
            else:    
                colored.msg = record.msg

        logging.StreamHandler.emit(self, colored)

def init_console_logging():
    """Initializes only console logging."""
    formatter = logging.Formatter('%(asctime)s [%(name)s] %(levelname)s: %(message)s')
    
    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)
    log.setLevel(logging.INFO)
    log.setLevel(logging.WARN)
    log.setLevel(logging.DEBUG)
    log.setLevel(logging.ERROR)
