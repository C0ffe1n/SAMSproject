# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS).
# See the file 'docs/LICENSE' for copying permission.

import copy
import os
import logging
import logging.handlers

from lib.common.config import Config
from lib.common.colors import red, green, yellow, cyan
from lib.common.abstarcts import NotificationEvent
from lib.core.emailmonitor import EmailMonitor
from lib.core.mailfilter import MailFilterManager
from lib.core.reporter import ReportManager
from lib.core.taskmanager import TaskManager
from lib.common.constants import _ROOT, _QUEUE_DIR, _TMP_DIR, _LOG_DIR, _ANALYSIS_DIR, _BACKUP_DIR

log = logging.getLogger()
_log = logging.getLogger(__name__)

class ControlApp(NotificationEvent):
    """
        Controller.
    """

    def initialize(self, debug):
        cfg = Config()
        self.init_directory()
        init_logging()
        if debug:
            _log.setLevel(logging.DEBUG)
            _log.debug('Initializing application in debug mode')
        else:
            _log.setLevel(logging.INFO)
            _log.info('Initializing the application')
        self.email_monitor = EmailMonitor(self, cfg)
        self.register(self.email_monitor)
        self.email_filter = MailFilterManager()
        self.email_filter.initialize(self, cfg)
        self.register(self.email_filter)
        self.reporter = ReportManager(self, cfg)
        self.register(self.reporter)
        self.analyz_dispatcher = TaskManager(self, cfg)
        self.register(self.analyz_dispatcher)       

    def init_directory(self):
        try:
            if not os.path.exists(_QUEUE_DIR):
                os.makedirs(_QUEUE_DIR)
            if not os.path.exists(_TMP_DIR):
                os.makedirs(_TMP_DIR)
            if not os.path.exists(_ANALYSIS_DIR):
                os.makedirs(_ANALYSIS_DIR)
            if not os.path.exists(_BACKUP_DIR):
                os.makedirs(_BACKUP_DIR)
            if not os.path.exists(_LOG_DIR):
                os.makedirs(_LOG_DIR)
        except OSError as e:
            _log.error(e)

    def start(self, debug):        
        self.initialize(debug)
        _log.info('[+] SAMS initialized successfully') 
        self.email_monitor.start()
        #self.analyz_dispatcher.start('init')
        

    def stop(self):
        self.running = False
        self.update('stop')

    def update(self, message, data=None):
        self.send_msg(message, data)


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

def init_logging():
    """Initializes logging."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    fh = logging.handlers.WatchedFileHandler(os.path.join(_LOG_DIR, "samsservice.log"))
    fh.setFormatter(formatter)
    log.addHandler(fh)

    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    log.setLevel(logging.INFO)
    log.setLevel(logging.WARN)
    log.setLevel(logging.DEBUG)
    log.setLevel(logging.ERROR)

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
