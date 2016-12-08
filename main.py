# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import sys
import os
import argparse
import datetime
import logging

from lib.core.manager import init_console_logging
from lib.core.manager import Manager

log = logging.getLogger('main')

def main():
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    
    init_console_logging()
    try:
        sams = Manager()
        sams.start()
    except KeyboardInterrupt:
        log.info('Stoping analysis system SAMS.')
        sams.stop()


if __name__ == '__main__':
    main()
    sys.exit(0)
