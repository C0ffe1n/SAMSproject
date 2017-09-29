# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

import sys
import os
import argparse
import datetime
import logging

from lib.core.controller import ControlApp
from lib.common.constants import _VERSION

log = logging.getLogger()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-v", "--version", action="version", version="You are running System Analysis of eMail messageS {0}".format(_VERSION))
    args = parser.parse_args()
    
    try:
        sams = ControlApp()
        sams.start(debug=args.debug)
    except KeyboardInterrupt:
        log.setLevel(logging.INFO)
        log.info('Stoping analysis system SAMS.')
        sams.stop()


if __name__ == '__main__':
    main()
    sys.exit(0)
