# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import ConfigParser

from lib.common.constants import _ROOT
from lib.common.objects import Dictionary


class Config:
    """File parser configuration."""

    def __init__(self, cfg=os.path.join(_ROOT, "conf", "sams.conf")):
        """@param cfg: configuration file path."""
        config = ConfigParser.ConfigParser()
        config.read(cfg)

        for section in config.sections():
            setattr(self, section, Dictionary())
            for name, raw_value in config.items(section):
                try:
                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)

                setattr(getattr(self, section), name, value)

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @raise CuckooOperationalError: if section not found.
        @return: option value.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:
            print("Option %s is not found in configuration, error: %s")
