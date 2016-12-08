# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


class Dictionary(dict):
    """Cuckoo custom dict."""

    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

class URL:
    """URL base object."""

    def __init__(self, url):
        """@param url: URL"""
        self.url = url