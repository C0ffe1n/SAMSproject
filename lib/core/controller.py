# -*- coding: utf-8 -*-
# Copyright (C) 2015-2016 Alexey Karyabkin.
# This file is part of System Analysis of eMail messageS (SAMS)
# See the file 'docs/LICENSE' for copying permission.

class Event(object):
    """
        
    """
    def __init__(self, *args, **kwargs):
        pass

    def register(self, observer):
        pass

    def unregister(self, observer):
        pass

    def notify_all(self, *args, **kwargs):
        pass


class NotificationEvent(Event):
    def __init__(self, *args, **kwargs):
        self._observers = []

    def register(self, observer):
        self._observers.append(observer)

    def unregister(self, observer):
        self._observers.remove(observer)

    def notify_all(self, message):
        for observer in self._observers:
            observer.notify(message)

    def send_msg(self, message):
        self.notify_all(message)
