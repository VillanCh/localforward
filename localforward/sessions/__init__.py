#!/usr/bin/env python3
# coding:utf-8
import socket


from .s5 import Sock5Session
from .raw import RawSession

__all__ = [
    "Sock5Session", "RawSession"
]


class SessionBase:

    def __init__(self, conn: socket.socket, addr, options):
        self.conn = conn
        self.addr = addr
        self.options = options

    def on_connect(self):
        """"""
        pass

    def handle(self):
        """"""
        pass


