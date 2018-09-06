#!/usr/bin/env python3
# coding:utf-8
import socket


class SessionBase:

    def __init__(self, conn: socket.socket, addr, options):
        self.conn = conn
        self.addr = addr
        self.options = options

        self.on_connect()

    def on_connect(self):
        """"""
        pass

    def handle(self):
        """"""
        pass
