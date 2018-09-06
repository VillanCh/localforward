#!/usr/bin/env python3
# coding:utf-8
import socket
import select
from .base import SessionBase


class RawSession(SessionBase):

    def on_connect(self):
        """"""
        pass

    def handle(self):
        """"""
        remote_host, remote_port = self.options['remote_addr']

        new_sock = socket.socket()
        new_sock.settimeout(self.options.get("timeout", 10))
        new_sock.connect((remote_host, remote_port))

        events = [
            select.kevent(self.conn.fileno(), select.KQ_FILTER_READ),
            select.kevent(new_sock.fileno(), select.KQ_FILTER_READ)
        ]
        kq = select.kqueue()

        should_close = False
        while True:
            if should_close == True:
                break

            for _es in kq.control(events, 2, 1):
                if _es.ident == self.conn.fileno():
                    buff = b""
                    while True:
                        try:
                            data = self.conn.recv(1024)
                        except BlockingIOError:
                            break

                        if not data:
                            should_close = True
                            break
                        else:
                            buff += data
                        break
                    if buff:
                        print(buff)
                        new_sock.sendall(buff)
                elif _es.ident == new_sock.fileno():
                    buff = b""
                    while True:
                        try:
                            data = new_sock.recv(1024)
                        except:
                            break

                        if not data:
                            should_close = True
                            break
                        else:
                            buff += data
                    if buff:
                        print(buff)

                        self.conn.sendall(buff)

        self.conn.close()
        new_sock.close()

