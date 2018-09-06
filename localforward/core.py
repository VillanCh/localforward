#!/usr/bin/env python3
# coding:utf-8
import socket
import threading
import traceback
from select import kqueue, kevent, KQ_FILTER_READ
from . import sessions

from . import pool

FORWORD_TYPE_RAW = 'raw'
FORWORD_TYPE_SOCKS5 = 'socks5'

_SessionCls = {
    FORWORD_TYPE_RAW: sessions.RawSession,
    FORWORD_TYPE_SOCKS5: sessions.Sock5Session,
}


class SessionPool(object):

    def __init__(self, backend=FORWORD_TYPE_RAW, size=20, options={}):
        self.size = size
        self._session_list = []
        self._session_kls = _SessionCls[backend]
        self.options = options

        self.pool = pool.Pool(size=20)
        self.pool.start()

    def new_session(self, conn: socket.socket, addr: tuple):
        """"""
        session = self._session_kls(conn, addr, self.options)
        self.pool.execute(session.handle)


class ForwordServer(object):

    def __init__(self, host="127.0.0.1", port: int = 8010, type=FORWORD_TYPE_RAW, size=20, options={}):
        self.host = host
        self.port = port

        self.size = size

        self._sock_listener = None
        self._kq = kqueue()
        self.is_working = threading.Event()

        self.session_pool = SessionPool(backend=type, options=options)

    def serve(self, detach=False):
        """"""
        self._init_listener()
        try:
            self._serve_forever()
        except:
            traceback.print_exc()
        finally:
            self._sock_listener.close()

    def _init_listener(self):
        """"""
        self._sock_listener = socket.socket()
        self._sock_listener.bind((self.host, self.port))
        self._sock_listener.listen(self.size)

    def _serve_forever(self):
        """"""
        events = [
            kevent(self._sock_listener.fileno(), KQ_FILTER_READ)
        ]
        self.is_working.set()
        while self.is_working.is_set():
            for event in self._kq.control(events, 1, 1):
                #assert isinstance(event, kevent)
                if event.ident == self._sock_listener.fileno():
                    new_conn, addr = self._sock_listener.accept()
                    self.session_pool.new_session(new_conn, addr)


if __name__ == "__main__":
    ForwordServer().serve()
