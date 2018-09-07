#!/usr/bin/env python3
# coding:utf-8
import socket
import threading
import traceback
from select import kqueue, kevent, KQ_FILTER_READ
from . import sessions
from . import outils
from . import pool

FORWORD_TYPE_RAW = 'raw'
FORWORD_TYPE_SOCKS5 = 'socks5'

_SessionCls = {
    # FORWORD_TYPE_RAW: sessions.RawSession,
    FORWORD_TYPE_SOCKS5: sessions.Sock5Session,
}

logger = outils.get_logger('localforward')


class SessionPool(object):

    def __init__(self, backend=FORWORD_TYPE_SOCKS5, size=20, options={}):
        self.size = size
        self._session_list = []
        self._session_kls = _SessionCls[backend]
        self.options = options
        self.backend = backend

        self.pool = pool.Pool(size=20)
        self.pool.start()

    def new_session(self, conn: socket.socket, addr: tuple):
        """"""
        logger.info("prepare to start session: {}".format(self.backend))
        self.pool.execute(self.start_session, (conn, addr))

    def start_session(self, conn, addr):
        """"""
        logger.info("session from: {} is started".format(addr))
        try:
            conn.settimeout(self.options.get("timeout", 10))
            session = self._session_kls(conn, addr, self.options)
            session.handle()
        except Exception:
            msg = traceback.format_exc()
            logger.warn("session from: {} met error: {}".format(
                addr, msg
            ))
        finally:
            conn.close()
            logger.info("session from: {} is finished".format(addr))

    def set_data_send_hook(self, callback):
        self.options['data_send'] = callback

    def set_data_recv_hook(self, callback):
        self.options['data_recv'] = callback


class ForwordServer(object):

    def __init__(self, host="127.0.0.1", port: int = 8010, type=FORWORD_TYPE_SOCKS5, size=20, options={}):
        self.host = host
        self.port = port

        self.size = size

        self._sock_listener = None
        self._kq = kqueue()
        self.is_working = threading.Event()

        self.session_pool = SessionPool(backend=type, options=options)

    def set_data_send_hook(self, callback):
        self.session_pool.set_data_send_hook(callback)

    def set_data_recv_hook(self, callback):
        self.session_pool.set_data_recv_hook(callback)

    def serve(self, detach=False):
        """"""
        logger.info("prepare to initialize listener")
        self._init_listener()

        try:
            self._serve_forever()
        except:
            msg = traceback.format_exc()
            logger.error("error in ForwardServer: {}".format(msg))
        finally:
            self._sock_listener.close()

    def _init_listener(self):
        """"""
        self._sock_listener = socket.socket()
        self._sock_listener.bind((self.host, self.port))
        self._sock_listener.listen(self.size)
        logger.info("listen on {}:{} with backlog:{}".format(
            self.host, self.port, self.size))

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
                    logger.info(
                        "accept connection from {}:{}".format(addr[0], addr[1]))
                    self.session_pool.new_session(new_conn, addr)

    def start(self):
        """"""
        rh = threading.Thread(target=self.serve)
        rh.daemon = True
        rh.start()

        return {
            "http": "socks5://{}:{}".format(self.host, self.port),
            "https": "socks5://{}:{}".format(self.host, self.port),
        }


if __name__ == "__main__":
    ForwordServer().serve()
