#!/usr/bin/env python3
# coding:utf-8
import select
import threading
import traceback
import socket
import ipaddress
import struct

import logging

logging.basicConfig()

logger = logging.getLogger("sock5")
logger.setLevel(logging.INFO)

'''
The SOCKS request is formed as follows:
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
    Where:
        o  VER    protocol version: X'05'
        o  CMD
            o  CONNECT X'01'
            o  BIND X'02'
            o  UDP ASSOCIATE X'03'
        o  RSV    RESERVED
        o  ATYP   address type of following address
            o  IP V4 address: X'01'
            o  DOMAINNAME: X'03'
            o  IP V6 address: X'04'
        o  DST.ADDR       desired destination address
        o  DST.PORT desired destination port in network octet
            order
'''

VER = 5

CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP = 3
CMD_TABLE = {
    CMD_CONNECT: "CONNECT",
    CMD_BIND: "BIND",
    CMD_UDP: "UDP"
}

ATYP_IPV4 = 1
ATYP_DDMAIN = 3
ATYP_IPv6 = 4


class Sock5Request(object):
    """"""

    def __init__(self, cmd, atyp, host, port, ipraw=b''):
        """Constructor"""
        self.cmd = cmd
        self.atyp = atyp
        self.host = host
        self.port = port
        self.ipraw = ipraw

    @classmethod
    def from_sock(cls, sock):
        # ver
        ver = sock.recv(1)
        cmd = ord(sock.recv(1))
        _ = sock.recv(1)

        ipraw = b''
        atyp = ord(sock.recv(1))
        if atyp == ATYP_DDMAIN:
            _dl = ord(sock.recv(1))
            addr = sock.recv(_dl)
        elif atyp == ATYP_IPV4:
            ipraw = sock.recv(4)
            addr = ipaddress.IPv4Address(ipraw)
        elif atyp == ATYP_IPv6:
            raise NotImplementedError("IPv6 is not supported.")
        else:
            raise NotImplementedError("No Defination: {}".format(atyp))

        port = struct.unpack('!h', sock.recv(2))[0]
        return cls(cmd, atyp, addr, port, ipraw)

    def __repr__(self):
        return "<sock5-req: {} to {}:{}>".format(
            CMD_TABLE[self.cmd], self.host, self.port
        )


'''
6.  Replies
   The SOCKS request information is sent by the client as soon as it has
   established a connection to the SOCKS server, and completed the
   authentication negotiations.  The server evaluates the request, and
   returns a reply formed as follows:
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
     Where:
          o  VER    protocol version: X'05'
          o  REP    Reply field:
             o  X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
          o  RSV    RESERVED
          o  ATYP   address type of following address
Leech, et al                Standards Track                     [Page 5]
RFC 1928                SOCKS Protocol Version 5              March 1996
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  BND.ADDR       server bound address
          o  BND.PORT       server bound port in network octet order
   Fields marked RESERVED (RSV) must be set to X'00'.
   If the chosen method includes encapsulation for purposes of
   authentication, integrity and/or confidentiality, the replies are
   encapsulated in the method-dependent encapsulation.
'''

REP_SUCCEEDED = 0
REP_S5ERR = 1
REP_FORBIDDEN = 2
REP_NETWORK_UNREACHABLE = 3
REP_HOST_UNREACHABLE = 4
REP_CONNECTION_REFUSED = 5
REP_TTL_EXPIRED = 6
REP_COMMAND_NOT_SUPPORTED = 7
REP_ADDRESS_TYPE_NOT_SUPPORTED = 8


class Sock5Response(object):
    """"""

    @classmethod
    def succeeded(self, bnd_addr, bnd_port):
        """"""
        return b"\x05\x00\x00\x01" + bnd_addr + bnd_port


class Sock5Session(object):
    """"""

    def __init__(self, conn):
        """Constructor"""
        self.conn = conn
        ver = conn.recv(1)
        nmethods = conn.recv(1)
        how_many_methods = ord(nmethods)
        methods = conn.recv(how_many_methods)

        if b"\x00" in methods:
            conn.send(b"\x05\x00")
        else:
            raise NotImplementedError()

    def _handle_connect(self, req):
        new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_sock.settimeout(10)
        new_sock.connect((req.host.compressed, req.port))
        _ip, port = new_sock.getpeername()
        _ipraw = ipaddress.IPv4Address(_ip).packed
        _portraw = struct.pack("!h", port)

        rsp = Sock5Response.succeeded(
            _ipraw, _portraw
        )
        self.conn.send(rsp)

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

        print("finished transport")
        self.conn.close()
        new_sock.close()

    def handle(self):
        req = Sock5Request.from_sock(self.conn)
        if req.cmd == CMD_CONNECT:
            self._handle_connect(req)


class Sock5Server(object):
    """"""

    def __init__(self, host='127.0.0.1', port=12342):
        """Constructor"""
        self.host = host
        self.port = port
        self.addr = (host, port)
        self._is_working = threading.Event()

    def _new_tcp_socket(self):
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def serve_forever(self):
        try:
            self._serve_forever()
        except:
            traceback.print_exc()
            self._listenner.close()

    def _serve_forever(self):
        self._is_working.set()

        logger.info("Build Listener Socket")
        self._listenner = self._new_tcp_socket()
        self._listenner.bind(self.addr)
        self._listenner.listen()

        kq = select.kqueue()
        sockevent = [
            select.kevent(
                self._listenner.fileno(), select.KQ_FILTER_READ, select.KQ_EV_ADD,
            )
        ]

        while self._is_working.is_set():
            for evenitem in kq.control(sockevent, 1, 1):
                if evenitem.ident == self._listenner.fileno():
                    new_sock, addr = self._listenner.accept()
                    try:
                        self._valid_socks5_proto(new_sock, addr)
                    except Exception as e:
                        traceback.print_exc()
                        raise e
                    finally:
                        new_sock.close()

    def _valid_socks5_proto(self, conn, addr):
        Sock5Session(conn).handle()


if __name__ == "__main__":
    Sock5Server().serve_forever()
