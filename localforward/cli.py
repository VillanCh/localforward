#!/usr/bin/env python3
# coding:utf-8
import argparse

import logging
from .core import ForwordServer

from .outils import get_logger


logger = get_logger("localforward")


def cli():
    """"""
    logger.setLevel(logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=8010,
                        help="the port will be listened.")
    parser.add_argument("-l", "--listen-host", type=str, default="127.0.0.1", dest="host",
                        help="which host is listened.")

    parser.add_argument("-rh", "--remote-host", type=str, dest="rhost",
                        help="which host is forward to.")
    parser.add_argument("-rp", "--remote_port", type=int, dest="rport",
                        help="the port of remote host.")
    parser.add_argument('--timeout', type=int, default=30,
                        help='timeout for each connection.')
    parser.add_argument("--size", type=int, default=20,
                        help="how many connections will be accepted same time.")
    parser.add_argument("--type", type=str, default="socks5",
                        help="what type of forward.")

    cmd_options = parser.parse_args()

    options = {
        "timeout": cmd_options.timeout,
        "remote_host": cmd_options.rhost,
        "remote_port": cmd_options.rport,
        "remote_addr": (cmd_options.rhost, cmd_options.rport),
    }

    ForwordServer(host=cmd_options.host, port=cmd_options.port,
                  size=cmd_options.size, type=cmd_options.type,
                  options=options).serve()
