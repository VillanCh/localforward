# LocalForward

 本地转发/代理模块

- [x] Socks5 无密码 CONNECT 协议
- [ ] 透明端口转发

```bash

usage: localforward -h -l HOST -rp RPORT --size SIZE

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  the port will be listened.
  -l HOST, --listen-host HOST
                        which host is listened.
  -rh RHOST, --remote-host RHOST
                        which host is forward to.
  -rp RPORT, --remote_port RPORT
                        the port of remote host.
  --timeout TIMEOUT     timeout for each connection.
  --size SIZE           how many connections will be accepted same time.
  --type TYPE           what type of forward.

```

