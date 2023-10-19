---
layout: post
title: Dreamhack | web-HTTP-CLI
subtitle: web-HTTP-CLI 문제 풀이
categories: Web
tags: [dreamhack, Pentest, Web]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/931888c1-928f-4fc4-9213-794fd0f7a227" width = 850>
</p>

### 문제 풀이

```python
def get_host_port(url):
    return url.split('://')[1].split('/')[0].lower().split(':')


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('', 8000))
    s.listen()

    while True:
        try:
            cs, ca = s.accept()
            cs.sendall('[Input Example]\n'.encode())
            cs.sendall('> https://dreamhack.io:443/\n'.encode())
        except:
            continue
        while True:
            cs.sendall('> '.encode())
            url = cs.recv(1024).decode().strip()
            print(url)
            if len(url) == 0:
                break
            try:
                (host, port) = get_host_port(url)
                if 'localhost' == host:
                    cs.sendall('cant use localhost\n'.encode())
                    continue
                if 'dreamhack.io' != host:
                    if '.' in host:
                        cs.sendall('cant use .\n'.encode())
                        continue
                cs.sendall('result: '.encode() + urllib.request.urlopen(url).read())
            except:
                cs.sendall('error\n'.encode())
        cs.close()
```

```python
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('', 8000))
    s.listen()
```

현재 소켓 통신을 진행하며 **8000**번 포트를 이용하여 서비스가 이루어지는 것을 알 수 있다.

```python
try:
    (host, port) = get_host_port(url)
    if 'localhost' == host:
        cs.sendall('cant use localhost\n'.encode())
        continue
    if 'dreamhack.io' != host:
        if '.' in host:
            cs.sendall('cant use .\n'.encode())
            continue
    cs.sendall('result: '.encode() + urllib.request.urlopen(url).read())
except:
    cs.sendall('error\n'.encode())
```

**localhost**에 대한 문자가 url에 포함되는 경우 localhost를 사용할 수 없음을 안내하는 문구를 서버에서 송신하고, **dreamhack.io**가 아닌 URL 사용 시 `.` 문자를 사용할 수 없음을 송신해준다.

소켓 통신을 위한 Client 코드는 [codezaram](https://codezaram.tistory.com/31)을 참고했습니다.

```python
## CLIENT ##

import socket
from _thread import *

HOST = ''
PORT = 9999

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

def recv_data(client_socket):
    while True:
        data = client_socket.recv(1024)
        print("recive : ", repr(data.decode()))

start_new_thread(recv_data, (client_socket,))
print('>> Connect Server')

while True:
    message = input()
    if message == 'quit':
        close_data = message
        break

    client_socket.send(message.encode())

client_socket.close()
```

이를 이용하여 통신을 진행해보면 아래와 같다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/8fa2bfc5-74c8-4de2-aece-97855d8359cc" width = 750>
</p>

`.` 문자를 사용했기에 통신이 이루어지지 않는다. `flag.txt` 파일은 서버내에 있으므로 localhost 통신을 통해 파일을 **/app/flag.txt** 접근하여 파일을 읽어와야 한다.

<center>

|Expression|Value|
|:--------:|:---:|
|Decimal               | 2130706433 (127.0.0.1)|
|Omission-1            | 127.1 (127.0.0.1)|
|Omission-2            | 192.168.1 (192.168.0.1)|
|Omission & Octal      | 0177.1 (127.0.0.1)|
|Hexademical           | 0x8080808 (8.8.8.8)|
|Octal & Hexademical   | 010.0x0000008.00000010.8 (8.8.8.8)|
|Decimal & Hexademical | 8.0x000000000000000080808 (8.8.8.8)|

</center>

**localhost**와 **.**를 우회하기 위해서는 10진수 표현인 `2130706433`을 이용해야한다.

또한, **http://** URI를 이용하는 것이 아닌 **file://** URI를 이용하여 로컬에서 파일을 찾는 프로토콜을 이용할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/59b67224-265b-46b6-a6ae-30aa68862b59" width = 750>
</p>

필터링 우회와 프로토콜 변경 시에 별도의 에러가 발생하는데 이 에러에 대해 확인하기 위해 별도의 Flask 서버 구축을 통해 테스트를 진행해봤다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/22aa91e7-d15d-4251-a75b-825d6debcc99" width = 750>
</p>

에러가 발생하는 곳은 `request.py`의 1532번째줄 `open_local_file` 함수에서 발생하는 것을 알 수 있다. 어떠한 이유에 의해 발생했는지 확인해보도록 한다.

```python
#--request.py--#

def open_local_file(self, req):
    import email.utils
    import mimetypes
    host = req.host
    filename = req.selector
    localfile = url2pathname(filename)
    try:
        stats = os.stat(localfile)
        size = stats.st_size
        modified = email.utils.formatdate(stats.st_mtime, usegmt=True)
        mtype = mimetypes.guess_type(filename)[0]
        headers = email.message_from_string(
            'Content-type: %s\nContent-length: %d\nLast-modified: %s\n' %
            (mtype or 'text/plain', size, modified))
        if host:
            host, port = _splitport(host)
        if host or \
            (port and _safe_gethostbyname(host) in self.get_names()):
            if host:
                origurl = 'file://' + host + filename
            else:
                origurl = 'file://' + filename
            return addinfourl(open(localfile, 'rb'), headers, origurl)
    except OSError as exp:
        raise URLError(exp)
    raise URLError('file not on local host') # <--- 1532 lines
```

정상 수행을 위해서는 아래의 코드로 넘어가야할 것으로 보인다.

```python
if host:
    host, port = _splitport(host)
if host or \
    (port and _safe_gethostbyname(host) in self.get_names()):
    if host:
        origurl = 'file://' + host + filename
    else:
        origurl = 'file://' + filename
    return addinfourl(open(localfile, 'rb'), headers, origurl)
```

조건문을 확인하면 **host**나 **port**가 없을 경우에만 가능한 것으로 보인다.

**port**를 없애기 위해 `file://2130706433/app/flag.txt`를 보내면 아래와 같이 **port**가 아예 구분되지 않았기에 문제가 에러가 발생한다.

```
Traceback (most recent call last):
  File "c:\Users\usr\Desktop\NSHC\File\test.py", line 32, in <module>
    (host, port) = get_host_port(url)
    ^^^^^^^^^^^^
ValueError: not enough values to unpack (expected 2, got 1)
```

```python
def get_host_port(url):
    return url.split('://')[1].split('/')[0].lower().split(':')
```

문제에서 주어진 코드 중 host와 port를 구분하기 위한 코드이다. 이를 확인해보면 `.split(':')`와 같이 콜론을 통해 구분짓기에 콜론은 반드시 필요하게 된다.

`file://2130706433:/app/flag.txt`로 하게 되면 콜론을 기준으로 값이 없는 것이 아닌 **NULL**로 되어 정상적으로 통신이 되며 플래그를 가져올 수 있게 된다.