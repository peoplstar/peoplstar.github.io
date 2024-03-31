---
layout: post
title: Dreamhack | pathtraversal
subtitle: Dreamhack Path Traversal
categories: dreamhack.io
tags: [Pentest, Web]
---
 
**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/236079480-94583ca3-606b-455b-89aa-2484e0cab190.png"> 
</p>

해당 문제는 `Path Traversal` 취약점을 이용해서 플래그를 획득하는 문제입니다.

접속하기에 앞서 해당 취약점이 무엇인지 알고 들어가겠습니다.

## Path Traversal

`Path traversal(Directory traversal)`은 서비스에서 사용자로부터 받은 입력이 path 형태의 백엔드에서 처리 로직을 가지는 경우, 이를 조작하여 공격자가 원하는 경로로 접근하여 동작을 수행하는 공격기법을 의미합니다.

보통 File을 처리하는 과정에서 가장 많이 발생하며, 파일 이름 등을 사용자로 부터 받는 경우 사용자가 `../` 같은 구문을 통해 상위 디렉토리로 접근하거나 허용된 디렉토리의 범위를 벗어나 시스템 파일 등을 읽을 수 있습니다.

흔히 알고 있는 `File Download`과 같은 방법을 통해 디렉토리에 접근을 하는 방식입니다.

## 문제 풀이

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/236079984-b116e397-fa2e-4cdb-b152-0f9178279349.png" width = 550> 
</p>

`get_info`를 통해 `userID`를 입력하여 View를 하면 해당 계정에 대한 정보가 출력되는 것을 알 수 있다.

제공되는 파일인 `app.py`을 통해 어떠한 로직으로 진행되는지 확인해보겠습니다.

```python
#!/usr/bin/python3
from flask import Flask, request, render_template, abort
from functools import wraps
import requests
import os, json

users = {
    '0': {
        'userid': 'guest',
        'level': 1,
        'password': 'guest'
    },
    '1': {
        'userid': 'admin',
        'level': 9999,
        'password': 'admin'
    }
}

def internal_api(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if request.remote_addr == '127.0.0.1':
            return func(*args, **kwargs)
        else:
            abort(401)
    return decorated_view

app = Flask(__name__)
app.secret_key = os.urandom(32)
API_HOST = 'http://127.0.0.1:8000'

try:
    FLAG = open('./flag.txt', 'r').read() # Flag is here!!
except:
    FLAG = '[**FLAG**]'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_info', methods=['GET', 'POST'])
def get_info():
    if request.method == 'GET':
        return render_template('get_info.html')
    elif request.method == 'POST':
        userid = request.form.get('userid', '')
        info = requests.get(f'{API_HOST}/api/user/{userid}').text
        return render_template('get_info.html', info=info)

@app.route('/api/flag')
@internal_api
def flag():
    return FLAG
```

유저는 `guest, admin` 두 개가 존재하고 내부에서 작동하며 HOST가 Local때만 작동하는 `internal_api` 함수가 보이며, 우리가 이용하고 있는 `get_info`가 보인다.

`get_info`를 보게 되면 우리가 입력한 값이 `API_HOST/api/user/{userID}`에 들어가는 것을 알 수 있는데 URL에 직접 연결시켜주는 것을 알 수 있다.

플래그는 `/api/flag`에 있다고 했으므로 `API_HOST/api/flag`와 같이 맞춰주면 된다.

상위 디렉토리로 이동하기 위한 `../`를 붙여준다면 쉽게 이동이 가능합니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/236082366-895de829-cc0c-465f-b401-303bc30548f0.png" width = 550> 
</p>

하지만 아무것도 나오지 않게 되는데 `Burp Suite`를 이용해서 다시 확인해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/236082707-bca3bfbe-4559-411c-8669-00781c395103.png" width = 550> 
</p>

우리가 원하는 **userid**가 `undefined`로 바뀌어 있는 것을 볼 수 있는데 이를 다시 `../flag`로 변경하고 넘기게 된다면 우리가 원하는 **FLAG**가 나오는 것을 확인할 수 있습니다.