---
layout: post
title: Dreamhack | blind-command
subtitle: Dreamhack Blind Command
categories: dreamhack.io
tags: [Pentest, Web]
---
 
**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/216917179-fe3a3cc7-ef02-457c-806f-2fa2d0b733b5.png" width = 500> 
</p>

해당 문제에 대해서는 단순히 FLAG 파일을 읽으라는 내용만 존재한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/216917317-dd431bc4-f0db-4d26-9ac0-a5b92f2bf598.png" width = 500> 
</p>

접속 시 `?cmd=[cmd]`의 문자만 출력하고 있다. `cmd`라는 변수를 이용해서 GET 메소드로 입력 값을 받는 것처럼 보이기에 시도하면 아래와 같이 그대로 다시 출력한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/216917536-5fcd65fa-8b64-41da-8845-8ed5ee590626.png" width = 500> 
</p>

자세한 내용을 위해 제공하는 파일을 읽어볼 필요가 있다.

## 문제 풀이

```python
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/' , methods=['GET'])
def index():
    cmd = request.args.get('cmd', '')
    if not cmd:
        return "?cmd=[cmd]"

    if request.method == 'GET':
        ''
    else:
        os.system(cmd)
    return cmd

app.run(host='0.0.0.0', port=8000)
```

입력 값을 받는 GET 메소드의 변수는 `cmd`이며 입력 값이 없는 경우 `?cmd=[cmd]`를 출력한다. **requset**의 메소드가 GET 메소드면 어떠한 행위조차 하지 않고, 다른 메소드인 경우 `os.system(cmd)`를 실행하며 return해준다.

GET 메소드로만 받지만, GET 메소드가 아니여야 `system` 실행이 가능하다?

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/216934002-09c26273-5372-415e-9a3d-a9bbcaeb9afe.png" width = 500> 
</p>

Burp Suite로 잡고 GET 메소드를 OPTIONS 메소드로 변경하면 허용중인 메소드의 종류가 나온다.

* **HEAD 메소드** : HEAD 요청 방식은 GET과 유사한 방식이나 웹 서버에서 헤더 정보 이외에는 어떤 데이터도 보내지 않는다. 웹 서버의 다운 여부 점검(Health Check)이나 웹 서버 정보(버전 등)등을 얻기 위해 사용될 수 있다.

즉, **HEAD**를 사용하면 GET의 방식과 유사하기에 `os.system(cmd)` 부분을 실행시킬 수 있다.

하지만, **HEAD**를 사용할 경우 Body를 제외한 Header의 정보만 넘어오기에 **웹훅**이라는 것을 이용하여 값을 받아오도록 하겠습니다.

### 웹 훅

웹 훅은 웹 페이지 혹은 웹 앱에서 발생하는 특정 행동(이벤트)들을 커스텀 Callback으로 변환해주는 방법으로 이러한 행동 정보들을 실시간으로 제공하는데 사용됩니다.

보통 REST API로 구축된 웹 서비스는 하나의 요청에 따라 하나의 응답을 제공합니다. 이러한 구조로 인해 특정 이벤트가 발생했는지 조회하려면 서버로의 요청이 선행되어야 합니다.

즉, **HEAD** 메소드로 이용하였을 때 Body에 포함되지 않는 정보들은 실시간으로 보기 위해 사용하려 합니다.

[requsetbin](https://requestbin.com/)이라는 웹 훅을 이용하도록 하겠습니다.

접속 후 **Create Request Bin** > **Source** > **Create One** > **HTTP / Webhook** 순서대로 하여 Request bin을 하나 만듭니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/216938655-61aed4e4-f409-42b8-907d-5b10bfb1c7b7.png" width = 500> 
</p>

이렇게 이벤트 목적인 엔드포인트에 대한 URL이 생성된다.

`curl` 명령어를 통해서 엔드포인트에 데이터를 전송할 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/216945033-47c064b2-9aeb-41d7-843f-4538b26ef63c.png" width = 500> 
</p>

**GET**과 비슷한 방식으로 사용되는 **HEAD** 메소드를 이용해 `curl` 명령어를 전송하면 응답 헤더가 200 코드를 보내게 되고, 웹 훅을 확인해보면

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/216945189-1c20e46d-1082-4809-8690-e8b0e7ca0d83.png" width = 350> 
</p>

`ls` 명령어에 대한 이벤트 값이 `app.py, flag.py, requirements.txt`가 있는 것을 알 수 있고 `flag.py`를 `cat`으로 읽어보면 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/216946006-55f1f0c8-fe21-413e-a4e3-6543a37da4c5.png" width = 500> 
</p>


## 참고

* [춤추는 개발자](https://frtt0608.tistory.com/143)

* [안전제일](https://jdh5202.tistory.com/807)