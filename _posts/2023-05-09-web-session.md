---
layout: post
title: Dreamhack | session
subtitle: Dreamhack session
categories: Web
tags: [Pentest, Web]
---
 
**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/236111751-1fe98067-026c-4b83-968d-e9cee8a54e52.png"> 
</p>

쿠키와 세션을 통해서 `admin` 계정으로 로그인에 성공하면 플래그를 획득한다는 것으로 보았을 때 세션쿠키값을 변조하여 **admin**으로 로그인하면 될 것으로 예상한다.

## 문제 풀이

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/236111894-7f118bb0-4739-449c-8353-ab656601fce8.png" width = 45%> 
</p>

로그인할 수 있는 화면이 Form이 존재하며 해당 계정은 아래처럼 두 개가 존재합니다.

```python
users = {
    'guest': 'guest',
    'user': 'user1234',
    'admin': FLAG
}
```

**guest** 계정으로 로그인하게 되면 `Hello guest, you are not admin`의 문구가 나오게 되며 세션 쿠키 값은 `984c0a86`로 나오게 된다.

**user** 계정으로 로그인할 경우에도 마찬가지로 위 문구가 나오며 세션 쿠키 값은 `67f6fbe0`로 나오는데 이것만 봤을 때는 세션 쿠키의 길이가 8글자로 제한되어있고 **Hex**로 이루어진거처럼 느껴진다.

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            pw = users[username]
        except:
            return '<script>alert("not found user");history.go(-1);</script>'
        if pw == password:
            resp = make_response(redirect(url_for('index')) )
            session_id = os.urandom(4).hex()
            session_storage[session_id] = username
            resp.set_cookie('sessionid', session_id)
            return resp 
        return '<script>alert("wrong password");history.go(-1);</script>'

if __name__ == '__main__':
    import os
    session_storage[os.urandom(1).hex()] = 'admin'
    print(session_storage)
    app.run(host='0.0.0.0', port=8000)
```

`/login`을 보게 되면 `session_id`는 4글자의 랜덤함수를 `hex`로 init하는 것을 볼 수 있고 결국 맨 처음에 로그인하면서 세션값을 보여 유추한게 정확한 것을 알 수 있습니다.

`main` 함수를 보면 `admin` 계정의 세션은 한 글자의 헥스 값(총 2글자)으로 이루어진 것을 알 수 있는데 0~9, A~F까지 모든 조합을 다 일일이 Brute Force 하기에는 불필요한 시간이 소요되기에 `Burp Suite Intruder`를 이용하겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/236113128-d6bdd145-93ad-458d-830f-6b4bdd7ad80e.png"> 
</p>

로그인 이후 새로고침해서 해당 세션을 보면 총 8글자로 되어있습니다.

새로고침때 프록시로 잡은 부분을 `Intruder`로 보내어 `Brute Force` Payload Type 변경 후 Hex Character Set **0123456789abcdef**로 하며 총 글자수는 2글자이므로 Min, Max를 모두 2로 변경하여 던지면 아래처럼 옳은 값일 때의 Response Length가 다른 것을 알 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/236113776-e2274bbd-7e8e-4233-9ff4-daff64b3ad34.png" width = 80%> 
</p>

해당 세션을 이용하여 접속을 하게 되면 플래그가 나오는 것을 확인할 수 있습니다.