---
layout: post
title: Dreamhack | Simple SQLi
subtitle: Dreamhack simple_sqli
categories: dreamhack.io
tags: [Pentest, Web]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://dreamhack.io/wargame/challenges/">dreamhack.io</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/208605718-77ffddc3-a6ea-4ab3-84a9-21d9c1206116.png" width = 500> 
</p>

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/208605599-5862ad3a-cfdc-4969-b757-d015742bcf71.png" width = 400> 
</p>

접속 시 로그인 페이지 하나와 **About, Contact** Fragment가 존재한다.

로그인 서비스를 통해 SQLi를 하여 FLAG를 가져오면 될 것으로 보인다.

## 문제 풀이

```python
#!/usr/bin/python3
from flask import Flask, request, render_template, g
import sqlite3
import os
import binascii

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

DATABASE = "database.db"
if os.path.exists(DATABASE) == False:
    db = sqlite3.connect(DATABASE)
    db.execute('create table users(userid char(100), userpassword char(100));')
    db.execute(f'insert into users(userid, userpassword) values ("guest", "guest"), ("admin", "{binascii.hexlify(os.urandom(16)).decode("utf8")}");')
    db.commit()
    db.close()
```

로그인에 대한 계정은 **guest, guest**와 **admin, random_password** 두 쌍이 존재한다.

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        userid = request.form.get('userid')
        userpassword = request.form.get('userpassword')
        res = query_db(f'select * from users where userid="{userid}" and userpassword="{userpassword}"')
        if res:
            userid = res[0]
            if userid == 'admin':
                return f'hello {userid} flag is {FLAG}'
            return f'<script>alert("hello {userid}");history.go(-1);</script>'
        return '<script>alert("wrong");history.go(-1);</script>'

app.run(host='0.0.0.0', port=8000)
```

**guest, guest**로 접속하게 되면 **hello guest** Alert만 나오고 다른 작업은 없는 것으로 보인다. 

**admin** 접속 시 FLAG가 무엇인지 출력해준다.

```sql
select * from users where userid="userid" and userpassword="userpassword"
```

해당 구문을 통해 **admin**의 비밀번호를 직접 구해서 들어갈 수도, `OR` 연산과 주석처리로 우회가 가능할 것으로 보인다.

```python
if userid == 'admin':
    return f'hello {userid} flag is {FLAG}'
```

이를 통해 userid의 값이 **admin**이기만 하면 되므로 아래와 같은 형식으로 우회하며 Query를 통과하겠습니다.

```sql
SELECT * FROM users WHERE userid = "admin" -- and userpassword="userpassword"
```

이후의 쿼리를 주석처리하여 테이블에 존재하는 admin으로 접근하면 해결이 된다.