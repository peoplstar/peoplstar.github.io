---
layout: post
title: Webhacking.kr | Level 6
subtitle: Webhacking CTF Problem Solving
categories: webhacking.kr
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186076077-5af0534f-8c4d-40b3-92b8-d48e4084698d.jpg" width = 320>
</p>

아이디와 패스워드가 무엇인지 말해주고 소스볼 수 있는 곳이 나온다.

소스를 보면 다음과 같다.

```php
if(!$_COOKIE['user']){
  $val_id="guest";
  $val_pw="123qwe";
  for($i=0;$i<20;$i++){
    $val_id=base64_encode($val_id);
    $val_pw=base64_encode($val_pw);
  }
  $val_id=str_replace("1","!",$val_id);
  $val_id=str_replace("2","@",$val_id);
  $val_id=str_replace("3","$",$val_id);
  $val_id=str_replace("4","^",$val_id);
  $val_id=str_replace("5","&",$val_id);
  $val_id=str_replace("6","*",$val_id);
  $val_id=str_replace("7","(",$val_id);
  $val_id=str_replace("8",")",$val_id);

  $val_pw=str_replace("1","!",$val_pw);
  $val_pw=str_replace("2","@",$val_pw);
  $val_pw=str_replace("3","$",$val_pw);
  $val_pw=str_replace("4","^",$val_pw);
  $val_pw=str_replace("5","&",$val_pw);
  $val_pw=str_replace("6","*",$val_pw);
  $val_pw=str_replace("7","(",$val_pw);
  $val_pw=str_replace("8",")",$val_pw);

  Setcookie("user",$val_id,time()+86400,"/challenge/web-06/");
  Setcookie("password",$val_pw,time()+86400,"/challenge/web-06/");
  echo("<meta http-equiv=refresh content=0>");
  exit;
}
```
```php
$decode_id=$_COOKIE['user'];
$decode_pw=$_COOKIE['password'];

$decode_id=str_replace("!","1",$decode_id);
$decode_id=str_replace("@","2",$decode_id);
$decode_id=str_replace("$","3",$decode_id);
$decode_id=str_replace("^","4",$decode_id);
$decode_id=str_replace("&","5",$decode_id);
$decode_id=str_replace("*","6",$decode_id);
$decode_id=str_replace("(","7",$decode_id);
$decode_id=str_replace(")","8",$decode_id);

$decode_pw=str_replace("!","1",$decode_pw);
$decode_pw=str_replace("@","2",$decode_pw);
$decode_pw=str_replace("$","3",$decode_pw);
$decode_pw=str_replace("^","4",$decode_pw);
$decode_pw=str_replace("&","5",$decode_pw);
$decode_pw=str_replace("*","6",$decode_pw);
$decode_pw=str_replace("(","7",$decode_pw);
$decode_pw=str_replace(")","8",$decode_pw);

for($i=0;$i<20;$i++){
  $decode_id=base64_decode($decode_id);
  $decode_pw=base64_decode($decode_pw);
}

echo("<hr><a href=./?view_source=1 style=color:yellow;>view-source</a><br><br>");
echo("ID : $decode_id<br>PW : $decode_pw<hr>");

if($decode_id=="admin" && $decode_pw=="nimda"){
  solve(6);
}
```

쿠키의 user와 password가 base64로 디코딩하며 replace를 20번하여 나온 값이 admin과 nimda이면 된다는 해결된다는 것으로 보인다. 

## 문제 풀이

이 문제는 웹 해킹이 아니라 그냥 코딩으로 base64 인코딩, 디코딩을 할 수 있냐고 물어보는것과 같다.

너무 간단하기도 하고 웹 해킹 문제가 아닌거 같다...

```python
import base64

def replace_encode(str):
    str = str.replace("1", "!")
    str = str.replace("2", "@")
    str = str.replace("3", "$")
    str = str.replace("4", "^")
    str = str.replace("5", "&")
    str = str.replace("6", "*")
    str = str.replace("7", "(")
    str = str.replace("8", ")")
    return str

def replace_decode(str):
    str = str.replace("!", "1")
    str = str.replace("@", "2")
    str = str.replace("$", "3")
    str = str.replace("^", "4")
    str = str.replace("&", "5")
    str = str.replace("*", "6")
    str = str.replace("(", "7")
    str = str.replace(")", "8")
    return str

def account_encode(account):
    account = account.encode('utf-8')

    for i in range(20):
        account = base64.b64encode(account)

    account = account.decode('utf-8')
    account = replace_encode(account)
    return account

def account_decode(account):
    account = replace_decode(account)
    account = account.encode('utf-8')

    for i in range(20):
        account = base64.b64decode(account)

    account = account.decode('utf-8')
    return account

ID = "admin"
PW = "nimda"

id_encode = account_encode(ID)
pw_encode = account_encode(PW)
id_decode = account_decode(id_encode)
pw_decode = account_decode(pw_encode)
print('-------------------------[ID Encode]--------------------------')
print(id_encode)
print('-------------------------[ID Decode]--------------------------')
print(id_decode)
print('------------------------[PW Encode]---------------------------')
print(pw_encode)
print('------------------------[PW Decode]---------------------------')
print(pw_decode)
```

[스크립트 링크](https://github.com/peoplstar/peoplstar.github.io/blob/main/assets/python/Webhacking_6_Base64.py)도 같이 올려드리겠습니다!

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186088980-04523795-9b16-4288-acb2-439df212a9cb.jpg" width = 320>
</p>

쿠키로 저희가 인코딩한 값을 넣고 새로고침하면 이렇게 풀리는 것을 알 수 있습니다!