---
layout: post
title: Webhacking.kr | Level 11
subtitle: Webhacking CTF Problem Solving
categories: webhacking.kr
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/188301327-e7f1b8f6-08df-409a-8302-c184ed61d235.jpg" width = 340> 
</p>

첫 화면에는 **Wrong**과 **view-source**밖에 보이질 않아 view-source로 넘어갔다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/188301386-ee6cea8d-90e7-472c-b22c-295b09284125.jpg" width = 340> 
</p>

DB 연결코드도 없고 매우 단순하기에 바로 소스코드 분석을 진행하면서 풀이를 해보겠습니다!

## 문제 풀이

```php
<?php
  $pat="/[1-3][a-f]{5}_.*$_SERVER[REMOTE_ADDR].*\tp\ta\ts\ts/";
  if(preg_match($pat,$_GET['val'])){
    solve(11);
  }
  else echo("<h2>Wrong</h2>");
  echo("<br><br>");
?>
```

**$pat**은 정규표현식으로 이루어진 변수이며, GET 메소드로 전달되는 변수 val의 값이 정규표현식인 **$pat**과 같으면 해결된다.

그렇다면 정규표현식으로 이루어진 $pat이 어떤 값을 가지는지 확인해보겠습니다.

* **[1-3]** : 1부터 3 사이의 한 글자
* **[a-f]** : a부터 f 사이의 한 글자
* **_** : 일반 `_` 문자
* **.** : 개행 (\n) 문자를 제외한 아무 문자
   * `.`는 a, b, c, 1, 2, 3 ... 등 아무 문자로 치환이 된다는 것
* __*__ : 앞 문자를 0번 이상 반복
   *  /a*b/의 경우 :  b, ab, aab, aaab, ...
* **$_SERVER[REMOTE_ADDR]** : 웹 서버에 접속한 접속자의 IP 정보
* **\t** : `TAB` (%09)

따라서, $pat은 [1-3]에 해당되는 **_1_**, [a-f]{5}에 해당되는 **_aaaaa_**, __.*__ 는 아무 문자를 하나 대입하고 0번 이상이므로 입력을 하지 않아도 된다.

일반 문자 **_\__**, **\$_SERVER[REMOTE_ADDR]** 는 각자 자신의 **_IP_**, **\t**은 **_%09 _**와 이후 문자는 p, a, s, s를 대입하면 된다

즉, **$pat = 1aaaaa_{Your IP}%09p%09a%09s%09s**가 된다. 이 값을 GET 메소드로 전달하는 val가 되어야 하므로 아래처럼 하면 해결된다!

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/188302222-f7fdd957-a292-4af6-bede-717cffb35f98.jpg" width = 400> 
</p>

하지만, `ipconfig` 명령어로 나오는 IP가 아닌 공인 IP주소를 입력해야 풀린다. 그렇다는 것은 `$_SERVER[REMOTE_ADDR]`는 웹 사용자의 공인 IP주소를 가져오는 것을 알 수 있다.

이번 문제는 PHP 정규 표현식을 이해하고 앞으로도 사용될 정규 표현식에 대해서 확실히 정리를 할 수 있는 문제였다.