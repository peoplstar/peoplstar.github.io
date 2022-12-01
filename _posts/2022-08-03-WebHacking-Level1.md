---
layout: post
title: Webhacking.kr | Level 1
subtitle: Webhacking CTF Problem Solving
categories: Webhacking.kr
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182548577-b19b5875-6121-401e-9803-5056aee1608d.png" width = 350>
</p>

처음 화면은 이 처럼 아무것도 없다. 따라서 view_source를 통해 해당 문제 내용을 알아본다.


## 문제 풀이

```php
<?php
  include "../../config.php";
  if($_GET['view-source'] == 1){ view_source(); }
  if(!$_COOKIE['user_lv']){
    SetCookie("user_lv","1",time()+86400*30,"/challenge/web-01/");
    echo("<meta http-equiv=refresh content=0>");
  }
?>
```

* `user_lv`이 없다면 시간에 대한 값으로 쿠키 값을 설정한다.

```php
<?php
  if(!is_numeric($_COOKIE['user_lv'])) $_COOKIE['user_lv']=1;
  if($_COOKIE['user_lv']>=4) $_COOKIE['user_lv']=1;
  if($_COOKIE['user_lv']>3) solve(1);
  echo "<br>level : {$_COOKIE['user_lv']}";
?>
<br>
<a href=./?view-source=1>view-source</a>
</body>
</html>
```

* user_lv에 대한 쿠키 값을 기반으로 문제 풀이 하는 것으로 보인다.
* 우리의 현재 레벨은 **1**임이 맨 처음에 나왔고, 해당 값이 3 이상이면 `solve(1)`로 해결되고, 4보다 크거나 같으면 user_lv은 계속 1이다.
* **즉, 3 < user_lv < 4 라는 소리니까 3.5로 설정하면 풀릴 것이다.**

크롬의 확장 프로그램인 'EditThisCookie'으로 쿠키 값을 변경 할 수 있다. 

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182549983-23b3e75c-fd71-4739-8719-99a06aa72973.png" width = 450>
</p>

쿠키 값을 변경하고 새로고침을 하면 해결됩니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182550356-5397a403-8c0f-4ae7-a8a3-4fe62fdc1648.png" width = 320>
</p>