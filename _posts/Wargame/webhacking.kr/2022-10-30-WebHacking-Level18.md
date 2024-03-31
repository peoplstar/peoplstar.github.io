---
layout: post
title: Webhacking.kr | Level 18
subtitle: Webhacking CTF Problem Solving
categories: webhacking.kr
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/198863390-54e3e418-676d-4e52-8636-c9881cb88667.jpg" width = 360> 
</p>

**SQL INJECTION**이란 타이틀과 우리가 입력한 값을 제출하는 form이 존재하며 결과 값을 출력해주는 것과 같은 **RESULT**가 존재한다.

view-source를 통해 어떠한 로직인지 확인해보겠습니다.

## 문제 풀이

```php
<?php
if($_GET['no']){
  $db = dbconnect();
  if(preg_match("/ |\/|\(|\)|\||&|select|from|0x/i",$_GET['no'])) exit("no hack");
  $result = mysqli_fetch_array(mysqli_query($db,"select id from chall18 where id='guest' and no=$_GET[no]")); // admin's no = 2

  if($result['id']=="guest") echo "hi guest";
  if($result['id']=="admin"){
    solve(18);
    echo "hi admin!";
  }
}
?>
```

입력한 값이 `no`라는 변수로 GET 전송을 진행하는 것을 알 수 있고, `preg_match()`를 통해 필터링이 진행되는 것을 알 수 있다.

* **필터링** : `/, \, |, (, ), &, select, from, 0x, 공백` 대소문자 구문 없이 진행

```sql
select id from chall18 where id='guest' and no=$_GET[no]
```

우리가 입력한 값과 `id='guest'`를 **AND** 연산하여 해당 질의가 chall18 table에 존재하면 해당 ID를 `result` 변수에 저장하는 것으로 볼 수 있다.

주석을 보면 **admin's no = 2**라는 힌트를 알 수 있다. 그렇다면 guest의 id는 무엇인지 입력해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/198864031-df494e3e-2dae-4a34-bc28-cbd5b17a1501.jpg" width = 360> 
</p>

**1**이라는 값을 넣으니 RESULT에 **hi guest**라는 문구가 출력된다.

그렇다면 해당 결과의 id가 admin이면서 입력 값이 2가 되어야 하는데 현재 질의로는 무조건 `guest`로 되어있다.

SQLi를 통해 해당 구문을 강제로 참으로 만들거나, id를 **admin**으로 다시 전송하는 것이 가능할 것으로 보인다.

```sql
where id='guest' and no=$_GET[no] or no=2 -- 참
```

`where id='guest' and no=$_GET[no]`까지는 **0**값을 전송하면 guest의 id가 0이므로 False이지만, **OR** 연산으로 값이 2인 것이 참이 되어 해결될 것이다.

```sql
where id='guest' and no=$_GET[no] or id="admin" and no=2 -- 강제 Admin
```

**OR** 기준으로 앞쪽의 질의를 거짓으로 하고 뒤 질의가 참인 값을 전달한다면 OR로 인해 참이 되어 해결될 것이다.

해당 값을 form에서 입력하게 된다면 URL Ending으로 입력 값이 변환이 되어 실패하게 된다. 

따라서, URL에 직접 입력하는 방식으로 하면 풀리게 될 것이다.

* `0%09or%09no=2`

* `0%09or%09id="admin"%09and%09no=2`