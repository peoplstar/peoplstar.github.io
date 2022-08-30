---
layout: post
title: Webhacking.kr | Level 7
subtitle: Webhacking CTF Problem Solving
categories: Webhacking
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187366815-87c72ded-5a94-421a-9f01-f25d88174807.jpg" width = 260>
</p>

**hi guest**와 함께 소스코드 보는 것 밖에는 없다. 소스 코드를 분석하면서 확인해보겠습니다.

## 소스 코드

```php
$agent=trim(getenv("HTTP_USER_AGENT"));
$ip=$_SERVER['REMOTE_ADDR'];
```

* **$agent** : `getenv("HTTP_USER_AGENT")`를 통해 사용자 웹 접속 환경 정보를 가져와 공백을 모두 제거한 String
* **$ip** : PHP의 예약 변수로써 접속자의 IP

```php
if(preg_match("/from/i",$agent)){
  echo("<br>Access Denied!<br><br>");
  echo(htmlspecialchars($agent));
  exit();
}
```

* 접속자 정보에 'from'의 문자열이 소, 대문자 구분 없이 포함되어 있으면 **Access Denied**

```php
$db = dbconnect();
$count_ck = mysqli_fetch_array(mysqli_query($db,"select count(id) from chall8"));
if($count_ck[0] >= 70){ mysqli_query($db,"delete from chall8"); }
```

* **$count_ck** : DB에 연결하고 **chall8** 테이블에 **id**의 개수

> 해당 id의 개수가 70개가 넘어가면 해당 chall8 테이블의 모든 튜플을 제거

```php
$result = mysqli_query($db,"select id from chall8 where agent='".addslashes($_SERVER['HTTP_USER_AGENT'])."'");
$ck = mysqli_fetch_array($result);
```

* **addslashes()** : SQL Query에서 `'` 싱글 쿼테이션이 있다면 `'\'`를 추가하여 특수 문자로 변환하는 함수

* **$result** : `$_SERVER['HTTP_USER_AGENT']` 사용자 웹 접속 환경 정보를 가져와 `'\'` 백 슬래시를 추가하고, **chall8** 테이블에 해당 agents가 있으면 해당 id를 select

* **$ck** : $result에 대한 결과를 Array로 변환
   * `mysqli_fetch_array` : `mysqli_fetch_array` 함수는 순번을 키로 하는 일반 배열과 컬럼명을 Key로 하는 연관배열 둘 모두 값으로 갖는 배열을 리턴합니다.

```php
if($ck){
  echo "hi <b>".htmlentities($ck[0])."</b><p>";
  if($ck[0]=="admin"){
    mysqli_query($db,"delete from chall8");
    solve(8);
  }
}
```
 
* `$ck`의 첫 인덱스의 값('id')이 "admin"이면 해결이다.

```php
if(!$ck){
  $q=mysqli_query($db,"insert into chall8(agent,ip,id) values('{$agent}','{$ip}','guest')") or die("query error");
  echo("<br><br>done!  ({$count_ck[0]}/70)");
}
```

* $ck가 존재하지 않는다면 테이블에 해당 값을 집어 넣거나, Query Error를 출력한다.

* Chall 8 Table의 형태

 AGENT  | IP | ID | 
:-----: | :----------:|:----------: | 
 "HTTP_USER_AGENT" | XXX.XXX.XXX.XXX | GUEST |

무조건 GUEST로 값이 들어가는 것을 알 수 있다.

## 문제 풀이

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187378020-dbca886c-1940-4161-a486-05f9c0421993.jpg" width = 440>
</p>

사용자 웹 접속 환경 정보가 담긴 헤더 **User-Agent**에 `'` 싱글 쿼테이션을 넣었을 때 Query Error가 나왔다는 것은 $ck가 존재하지 않는다는 것을 의미하는 것으로 보인다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187379812-feb817ae-4b75-41de-8f2a-5ff505c40a39.jpg" width = 440>
</p>

**User-Agent** 값을 변경하였을 때는 아래처럼 몇번째인지, 테이블에 insert 되었다는 것을 알 수 있다.

우리는 무조건 GUEST로 들어가는 ID의 값을 변경해야만 할 것이다.

```php
if(!$ck){
  $q=mysqli_query($db,"insert into chall8(agent,ip,id) values('{$agent}','{$ip}','guest')") or die("query error");
  echo("<br><br>done!  ({$count_ck[0]}/70)");
}
```

이 부분에서 우리가 입력해서 변경할 수 있는 부분은 **$agent**다. insert 구문에서 우리가 직접 "admin"을 넣는다면 가능할 것이다.

```sql
insert into chall8(agent,ip,id) values('peoplstar','1.1.1.1','admin')
```

이렇게 된다면 우리가 원하는 admin을 HTTP_USER_AGENT 정보를 peoplstar로 넣을 수 있다.

```sql
peoplstar', '1.1.1.1', 'admin'), ('guest
```

 AGENT  | IP | ID | 
:-----: | :----------:|:----------: | 
 peoplstar | 1.1.1.1 | admin |
 guest     | XXX.XXX.XXX.XXX | guest|

이렇게 테이블이 만들어 질 것이다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187395066-eb704365-837c-48d5-bff2-5a3a367504bd.jpg" width = 440>
</p>

이후 **User-Agent**를 우리가 집어 넣은 Agent를 넣는다면 아래처럼 해결될 겁니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187395708-3c32ed7e-4ef8-4fa4-abe4-a6f3305410aa.jpg" width = 240>
</p>