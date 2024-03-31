---
layout: post
title: Webhacking.kr | Level 7
subtitle: Webhacking CTF Problem Solving
categories: Web
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186561620-aa90e86f-6093-44b4-903e-bf9cc49c346f.jpg" width = 260>
</p>

Admin page라는 것과 함께 auth 버튼과 소스코드를 보는 것이 있다. **auth**를 누르면 **Access_Denied!**의 Alert가 뜬다. 

그리고 URL을 보면 https://webhacking.kr/challenge/web-07/index.php **?val=1** Parameter를 GET 방식으로 val 변수에 대해서 넘겨주고 있는 것을 알 수 있다.

view-source를 통해 소스코드를 먼저 보겠습니다.

```php
$go=$_GET['val'];
if(!$go) { echo("<meta http-equiv=refresh content=0;url=index.php?val=1>"); }
echo("<html><head><title>admin page</title></head><body bgcolor='black'><font size=2 color=gray><b><h3>Admin page</h3></b><p>");
if(preg_match("/2|-|\+|from|_|=|\\s|\*|\//i",$go)) exit("Access Denied!");
$db = dbconnect();
```

GET 방식으로 넘긴 Parameter **val**는 `$go`라는 변수에 들어가고, `$go`변수에 대해 정규 표현식 패턴 검사 통과하면 DB를 연결하는 것을 알 수 있다.

* **preg_match** : `$go` 변수에 '2', '-', '+', 'from', 공백, '*' 문자가 대소문자 구분없이 포함되어 있으면 **Access Denied**하겠다. 즉, SQL에 대해서 어느 정도 필터링을 하고 있다는 것을 의미한다.

```php
$rand=rand(1,5);
if($rand==1){
  $result=mysqli_query($db,"select lv from chall7 where lv=($go)") or die("nice try!");
}
if($rand==2){
  $result=mysqli_query($db,"select lv from chall7 where lv=(($go))") or die("nice try!");
}
if($rand==3){
  $result=mysqli_query($db,"select lv from chall7 where lv=((($go)))") or die("nice try!");
}
if($rand==4){
  $result=mysqli_query($db,"select lv from chall7 where lv=(((($go))))") or die("nice try!");
}
if($rand==5){
  $result=mysqli_query($db,"select lv from chall7 where lv=((((($go)))))") or die("nice try!");
}
$data=mysqli_fetch_array($result);
```

`$rand` 랜덤 변수 값에 대해서 SQL Query가 달라지는데 `$go` 변수에 괄호 로 묶여 있는 것을 알 수 있다.

```php
if(!$data[0]) { echo("query error"); exit(); }
if($data[0]==1){
  echo("<input type=button style=border:0;bgcolor='gray' value='auth' onclick=\"alert('Access_Denied!')\"><p>");
}
elseif($data[0]==2){
  echo("<input type=button style=border:0;bgcolor='gray' value='auth' onclick=\"alert('Hello admin')\"><p>");
  solve(7);
}
```

쿼리의 결과 값 즉, 우리가 입력할 **val**의 값이 **2**인 경우 **Hello admin**과 함께 해결된다.

맨 처음에 `$go`의 값이 2가 되면 안된다는 것을 정규 표현식에 만들어줬다.

## 문제 풀이

우선 `$rand`가 1일 경우를 생각해서 보겠습니다

```sql
select lv from chall7 where lv=($go)
```

이 쿼리를 통해 $result 즉 $data[0]의 값을 2로 만들려면 **$go** 2를 강제로 만들어야 한다.

몫을 구하는 연산자는 `%`를 이용한다. 

```
https://webhacking.kr/challenge/web-07/index.php?val=(5%3)
```

이렇게 하여 결과 값을 2로 만들었지만 아래처럼 쿼리에 문제가 있다고 한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186606617-48c0e406-caa3-47d2-9a5f-6ef17c188c3b.jpg" width = 200>
</p>

chall7 테이블인 lv 칼럼에는 **2**라는 값이 있지 않다는 것이다.

그렇다면 강제로 2라는 값을 출력하는 Query를 Union SQL Injection을 통해 만들면 될 것이다.

```sql
select lv from chall7 where lv=(999)union(select(5%3))
```

**999)union(select(5%3)**을 대입하면 해당 lv에는 999라는 값은 존재하지 않아 아무 값도 뽑아내지 못하고 뒤에 나오는 Union에는 2라는 값을 전달하므로 해결된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186608448-3978f71e-155c-44d5-8ac1-52a4a896d60e.jpg" width = 420>
</p>

하지만, 저 값을 입력하고 풀리지 않으면 새로고침을 통해서 $rand 값이 1이 될 때 까지 해야한다. 

그 이유로는 `select lv from chall7 where lv=(($go))` 일 경우 `where lv=((999)union(select(5%3))))` **UNION** 구문이 기존에 존재하는 **WHERE** 구문에 포함되어 별도의 5%3의 값을 뽑아올 수 없기 때문이다. 예시를 들어서 보여드리겠습니다.

## 예외에 대한 예시

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186613692-658aa487-853a-44e8-94ec-d80b16255293.jpg">
</p>

이러한 테이블이 존재한다고 했을 때 우리의 문제 $rand가 1일 경우를 해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186613980-de245028-bf4a-4080-81f4-f2b14eaa1f17.jpg">
</p>

이렇게 괄호가 하나가 있을 때는 ID 가 **999** 구문에 **UNION**에 대한 값이 나오는 반면 $rand가 2일 경우에는

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186614375-78c23ab9-5f8c-46d4-8d70-36c79e2e0cea.jpg">
</p>

이렇게 쿼리 에러가 발생한다. 자세히 보면 기존 **WHERE**에 대한 구문 안에 UNION이 들어가면서 쿼리가 비정상적이기 때문이다. ([실습 링크](http://sqlfiddle.com/))

이번 문제를 통해 UNION SQL Injection을 해봤다.