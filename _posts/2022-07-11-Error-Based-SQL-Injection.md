---
layout: post
title: Error-Based SQL Injection
subtitle: Error-Based SQL Injection
categories: SQL
tags: [SQL, Injection, Pentest]
---

**본 내용 및 실습 환경은 KISEC, 케이쉴드 주니어 교육 과정에 있음을 알려드립니다.**

## 정의

정상 작동하던 SQL Query에 고의적으로 오류를 발생시켜, 출력되는 에러의 내용을 통해 필요한 정보를 찾아낸다.

이러한 에러 출력은 2021년 OWASP TOP 10에 새롭게 등장할 정도로 위험한 취약점이라 알려져 있다.

기본적으로 `'(싱글 쿼테이션)`, 또는 `"(더블 쿼테이션)`, `Group by`와 `Having` 등을 이용해 비정상적인 SQL Query를 진행시킨다.

## 환경

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178284094-543a193c-8fdb-4ed6-800f-34c134c01160.png">
</p>

쇼핑몰과 같은 환경으로 SQL Injection에 대해서는 보안 대책이 갖추어 지지 않은 환경이다.

## 실습

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178286635-3411489a-a3d1-431d-a2d6-74214f772efd.png">
</p>

위 그림과 같이 SQL의 기본 구문은 `SELECT * FROM TABLE_NAME WHERE 조건 = ''` 처럼 되어 있다. 

하지만, `'(싱글 쿼테이션)`을 하나 더 추가하게 된다면 `() {} [] `처럼 짝을 이루지 않았을 때 에러가 발생하게 된다. 

이러한 에러를 발생시켜서 정보를 수집하는 것이다.

### 1. 에러 메시지를 통한 DB 정보 확인

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178286249-02b0b9bd-5687-4342-897c-f65417ea9030.png">
</p>

위에서 예시로 Quick Search 부분에 `'`를 하나 넣으면 아래와 같은 에러와 함께 Microsoft OLE DB Provider for SQL Server가 나오게 된다.

**즉, 해당 환경은 MSSQL을 사용하고 있다는 것을 알 수 있다.**

또한 Quick Search에 대한 SQL 작동은 `shop_searchresult.asp`를 통해서 전달 되는 것을 알 수 있다.

### 2. DateBase 이름 확인

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178288703-cc39bcf4-db8a-46e9-bb13-2639a6ec9b3f.png">
</p>

`db_name()`해당 함수는 SQL에서 기본 제공 해주는 함수이다.

이 함수는 Return 값으로 현재 Database의 이름을 반환한다. 

<a href = "https://docs.microsoft.com/ko-kr/sql/t-sql/functions/db-name-transact-sql?view=sql-server-ver16"> 자세한 내용은 해당 링크를 참조하시면 됩니다.</a>

반환 형식은 **nvarchar(128)**로 명시 되어 있는데 즉, 
함수를 이용해서 `' and db_name() > 1 --`를 하게 된다면,

`SELECT * FROM TABLE WHERE ITEM = ''`를 `SELECT * FROM TABLE WHERE ITEM = '' AND db_name() > 1 -- '`로 바꾸게 된다.

db_name()의 Return은 varchar이지만 비교 대상의 '1'은 int형이기에 에러가 발생한다.

결과로 해당 Datebase의 이름은 'oyesmall'인 것을 알 수 있다.

### 3. Having 구절로 테이블, 칼럼 확인

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178291719-15b6f64e-fe33-43ec-8cd8-75319382577e.png" width = 320>
</p>

SQL에서 그룹별 집계된 결과 중 원하는 조건의 결과만 필터링 해주는 `HAVING`절이 존재한다.

그룹별이라면 `Group by`와 같이 사용 해야한다는 것인데 `having`을 단독으로 사용했을 때에 에러를 이용 하는 것이다.

`having`에 대한 조건은 `1=1`로 항상 참이 되게 하고 이후 내용을 모두 `--`로 주석 처리한다면 비밀번호에 어떤 문자가 와도 주석이 되는 것을 참고하세요.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178293904-23d53ef4-4b4c-452b-9611-7ab12f1d3edf.png" width = 480>
</p>

해당 결과로는 Members 테이블에 num이라는 컬럼이 존재하는 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178294912-52aaf9fa-a752-47c4-a12e-d8b0789aa619.png" width = 480>
</p>

첫번째 칼럼의 이름을 알았으므로 group by를 이용해 `' group by Members.num having 1=1 --`를 하면 두번째 칼럼을 알 수 있다.

이렇게 두번째 칼럼의 이름까지 `' group by Members.num, Members.user_id having 1=1 --`로 세번째도 알 수 있다.

### 4. in, not in을 통한 칼럼 내용 확인

Having 구절로 테이블, 칼럼의 이름을 알아냈다.

칼럼의 이름을 알아 낸 것으로 그치면 아무 쓸모가 없기에, 해당 칼럼의 값이 무엇인지 확인 해본다.

Having 구절로 테이블명은 **Members**, 칼럼은 **num, user_id, passwd** 등이 있는 것을 알았다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178434665-1951d930-c6c5-41c7-9ff1-be1a30506d99.png" width = 320>
</p>

기본 형태로는 `SELECT COLUMN FROM TABLE WHERE ITEM = ''`와 같으므로,

`' OR 1 IN(SELECT USER_ID FROM MEMBERS WHERE USER_ID >= 'a') --`

우리가 알아낸 테이블명 **Members**, 칼럼명 **USER_ID**을 대입하여 완성한다.

해당 구문에서 Error가 발생하는 이유로는 `IN`은 WHERE구문에서 내부 Query를 진행 하는데 `IN` 내부에서 진행한 쿼리와 `OR 1`에 대한 데이터 형식이 **INT**, **nvarchar**로 다르기에 에러가 발생하면서 해당 값을 보여주게 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178436961-33a53c45-ce25-4b1d-a54b-e8517ef436cf.png" width = 480>
</p>

가장 첫번째로 나온 값으로는 **'oyes'** 라는 칼럼의 값을 뽑아냈다.

이후로는 `NOT IN`을 이용하여 뽑아볼 수 있다. 결과는 **'oyes'**의 이후 값을 뽑아 내기에 명령어만 보여줄 것이다.

`'OR 1 IN(SELECT USER_ID FROM MEMBERS WHERE USER_ID NOT IN (‘oyes’,‘,,,,,’)) -- `

NOT IN에 나온 값을 하나씩 대입하면 해당 값을 제외한 칼럼의 값을 뽑을 수 있다.

### 5. DB Table의 행(튜플)의 개수

각 DB에는 몇 개의 데이터가 있을 지 확인 해볼 것이다.

이번에 이용해볼 함수로는 `CAST()`함수다.

이 함수는 테이블에서 추출한 값을 명시적으로 형변환 하는 것이다.

예를 들면 `SELECT 3 + 'age' -- Error 발생`

이런 것을 막기 위해서 사용 하지만, 우리는 이러한 Error를 유발하여 테이블의 행 개수를 알아 낼 것이다.

`'OR 1 IN(SELECT 'a' + CAST(COUNT(*) AS VARCHAR(100)) FROM MEMBERS) --`

MEMBERS 테이블에서 모든 것을 COUNT 하여 VARCHAR(100)로 형변환 한 후, 해당 값에 'a'를 더하여 `OR 1`을 하기에 INT와 VARCHAR로 데이터 형식이 맞지 않아 Error를 유발한다. 

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178441663-b75e4a43-ba0e-4b53-bd3f-e218252c435d.png" width = 480>
</p>

이처럼 해당 테이블에는 총 9개의 행이 존재한다는 것을 알 수 있다.

이렇게 Error-Based SQL Injection을 알아봤다.

## 보안 대책

서버 입장에서는 에러에 대한 메세지를 직접적으로 노출 시키면 안된다.

이러한 에러 노출로 인해 관리자의 ID, PW 및 이용자의 모든 정보를 확인 가능 하기 때문이다.