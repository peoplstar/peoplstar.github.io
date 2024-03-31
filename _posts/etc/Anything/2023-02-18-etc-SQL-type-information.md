---
layout: post
title: SQL 정보 수집
subtitle: Database 종류 및 테이블, 칼럼 정보 수집
categories: Anything
tags: [Pentest, SQL]
---
 
**본 내용은 Dreamhack [\[WHA\] ExploitTech: System Table Fingerprinting](https://learn.dreamhack.io/306)을 통해서 학습할 수 있습니다.**

**Oracle, MySQL, MSSQL등 테스트용 사이트를 해당 [링크](http://sqlfiddle.com/#!17)를 클릭하시면 해볼 수 있습니다.**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/219926801-2d52b8d3-cde6-4dbf-ac82-0ad4fcd574ef.png" width = 500> 
</p>

## 들어가기 앞서

모의해킹을 진행하면서 **SQLi**에 대한 시나리오를 진행하게 된다면 해당 시스템에서 어떠한 종류의 DB를 사용하고 있는지, 어떠한 테이블과 칼럼이 존재하는지 정보 수집이 필요하다.

데이터베이스의 종류는 대표적으로 **MySQL, MSSQL, Oracle, PostgreSQL, SQLite**가 있다. (NoSQL도 있지만 추후에 다루겠습니다.)

데이터베이스의 종류는 `nmap`을 통한 포트스캐닝을 통해서 Open되어 있는 포트 번호를 보고 유추할 수 있습니다.

각 DB마다 사용되는 명령어가 조금씩 다르기에 모의해킹에 하는데 있어서 필요할 것으로 보이는 주요 명령어를 모았습니다.

## MySQL

### 데이터베이스 정보

MySQL에 어떠한 데이터베이스가 존재하고 있는지 확인한다.

```sql
mysql> select TABLE_SCHEMA from information_schema.tables group by TABLE_SCHEMA;
/*
+--------------------+
| TABLE_SCHEMA       |
+--------------------+
| information_schema |
| DREAMHACK          |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.01 sec)
*/
```

MySQL의 내장 함수 중 `DATABASE()`를 하게 되면 현재 사용중인 DB를 출력한다.

```sql
mysql> select DATABASE();
/*
+--------------------+
| TABLE_SCHEMA       |
+--------------------+
| DREAMHACK          |
+--------------------+
1 rows in set (0.01 sec)
*/
```

### 테이블 정보

`information_schema.TABLES`를 통해 어떠한 데이터베이스에서 어떤 테이블이 있는지 확인한다.

```sql
mysql> select TABLE_SCHEMA, TABLE_NAME from information_schema.TABLES;
/*
+--------------------+----------------+
| TABLE_SCHEMA       | TABLE_NAME     |
+--------------------+----------------+
| information_schema | CHARACTER_SETS |
...
| DREAMHACK          | users          |
| mysql              | db             |
...
+--------------------+----------------+
292 rows in set (0.01 sec)
*/
```

아래의 명령은 테이블 이름을 유추하여 Injection하는 방법으로 테이블의 존재여부 확인하는 방법이다. 해당 테이블이 있으면 **1**, 없으면 **0** 으로 알 수 있다.

```sql
mysql> SELECT 1 FROM information_schema.tables WHERE table_schema = 'DB명'  AND table_name = '테이블명'
```

### 칼럼 정보

`information_schema.COLUMNS`을 통해 칼럼 정보를 확인할 수 있다.

```sql
mysql> select TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME from information_schema.COLUMNS;
/*
+--------------------+----------------+--------------------+
| TABLE_SCHEMA       | TABLE_NAME     | COLUMN_NAME        |
+--------------------+----------------+--------------------+
| information_schema | CHARACTER_SETS | CHARACTER_SET_NAME |
...
| DREAMHACK          | users          | uid                |
| DREAMHACK          | users          | upw                |
...
| mysql              | db             | Db                 |
| mysql              | db             | User               |
...
+--------------------+----------------+--------------------+
3132 rows in set (0.07 sec)
*/
```

이후에는 칼럼에 대한 정보를 통해 Blind, Union등의 Injection을 통해서 값을 추출할 수 있다.

## MSSQL

### 데이터베이스 정보

MSSQL에 어떠한 데이터베이스가 존재하고 있는지 확인한다.

```sql
SELECT name FROM sys.databases
/*동일한 결과*/
SELECT name FROM master..sysdatabases;
/*
name
-------
master
tempdb
model
msdb
dreamhack # 이용자 정의 데이터베이스 (예시)
*/
```

MSSQL의 내장 함수 중 `DB_NAME(인자)`를 통해서 데이터베이스 정보를 확인할 수 있는데, 인자의 값 없이 `DB_NAME()`를 하게 되면 현재 사용중인 DB를 출력한다.

```sql
SELECT DB_NAME(1);
/*
master
*/
```

### 테이블 정보

`SYSOBJECTS` 테이블을 통해 드림핵 데이터베이스의 테이블 정보를 조회할 수 있는데 `xtype='U'`라는 조건을 적용한다. 이는 이용자 정의 테이블을 의미합니다.

```sql
SELECT name FROM DB명..sysobjects WHERE xtype = 'U';

SELECT table_name FROM DB명.information_schema.tables;
/*
+--------+  +------------+
| name   |  | table_name |
|--------|  |------------|
| users  |  | users      |
+--------+  +------------+
*/
```

### 칼럼 정보

MSSQL의 경우 `SYSCOLUMNS` 테이블을 통해서도 컬럼의 정보를 조회할 수 있다.

```sql
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = '테이블명');
/*
name
-----
uid
upw
*/
```

MySQL과 마찬가지로 `information_schema.columns`를 통해서도 조회가 가능하다.

```sql
SELECT table_name, column_name FROM DB명.information_schema.columns;
SELECT table_name, column_name FROM information_schema.columns WHERE table_name = "테이블명";
/*
table_name	column_name
-------------------------
users		uid
users		upw
*/
```

### 계정 정보

```sql
SELECT name, password_hash FROM master.sys.sql_logins;
/*
name		password_hash
--------------------------
sa			NULL
dreamhack	NULL
*/
```

## PostgreSQL

### 데이터베이스 정보

PostgreSQL는 초기에 `postgres, template1, template0` 데이터베이스가 존재한다.

```sql
select datname from pg_database;
```

### 스키마 정보

주요 정보를 담고 있는 테이블을 포함한 스키마는 `pg_catalog, information_schema`가 있다.

```sql
postgres=$ select nspname from pg_catalog.pg_namespace;
/*
      nspname       
--------------------
  pg_toast
  pg_temp_1
  pg_toast_temp_1
  pg_catalog <--
  public
  information_schema <--
  (6 rows)
*/
```

### 테이블 정보

주요 정보를 담고 있는 두 스키마를 통해서 데이터를 뽑으면 다른 결과가 나오는 것을 알 수 있다.

**information_schema**에도 메타데이터 정보가 저장되어 있는데, **pg_catalog** 시스템 카탈로그 정보를 조인해서 얻은 view이다.

`CREATE database` 와 같은 쿼리를 수행하면 **pg_catalog**에 자동으로 `insert`되기에 시스템 카탈로그를 직접 조작하는 것은 위험하다.

>즉 **pg_catalog**는 각 DB 내부에 존재하는 schema다.

```sql
postgres=$ select table_name from information_schema.tables where table_schema='pg_catalog';
/*
           table_name
---------------------------------
pg_shadow
pg_settings
pg_database
pg_stat_activity
...
*/
postgres=# select table_name from information_schema.tables where table_schema='information_schema';
/*
              table_name
---------------------------------------
schemata
tables
columns
...
*/
```

### 칼럼 정보

```sql
postgres=$ select table_schema, table_name, column_name from information_schema.columns;
/*
    table_schema    |      table_name         |    column_name
--------------------+-------------------------+------------------
 pg_catalog         | pg_stat_user_indexes    | relid
...
 information_schema | view_routine_usage      | specific_name
...
*/
```

### 계정 정보

리눅스는 `/etc/shadow`에서 계정에 대한 해시 정보를 담고 있는데 **PostgreSQL** 또한 `pg_catalog.pg_shadow` 테이블을 통해 PostgreSQL 서버의 계정 정보를 조회할 수 있다.

```sql
postgres=$ select usename, passwd from pg_catalog.pg_shadow;
/*
 usename  |               passwd
----------+-------------------------------------
 postgres | md5df6802cb10f4000bf81de27261c1155f
(1 row)
*/
```

## Oracle

### 데이터베이스 정보

`all_tables`는 현재 사용자가 접근할 수 있는 테이블의 집합이다.

```sql
SELECT DISTINCT owner FROM all_tables
/*
OWNER
-----
SYS
AV
CTXSYS
...
SH
XDB
---
15 rows selected.
*/
```

### 칼럼 정보

`all_tab_columns`를 통해 특정 테이블의 컬럼 정보를 확인할 수 있다.

```sql
SELECT column_name FROM all_tab_columns WHERE table_name = '테이블명';
```

### 계정 정보

`all_users` 테이블을 통해 DBMS 계정 정보를 획득할 수 있습니다.

```sql
SELECT * FROM all_users
```

## SQLite

**SQLite**는 `information_schema`가 없고 **sqlite_master** 라는게 있다. 

### 테이블 정보

```sql
sqlite> SELECT tbl_name FROM sqlite_master; /*name 이랑 tbl_name 이랑 같다*/
sqlite> select * from sqlite_master;
/*
type|name|tbl_name|rootpage|sql
table|users|users|2|CREATE TABLE users (uid text, upw text)
*/
```

## 참고 

* [컴퓨터 엔지니어로 살아남기](https://getchan.github.io/data/pg_catalog/)

* [NoirStar Space](https://noirstar.tistory.com/291)