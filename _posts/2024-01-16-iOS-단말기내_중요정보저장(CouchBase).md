---
layout: post
title: iOS DVIA-v2 | 단말기 내 중요 정보 저장 (CouchBase)
subtitle: 단말기 내 중요 정보 저장 취약점
categories: iOS
tags: [iOS, Moblie]
---

## 취약점 개요

모바일 진단 항목 중 하나인 단말기 내 중요정보 저장이다. 안드로이드를 비롯하여 iOS에 설치된 스마트폰이나 태블릿과 같은 기기에서 사용자의 중요한 정보가 저장되는 방식과 관련된 보안 취약점을 진단한다.

개발자들은 단말기에 저장될 데이터의 크기, 중요도, 기간 등을 고려해서 운영체제가 제공하고 있는 다양한 저장소에 데이터를 보관한다.

iOS 기기에는 다양한 유형의 중요한 정보가 저장될 수 있다. 이 정보에는 사용자의 개인 식별 정보, 금융 정보, 의료 정보, 회사 비즈니스 정보 등이 포함될 수 있다. 따라서 이러한 정보가 노출되거나 악용될 경우 사용자의 프라이버시나 안전이 위협 받을 수 있다.

모바일 취약점 진단 항목에서는 이러한 중요한 정보가 저장되는 방식에 따라 취약점을 식별한다. 

이 항목은 데이터베이스나 파일 시스템, 암호화와 같은 보안 기술을 사용하여 중요한 정보를 안전하게 저장하는 방식을 살펴본다. 또한, 사용자 인증 및 권한 관리와 같은 보안 메커니즘도 확인한다.

## CouchBase

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/b32d71ca-7bbb-447b-8933-11b03986667d">
</p>

`Couchbase` Lite는 모바일 앱을 위한 임베디드 NoSQL JSON 문서 스타일 데이터베이스입니다.

모바일 앱 내에서 독립형 임베디드 데이터베이스로 Couchbase Lite를 사용하거나, Sync Gateway 및 Couchbase Server와 함께 사용하여 완벽한 클라우드-에지 동기화 솔루션을 제공할 수 있습니다.

Couchbase Lite는 공식적으로 Swift를 지원하며 크로스 플랫폼을 지원하기에 Database CRUD를 사용하기에 용이하다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Local Data Storage > Couch Base**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/cb511a3a-6ebc-4bbd-aad3-f12d220dcd94" width = 450>
</p>

TextField에 값을 삽입하고 버튼 클릭 시 Couchbase를 통해 데이터가 저장된 것을 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/f5c359cd-ff01-4f79-8b96-14d19411166b">
</p>

* `/private/var/mobile/Containers/Data/Application/AAA8DAB1-874E-4B9D-96B7-52E3FB08AC5E/Library/Application Support/CouchbaseLite/dvcouchbasedb.cblite2`

`WinSCP`프로그램을 이용하여 해당 경로를 확인하게 되면 Core Data에 대한 DB 파일이 저장 되어 있는 것을 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/b55b3d3c-dc5b-4615-b576-15fb4300e3da">
</p>

해당 파일을 PC로 모두 옮겨 `SQLite`를 통해 해당 DB 파일을 확인한 결과 입력하였던 해당 Input Data가 저장 되어 있는 것을 확인할 수 있다.

## 대응 방안

* 자격증명, 개인정보, 인증정보 등 중요한 정보는 디바이스 내 저장하지 않아야 한다.

* 디바이스 내 중요정보를 저장해야 할 경우, 안전한 암호화 알고리즘을 통해 데이터를 암호화 해야 한다.

|  **분류**     |   **미국(NIST)**   |     **일본(CRYPTREC)**   | **유럽(ECRYPT)** |      **국내**    | 
|:--------:|:--------------:|:-------------------:|:-------------------:|:-----------------:|
| 대칭키 암호 알고리즘 |  AES-128/192/256     |   AES-128/192/256<br>Camellia-128/192/256    | AES-128/192/256<br>Camellia-128/192/256<br>Serpent-128/192/256 | SEED<br>HIGHT<br>ARIA-128/192/256<br>LEA-128/192/256 |
| 공개키 암호 알고리즘 |           RSA        |   RSAS-OAEP   |  RSAS-OAEP  | RSAES |
| 일방향 암호 알고리즘 |  SHA-224/256/384/512 |   SHA-256/384/512  | RSAS-OAEP | SHA-224/256/384/512 |

## Reference

* [https://docs.couchbase.com/couchbase-lite/current/swift/quickstart.html](https://docs.couchbase.com/couchbase-lite/current/swift/quickstart.html)

* [https://seed.kisa.or.kr/kisa/Board/23/detailView.do](https://seed.kisa.or.kr/kisa/Board/23/detailView.do)