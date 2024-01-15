---
layout: post
title: iOS DVIA-v2 | 단말기 내 중요 정보 저장 (CoreData)
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

## CoreData

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/621832a8-4539-4675-909b-be4c2c86ab70">
</p>

`Core Data`는 데이터 관리 및 지속성을 지원하는 iOS의 프레임워크로 이를 통해 SQLite, XML 또는 바이너리 파일과 같은 영구 저장소에서 데이터를 생성, 검색, 업데이트 및 삭제할 수 있습니다.

Core Data를 사용하여 오프라인 사용을 위해 애플리케이션의 영구 데이터를 저장하고, 임시 데이터를 캐싱하고, 단일 기기에서 앱에 실행 취소 기능을 추가할 수 있습니다. 

하나의 iCloud 계정으로 여러 기기에서 데이터를 동기화하기 위해 Core Data는 스키마를 CloudKit 컨테이너에 자동으로 미러링합니다.

Core Data의 데이터 모델 에디터를 통해 데이터의 유형과 관계를 정의하고 각각의 클래스 정의를 생성합니다.

그런 다음 Core Data는 런타임에 오브젝트 인스턴스를 관리하여 다음과 같은 기능을 제공할 수 있습니다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Local Data Storage > Core Data**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/4e2c819a-73fd-459a-a96c-98bfcd0f7dfa">
</p>

아이디 및 이메일과 같은 정보를 입력하여 버튼을 크릭하면 Core Data에 저장되었다는 것을 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/884f6fa2-ca56-40db-b730-1f9d081f2916">
</p>

* **/private/var/mobile/Containers/Data/Application/AAA8DAB1-874E-4B9D-96B7-52E3FB08AC5E/Library/Application Support**

`WinSCP`프로그램을 이용하여 해당 경로를 확인하게 되면 Core Data에 대한 DB 파일이 저장 되어 있는 것을 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/89862188-de5b-4a7f-a5fe-23d1ce05a110">
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

* [https://developer.apple.com/documentation/coredata/](https://developer.apple.com/documentation/coredata/)

* [https://medium.com/@vipandey54/core-data-1fe021cd7fa](https://medium.com/@vipandey54/core-data-1fe021cd7fa)

* [https://seed.kisa.or.kr/kisa/Board/23/detailView.do](https://seed.kisa.or.kr/kisa/Board/23/detailView.do)