---
layout: post
title: iOS DVIA-v2 | 단말기 내 중요 정보 저장 (Yap Database)
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

## YapDatabase

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/ecfcce50-39de-4482-be41-13de441746d0">
</p>

`YapDatabase`는 iOS 및 Mac 애플리케이션용 SQLite 위에 구축된 데이터베이스 프레임워크입니다.

Yap의 기본 데이터베이스는 **Collection-Key-Value**  저장소로 구성되어 있습니다. `Collection`은 일반적인 Key-Value 데이터베이스 위에 추가적인 수준의 구성을 제공합니다. 라이브러리의 예를 들어, 적절한 Collection 값은 장르입니다. 따라서 책을 각각의 장르로 구분한 다음 각 장르 내의 고유 Key(ISBN)를 기준으로 책을 정렬할 수 있습니다.

이 경우 값은 제목, 저자 및 기타 세부 정보를 포함하는 Book 개체가 되고, **각 Collection 내에서 각 Key는 고유해야 하므로 모든 객체는 (Collection, Key) 쌍으로 고유하게 식별될 수 있습니다.**

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Local Data Storage > Yap**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/4f74f68a-2324-43ec-aae1-ddbc789558f7" width = 450>
</p>

`Username`과 `Password`에 각각 데이터를 정보 저장하면 **Yap Database**에 저장된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/805ba420-e6cd-481d-b76b-26b0f04211ef">
</p>

* `/private/var/mobile/Containers/Data/Application/AAA8DAB1-874E-4B9D-96B7-52E3FB08AC5E/Library/Application Support`

`WinSCP`프로그램을 이용하여 해당 경로를 확인하게 되면 `YapDatabase.sqlite`로 명시된 파일이 생성된 것을 확인 할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/e55dfcb4-65a2-4b18-bc8e-6dde587ae23f">
</p>

해당 파일을 PC로 모두 옮겨 파일을 확인하면 입력한 값이 `Collection`, `Username`, `Password`의 Yap 형태를 확인할 수 있지만, 해당 앱을 데이터 저장쪽 로직이 미구현 혹은 정상 작동하지 않아 저장 되지 않는다.

## 대응 방안

* 자격증명, 개인정보, 인증정보 등 중요한 정보는 디바이스 내 저장하지 않아야 한다.

* 디바이스 내 중요정보를 저장해야 할 경우, 안전한 암호화 알고리즘을 통해 데이터를 암호화 해야 한다.

|  **분류**     |   **미국(NIST)**   |     **일본(CRYPTREC)**   | **유럽(ECRYPT)** |      **국내**    | 
|:--------:|:--------------:|:-------------------:|:-------------------:|:-----------------:|
| 대칭키 암호 알고리즘 |  AES-128/192/256     |   AES-128/192/256<br>Camellia-128/192/256    | AES-128/192/256<br>Camellia-128/192/256<br>Serpent-128/192/256 | SEED<br>HIGHT<br>ARIA-128/192/256<br>LEA-128/192/256 |
| 공개키 암호 알고리즘 |           RSA        |   RSAS-OAEP   |  RSAS-OAEP  | RSAES |
| 일방향 암호 알고리즘 |  SHA-224/256/384/512 |   SHA-256/384/512  | RSAS-OAEP | SHA-224/256/384/512 |

## Reference

* [https://github.com/yapstudios/YapDatabase](https://github.com/yapstudios/YapDatabase)