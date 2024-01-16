---
layout: post
title: iOS DVIA-v2 | 단말기 내 중요 정보 저장 (NSUserDefaults)
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

## NSUserDefaults

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/a0ba6839-3e42-4c63-81b4-bd3786bca048">
</p>

`NSUserDefaults`는 앱이 실행되는 동안 키-값 쌍을 지속적으로 저장할 수 있는 사용자 기본 데이터베이스에 대한 인터페이스입니다.

`NSUserDefaults` 클래스는 기본값 시스템과 상호 작용하기 위한 프로그래밍 인터페이스를 제공합니다. 기본값 시스템을 사용하면 앱이 사용자의 기본 설정에 맞게 동작을 사용자 지정할 수 있습니다. 예를 들어 사용자가 선호하는 측정 단위나 미디어 재생 속도를 지정하도록 허용할 수 있습니다. 

앱은 사용자의 기본값 데이터베이스에 있는 매개변수 세트에 값을 할당하여 이러한 기본 설정을 저장합니다. 이러한 매개 변수는 일반적으로 앱 시작 시 앱의 기본 상태 또는 기본 동작 방식을 결정하는 데 사용되기 때문에 기본값이라고 합니다.

런타임에 `NSUserDefaults` 객체를 사용하여 사용자의 기본값 데이터베이스에서 앱이 사용하는 기본값을 읽습니다. 기본값이 필요할 때마다 사용자의 기본값 데이터베이스를 열지 않아도 되도록 `NSUserDefaults`는 정보를 캐시합니다. 기본값을 설정하면 프로세스 내에서 동기적으로 변경되고 영구 저장소 및 기타 프로세스에 비동기적으로 변경됩니다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Local Data Storage > UserDefaults**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/aac33840-b822-4395-8489-134a0a6f23eb" width = 450>
</p>

`Test UserDefaults` 값을 넣고 저장하게 되면 **NSUserDefaults**에 저장되었다는 것을 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/2b965443-855d-49ed-9276-ddc52f1fb014">
</p>

* `/private/var/mobile/Containers/Data/Application/AAA8DAB1-874E-4B9D-96B7-52E3FB08AC5E/Library/Preferences`

`WinSCP`프로그램을 이용하여 해당 경로를 확인하게 되면 `plist` 확장자의 파일이 저장되어있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/9117eb3a-1a04-493e-a6fe-a2380d7882f5">
</p>

해당 파일을 PC로 모두 옮겨 파일을 확인하면 입력한 값 `Test UserDefaults`가 `Key-Values` 형태로 저장된 것을 확인할 수 있다.

## 대응 방안

* 자격증명, 개인정보, 인증정보 등 중요한 정보는 디바이스 내 저장하지 않아야 한다.

* 디바이스 내 중요정보를 저장해야 할 경우, 안전한 암호화 알고리즘을 통해 데이터를 암호화 해야 한다.

|  **분류**     |   **미국(NIST)**   |     **일본(CRYPTREC)**   | **유럽(ECRYPT)** |      **국내**    | 
|:--------:|:--------------:|:-------------------:|:-------------------:|:-----------------:|
| 대칭키 암호 알고리즘 |  AES-128/192/256     |   AES-128/192/256<br>Camellia-128/192/256    | AES-128/192/256<br>Camellia-128/192/256<br>Serpent-128/192/256 | SEED<br>HIGHT<br>ARIA-128/192/256<br>LEA-128/192/256 |
| 공개키 암호 알고리즘 |           RSA        |   RSAS-OAEP   |  RSAS-OAEP  | RSAES |
| 일방향 암호 알고리즘 |  SHA-224/256/384/512 |   SHA-256/384/512  | RSAS-OAEP | SHA-224/256/384/512 |

## Reference

* [https://developer.apple.com/documentation/foundation/nsuserdefaults](https://developer.apple.com/documentation/foundation/nsuserdefaults)