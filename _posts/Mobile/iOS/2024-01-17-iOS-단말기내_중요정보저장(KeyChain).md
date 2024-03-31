---
layout: post
title: iOS DVIA-v2 | 단말기 내 중요 정보 저장 (KeyChain)
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

## KeyChain

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/e940380b-8878-4e66-8d8a-8258a5a34019">
</p>

PC 사용자들은 종종 안전하게 보관해야 하는 정보를 가지고 있는데 대부분의 사람들은 수많은 온라인 계정을 관리합니다. 각 계정마다 복잡하고 고유한 비밀번호를 기억하는 것은 불가능하지만, 일일이 적어두는 것은 안전하지도 않고 귀찮기도 합니다.

그래서 사용자는 일반적으로 여러 계정에 걸쳐 간단한 비밀번호를 재활용하는 방식으로 이러한 상황에 대응하는데 이 방식은 안전하지 않습니다.

`Keychain` 서비스 API는 앱에 Keychain이라는 암호화된 데이터베이스에 소량의 사용자 데이터를 저장하는 메커니즘을 제공함으로써 이 문제를 해결할 수 있도록 도와줍니다. 

비밀번호를 안전하게 기억하면 사용자가 복잡한 비밀번호를 선택할 필요가 없습니다. 키체인은 위 그림에서 볼 수 있듯이 비밀번호 저장에만 국한되지 않습니다. 

신용카드 정보나 짧은 메모 등 사용자가 명시적으로 중요하게 생각하는 다른 비밀을 저장할 수 있고, 사용자가 필요하지만 잘 모르는 항목도 저장할 수 있습니다. 예를 들어, 인증서, 키 및 신뢰 서비스로 관리하는 암호화 키와 인증서를 통해 사용자는 보안 통신에 참여하고 다른 사용자 및 장치와 신뢰를 구축할 수 있기에 Keychain을 사용하여 저장합니다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Local Data Storage > KeyChain**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/b0cd8e12-9d23-46ea-8bc2-f1ff15d1472b" width = 450>
</p>

TextField에 값을 삽입하고 버튼 클릭 시 `KeyChain`를 통해 데이터가 저장된 것을 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/57dc07e2-f9fc-4be8-b821-1ce706e8a9de">
</p>

Keychain은 `objection` 이라는 모듈을 통해 해당 어플리케이션에 저장된 Keychain을 모두 확인할 수 있다.

```
objection -g {APP_PACKAGE_NAME} explore
ios keychain dump
```

## 대응 방안

* 자격증명, 개인정보, 인증정보 등 중요한 정보는 디바이스 내 저장하지 않아야 한다.

* 디바이스 내 중요정보를 저장해야 할 경우, 안전한 암호화 알고리즘을 통해 데이터를 암호화 해야 한다.

|  **분류**     |   **미국(NIST)**   |     **일본(CRYPTREC)**   | **유럽(ECRYPT)** |      **국내**    | 
|:--------:|:--------------:|:-------------------:|:-------------------:|:-----------------:|
| 대칭키 암호 알고리즘 |  AES-128/192/256     |   AES-128/192/256<br>Camellia-128/192/256    | AES-128/192/256<br>Camellia-128/192/256<br>Serpent-128/192/256 | SEED<br>HIGHT<br>ARIA-128/192/256<br>LEA-128/192/256 |
| 공개키 암호 알고리즘 |           RSA        |   RSAS-OAEP   |  RSAS-OAEP  | RSAES |
| 일방향 암호 알고리즘 |  SHA-224/256/384/512 |   SHA-256/384/512  | RSAS-OAEP | SHA-224/256/384/512 |

## Reference

* [https://developer.apple.com/documentation/security/keychain_services/](https://developer.apple.com/documentation/security/keychain_services/)

* [https://seed.kisa.or.kr/kisa/Board/23/detailView.do](https://seed.kisa.or.kr/kisa/Board/23/detailView.do)