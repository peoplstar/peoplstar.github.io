---
layout: post
title: iOS DVIA-v2 | Side Channel Data Leakage (Device Logs)
subtitle: 부채널 데이터 유출 취약점
categories: iOS
tags: [iOS, Moblie]
---

## 취약점 개요

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/0ee28872-faff-43cf-863e-49e4bc3026ea">
</p>

**부채널 데이터 유출**은 사용되는 어플리케이션의 주 기능이 아닌 타 기능을 통해 데이터가 유출되는 취약점을 말한다. 의도하지 않은 데이터 유출은 개발자가 실수로 모바일 디바이스의 다른 앱이 쉽게 액세스할 수 있는 위치에 민감한 정보나 데이터를 저장할 때 발생한다. 

개발자의 코드가 사용자 또는 백엔드에서 제공한 민감한 정보를 처리할 때 이 과정에서 개발자가 알지 못하는 부작용으로 인해 해당 정보가 모바일 디바이스의 안전하지 않은 위치에 배치되어 디바이스의 다른 앱이 공개적으로 액세스할 수 있게 된다. 일반적으로 이러한 부작용은 기본 모바일 디바이스의 운영 체제(OS)에서 발생하며 공격자는 간단한 코드를 작성하여 민감한 정보가 저장된 위치에 액세스할 수 있다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Side Channel Data Leakage > Device logs**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5a9e7cbf-6b60-462e-932e-2d59f7bd620e" width = 450>
</p>

ID, Password, Email, Phone Number에 각 정보를 입력하고 `iOSLogInfo` 프로그램 통해 로그 기록과 동시에 **Sign Up** 버튼 클릭 시 설정해둔 로그 파일명으로 로그가 찍히는 것을 확인할 수 있다.

```shell
sdsiosloginfo.exe -d > logfilename
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/6ce4ffcb-4a3d-4cc3-9b31-c61ee6587303">
</p>

생성된 로그 파일을 통해 해당 입력 값을 검색하면 앱에서 불필요한 디버그 정보를 남기는 경우 입력 값에 대한 로그를 확인할 수 있다.

하지만 해당 앱을 오류로 인해 앱이 꺼지기에 해당 정보가 저장되지 않아 확인이 불가하다. **이와 같은 방식을 통해 Device logs가 남는지 진단하면 된다.**

## 대응 방안

모니터링해야 할 몇 가지 일반적인 유출 지점이 있습니다. **OS, 플랫폼 및 프레임워크**를 위협 모델링하여 다음 유형의 기능을 어떻게 처리하는지 확인하는 것이 중요하다.

* **URL Caching (Both request and response)**

* **Keyboard Press Caching**

* **Copy/Paste buffer Caching**

* **Application backgrounding**

* **Logging**

* **HTML5 data storage**

* **Browser cookie objects**

* **Analytics data sent to 3rd parties**

## Reference

* [https://owasp.org/www-project-mobile-top-10/2014-risks/m4-unintended-data-leakage](https://owasp.org/www-project-mobile-top-10/2014-risks/m4-unintended-data-leakage)