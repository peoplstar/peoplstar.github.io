---
layout: post
title: iOS DVIA-v2 | Side Channel Data Leakage (Cookies)
subtitle: Key Logging 정보 취약점
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

* **좌측 상단 메뉴 > Side Channel Data Leakage > Cookies**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/d95a026e-26ea-4e6c-872f-a68ab7967813">
</p>

몇몇 어플리케이션은 쿠키 값을 저장해두는데 그 위치는 `/private/var/mobile/Library/{app_uuid}/Cookies`에 있다고 하며 아무 값을 입력하고 Test 하게 되면 **Failure**가 발생한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/f02fa68c-2a1d-4f2c-8a9d-37e72837c623">
</p>

**WinSCP**프로그램을 통해 단말기와 연결을 하면 `Cookies.binarycookies`라는 파일이 생성 되어 있는 것을 알 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/b6208fb7-91ff-4606-a93f-209b3862bba7">
</p>

해당 파일의 내용을 확인해보면 **username** `admin123`, **password** `dvpassword` 두 값이 평문으로 저장 되어 있는 것을 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/4f17c00f-6197-462a-ac34-f8b3efc61877" width = 450>
</p>

두 값을 넣고 다시 한 번 **Test the results** 버튼 클릭 시 **Success!**로 옳은 값을 찾았다는 것을 알 수 있다.

## 대응 방안

* 계정정보와 같이 중요정보는 Cookie에 저장하지 말고 서버로부터의 인증을 하는 것이 안전하다.

* 계정정보와 같이 중요정보를 저장하게 될 경우 안전한 암호화 알고리즘을 통해 데이터를 암호화한다.