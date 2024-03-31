---
layout: post
title: iOS DVIA-v2 | Application Patching (Alert)
subtitle: 앱 위변조 취약점
categories: iOS
tags: [iOS, Moblie]
---

## 취약점 개요

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/52fdf7e5-edac-48be-b59f-9b1a94ba490b">
</p>

**바이너리 코드 패치**는 공격자가 코드의 나머지 기능은 그대로 유지하면서 프로그램 코드의 특정 부분을 변경하는 일반적이고 효과적인 방법으로 소스 코드 없이도 프로그램을 제자리에서 조작할 수 있다.

공격자는 잘 알려진 디스어셈블러 또는 후킹 도구를 사용하여 코드를 이해하고 바이너리 패치를 구현할 수 있다. 그러나 다른 비표준 기술을 사용하여 바이너리 패치를 구현할 수도 있으며, 이는 쉽게 탐지되지 않을 수 있다.

바이너리 패치의 일반적인 표적은 다음과 같습니다

* 소프트웨어에서 라이선스 검사 제거

* 애플리케이션 제한 우회

* 광고 비활성화

* 비디오 게임에서의 부정 행위

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Application Patching**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/860ceecd-a050-475c-8fcf-32785227af7e">
</p>

**Application Patching**에 Login Method 1를 포함한 4개의 버튼이 보이는데 이번엔 Check For Jalibreak를 진행한다.

**Show Alert**를 클릭하는 경우 **I love Google**의 문구가 나오는 것을 알 수 있다. 해당 문구를 **I Love Apple**로 바꾸는게 관건이다.

### 바이너리 분석

iOS에서 앱을 실행할 때는 **앱의 Binary** 자체가 실행되고 있다. 따라서 분석하기 위해서는 `ipa` 파일이 아닌 `Binary` 파일을 찾아서 분석해야한다.

단말기와 PC를 같은 네트워크에 연결하고 단말기 네트워크 IP를 통해 **SSH** 붙어서 실행중인 바이너리를 검색한다._(탈옥 후 기본 ROOT 패스워드는 **alpine**이다)_

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5a51d272-2494-4f86-9327-70ac65e6e6a8">
</p>

`ssh`로 붙은 이후 앱을 실행하고 `ps -ef | grep /var`를 입력하게 되면 사용중인 바이너리의 위치를 확인할 수 있다.

해당 파일을 **WinSCP**를 통해 PC로 이동시켜 **Ghidra**나 **IDA, Hopper**를 통해 분석을 진행하면 된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/bcef6853-0491-45db-a188-96fbc9f77df2">
</p>

IDA를 통해 진행할 경우 `Shift + F12` 단축키를 이용하여 Strings 검색이 가능하다.

앱에서 확인된 **I love Google** string을 검색하면 어느 부분에서 호출하는지 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/d9f1e722-f8b8-467c-97cd-b4dd5345d222">
</p>

IDA에서 해당 Hex 값을 포커싱한 다음 **Edit > Patching Program > Change Bytes**를 통해 Google을 표기하기 위한 기본 값인 `47 6F 6F 67 6C 65`의 Hex 값을 Apple에 맞춰 `41 70 70 6C 65 00`으로 변경한다.

이후 **Edit > Patching Program > Apply patches to input file**을 이용하여 패치된 `DVIA-v2` 바이너리를 생성한다.

**Apple** 다섯 글자이지만 마지막 `00`을 넣은 이유는 해당 바이너리의 크기는 정해져있지만 1byte라도 오차가 발생하는 경우 참조하고자 했던 다른 메모리에 대한 주소가 변경되기에 byte를 넘기지도 모라지도 않게 수정해야된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/13efdeee-e8a7-4691-bd57-0a086d2fb2dd" width = 450>
</p>


## 대응 방안

* 프로그램 및 어플리케이션의 위변조를 탐지하기 위한 무결성 검증을 진행하는 솔루션을 도입한다.

## References

* [https://armconverter.com/](https://armconverter.com/)