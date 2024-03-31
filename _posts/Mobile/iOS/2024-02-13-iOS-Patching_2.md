---
layout: post
title: iOS DVIA-v2 | Application Patching (Jailbreak)
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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/d4396d69-47af-41f3-9700-9817203122bd">
</p>

**Application Patching**에 Login Method 1를 포함한 4개의 버튼이 보이는데 이번엔 Check For Jalibreak를 진행한다.

**Check For Jalibreak**를 클릭하는 경우 **Device is Jailbroken**와 같이 Jalibreak가 탐지된 것을 알 수 있다.

### UI Dump

```Javascript
// 사용중인 UI 리스트

var colors = {
    "reset" : "\x1b[0m",
    "red" : "\x1b[31m",
    "green" : "\x1b[32m",
    "yellow" : "\x1b[33m",
    "blue" : "\x1b[34m"
}

var window = ObjC.classes.UIWindow.keyWindow();
var rootControl = window.rootViewController();

var ui = window.recursiveDescription().toString();
var ui_autolayout = window['- _autolayoutTrace']().toString();
var control = rootControl['- _printHierarchy']().toString();

console.log(colors.green + control + colors.reset); 
```

* **현재 사용 중인 앱의 UI 내용 출력 코드**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/b4bf2068-da02-4e65-9fda-7f8f078b291b">
</p>

`frida -U -f com.highaltitudehacks.DVIAswiftv2 -l .\Hook\iOS\1_Ui_dump.js`로 해당 코드를 실행하게 되면 처음에는 어떠한 값을 받아오지 못하지만 원하는 Ui로 이동 후 해당 코드에서 `Ctrl + S` 저장하게 되면 해당 Ui에서 다시 한 번 코드가 실행되게 된다.

그 때 위 처럼 초록색으로 어떠한 Ui로 실행되고 있는지 확인할 수 있다. 로그인 View에서 사용중인 Ui는 `DIVA_v2.RuntimeManipualtionDetailsViewController`임을 알 수 있다.

### Method Dump in UI

```Javascript
// 해당 클래스 내에 메소드 리스트 출력

let colors = {
    "reset" : "\x1b[0m",
    "red" : "\x1b[31m",
    "green" : "\x1b[32m",
    "yellow" : "\x1b[33m",
    "blue" : "\x1b[34m"
}

if (ObjC.available) {
    try {
        var className = "DVIA_v2.RuntimeManipualtionDetailsViewController";    // 찾고 싶은 class 이름으로 변경
        var methods = ObjC.classes[className].$ownMethods;
  
        console.warn("\n[*] Started: Find All Methods of a class " + '"' + className + '"');
        
        for (var i = 0; i < methods.length; i++) {
            try { console.log("\x1b[32m"+methods[i] + "\x1b[0m"); }
            catch(err) { console.log("[!] Exception1: " + err.message); }
        }}
    catch(err) { console.log("[!] Exception2: " + err.message); } }
  
  else { console.log("Objective-C Runtime is not available!"); }
  
  console.warn("[*] Completed: Find All Methods of a Class " + '"' + className + '"');
```

* **현재 UI에서 사용중인 메소드 출력 코드**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/94ae1ea1-6e0e-4356-9729-138b545d0e9f">
</p>

`frida -U -f com.highaltitudehacks.DVIAswiftv2 -l .\Hook\iOS\2_Method_dump.js`로 해당 코드를 실행하게 되면 해당 클래스에서 사용중인 모든 메소드가 나오게 되는데 `Check For Jalibreak` 버튼을 눌렀을 때 실행될 것으로 추측되는 메소드 `- jailbreakTestTapped:`를 확인할 수 있다.

### 메소드 분석

iOS에서 앱을 실행할 때는 **앱의 Binary** 자체가 실행되고 있다. 따라서 분석하기 위해서는 `ipa` 파일이 아닌 `Binary` 파일을 찾아서 분석해야한다.

단말기와 PC를 같은 네트워크에 연결하고 단말기 네트워크 IP를 통해 **SSH** 붙어서 실행중인 바이너리를 검색한다._(탈옥 후 기본 ROOT 패스워드는 **alpine**이다)_

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5a51d272-2494-4f86-9327-70ac65e6e6a8">
</p>

`ssh`로 붙은 이후 앱을 실행하고 `ps -ef | grep /var`를 입력하게 되면 사용중인 바이너리의 위치를 확인할 수 있다.

해당 파일을 **WinSCP**를 통해 PC로 이동시켜 **Ghidra**나 **IDA, Hopper**를 통해 분석을 진행하면 된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/a1c90b09-cf06-41e5-861c-d9960d4eb6cd">
</p>

확인된 메소드 `- jailbreakTestTapped:`에 대한 분석을 위해 IDA 프로그램으로 확인한 결과 이동할 분기로는 `_T07DVIA_v240ApplicationPatchingDetailsViewControllerC19jailbreakTestTappedyypF`를 제외한 중요한 분기는 보이지 않는다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/b6914394-6fa7-4036-bf8a-8719a2aa26e4">
</p>

해당 분기를 확인하면 위와 같이 `selRef_isJailbroken`이라는 클래스 메소드를 `objc_msgSend`를 통해 실행하게 된다.

`selRef_isJailbroken` 클래스 메소드를 확인해보면 무수히 많은 분기로 이루어져있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/590b6ca4-a8d2-4452-acb6-9f60e0de7440">
</p>

모든 분기는 `loc_10016D720`를 만나게 되며 아래의 어셈블리를 거치게 된다.

```armasm
LDURB           W8, [X29,#var_1]
AND             W8, W8, #1
AND             W0, W8, #1
```

* `LDURB W8, [X29,#var_1]` : `X29` 레지스터에서 **#var_1** 바이트를 `X29`에 저장

* `AND W8, W8, #1` : `W8` 레지스터와 `1`을 `AND` 연산하여 `W8`에 저장

* `AND W0, W8, #1` : `W8` 레지스터와 `1`을 `AND` 연산하여 `W0`에 저장

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/991f19ba-9201-48fe-a57d-ad331d5f2bfa">
</p>

해당 분기를 확인한 결과 Jailbreak 탐지 되었을 때의 `W8`의 값을 **0x1**이며 `register write w8 0x0`로 `W8`의 값을 임의로 변경하여 실행한 경우 Jailbreak 탐지가 되지 않았다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/e17a9e60-2b97-46e2-8ac7-21255c253d4d">
</p>

결국 `0x104d05724 and w8, w8, #0x1`에서 **w8**의 **1** 값과 **#0x1**의 AND 결과 값이 `1`이 되므로 AND의 반대 연산인 **XOR**로 패치한다. ARM64에서는 XOR 대신 `EOR`이라는 연산자를 통해 **XOR** 연산을 진행한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/65d415f3-e218-46f0-bd5a-bb3612b7c906">
</p>

IDA에서 해당 Hex 값을 포커싱한 다음 **Edit > Patching Program > Change Bytes**를 통해 기존 AND의 해당 값인 **12**를  EOR 연산자의 값 **52**로 변경하고 **Edit > Patching Program > Apply patches to input file**을 이용하여 패치된 `DVIA-v2` 바이너리를 생성한다.

해당 바이너리를 `WinSCP` 프로그램을 통해 위에서 설명한 [메소드 분석](#메소드-분석)처럼 원래 있던 바이너리를 덮어 씌운다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/e4fa6e5a-96e0-4ed2-927a-b4e31645f01a" width = 450>
</p>

덮어 씌운 이후 앱을 종료하고 재실행하여 아무런 값을 입력하고 **Login Method 1** 클릭 시 **SUCCESS**가 나오면서 패치가 된 것을 알 수 있다.


## 대응 방안

* 프로그램 및 어플리케이션의 위변조를 탐지하기 위한 무결성 검증을 진행하는 솔루션을 도입한다.

## References

* [https://armconverter.com/](https://armconverter.com/)