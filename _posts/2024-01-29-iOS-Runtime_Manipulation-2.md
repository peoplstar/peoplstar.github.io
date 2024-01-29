---
layout: post
title: iOS DVIA-v2 | Runtime Manipulation - 2
subtitle: 런타임 조작 취약점
categories: iOS
tags: [iOS, Moblie]
---

## 취약점 개요

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/c535174a-2c44-4fe7-8f6a-0223a01848d8">
</p>

**런타임 조작 취약점**이란 어플리케이션이 실행될 때 모든 실행 로직 및 정보는 메모리에 올라가있다. 이 때 메모리의 값을 조작하여 함수의 흐름을 조작하거나 정보 유출이 가능하게 되는 취약점이다.

이를 통해 인스턴스 변수 수정, 로컬 로그인 검사 우회, 강제 핀 코드 사용이 가능하며 데이터를 조작함으로써 비즈니스 프로세스, 조직의 이해 및 의사 결정에 영향을 미치려고 시도할 수 있다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Runtime Manipulation**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5c61b39f-6fd0-47bb-ae0f-51431ce54834">
</p>

아이디와 패스워드를 입력하고 `Login Method 2`을 클릭하면 **Incorrect Username or Password**으로 옳지 않은 아이디, 패스워드임을 알려주고 있다. 어떤 아이디와 패스워드가 와도 옳은 방법을 내보기 위해 해당 함수의 `Return` 혹은 `Branch`를 변경해주면 된다. (`3utools`을 이용한 스크린샷은 패스워드 입력을 하지 않는 것처럼 나온다.)

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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/a216de37-f565-45d4-a945-c6e109facce0">
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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/245aaf35-5009-4d01-8e15-6d7389809b48">
</p>

`frida -U -f com.highaltitudehacks.DVIAswiftv2 -l .\Hook\iOS\2_Method_dump.js`로 해당 코드를 실행하게 되면 해당 클래스에서 사용중인 모든 메소드가 나오게 되는데 `Login Method 2` 버튼을 눌렀을 때 실행될 것으로 추측되는 메소드 `- loginMethod2Tapped:`를 확인할 수 있다.

### 메소드 분석

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/cdb0e125-32af-441e-a5cb-2d5be88b2d9c">
</p>

확인된 메소드 `- loginMethod2Tapped:`에 대한 분석을 위해 IDA 프로그램으로 확인한 결과 이동할 분기로는 `_T07DVIA_v240RuntimeManipulationDetailsViewControllerC18loginMethod2TappedyypF`를 제외한 중요한 분기는 보이지 않는다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/7abcca1f-804c-4d67-8667-46abb069d4ff">
</p>

추가로 확인된 분기를 확인한 결과 `Offset 00000001001BDED4 TBZ W8, #0, loc_1001BDF94`에서 **W8** 레지스터가 0과 같은 경우 `loc_1001BDF94`로 이동하면 **Oops**를 출력하며 로그인 실패, **W8** 레지스터가 0과 다른 경우 **You have successfully bypassed the auth**를 출력하며 로그인이 성공한 분기로 이동하는 것을 확인할 수 있다.

### Frida Code

```javascript
let colors = {
    "reset" : "\x1b[0m",
    "red" : "\x1b[31m",
    "green" : "\x1b[32m",
    "yellow" : "\x1b[33m",
    "blue" : "\x1b[34m"
}

if (ObjC.available) {
    var module_base = Module.findBaseAddress("DVIA-v2"); // get base addr > App Name
    console.log(colors.red, "[*] module_base : " + module_base, colors.reset);

    var custom_0x1BDED4 = module_base.add(0x1BDED4); // add function offset
    console.log(colors.red, "[*] custom_0x1BDED4 : " + custom_0x1BDED4, colors.reset);

    Interceptor.attach(custom_0x1BDED4, {
        onEnter: function (args) {
            console.log(colors.green, "\n [+] Register x8 : " + JSON.stringify(this.context.x8));
            this.context.x8 = 0x1;
            console.log(colors.green, "[+] Change x8 : " + JSON.stringify(this.context.x8) + "\n");
        }
    });
}
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/a7437488-328c-43cc-8ac3-69f539b72c60">
</p>

로그인 성공 여부를 판단하는 `x8` 레지스터의 값이 정상적으로 변경되는 것을 확인할 수 있고

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/2ef46497-5630-41ba-b6c1-87bc45b232cc" width = 450>
</p>

어떠한 값을 넣고 `Login Method 2` 버튼 클릭 시 로그인이 성공하는 것을 확인할 수 있다.

## 대응 방안

* 디버깅 차단

    * **Using ptrace** : **PT_DENY_ATTACH**를 사용한 안티 디버깅

    * **Using sysctl** : `sysctl`을 호출하여 반환된 **info.kp_proc.p_flag**플래그 확인

    * **Using getppid** : 일반적인 어플리케이션의 경우 사용자 모드에서 Launched Process에 의해 실행되면 `PID`가 1, 디버거에 의해 실행되는 경우 `getppid`가 1이 아닌 다른 값
    
* `Frida`를 이용한 런타임 조작이 대중적이기에 Frida 자체 차단

    * **Frida Binary**

    * **Frida Sever Port** : 27042 포트 사용 확인

    * **Frida D-Bus**

    * **Frida Library** : 타겟 프로세스에 주입된 Frida-agent Library file 확인

    * **Frida Thread**

    * **Frida Hook** : Frida가 사용하는 Hook 방식인 Inline Hook 탐지

* 런타임 조작은 단순히 `Frida`를 이용할 뿐만 아니라 디버깅 과정에서도 조작이 가능하기에 디버깅을 차단

## Reference

* [https://attack.mitre.org/techniques/T1565/003/](https://attack.mitre.org/techniques/T1565/003/)

