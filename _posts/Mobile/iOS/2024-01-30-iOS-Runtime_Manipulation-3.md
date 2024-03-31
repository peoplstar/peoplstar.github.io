---
layout: post
title: iOS DVIA-v2 | Runtime Manipulation - 3
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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/ae24e9f5-2d63-4ed7-8d3f-41e60265742f">
</p>

**Enter correct 5 digit numberic code**에 임의의 값을 넣고 `Validate code`를 클릭하게 되면 입력한 코드와 함께 옳지 않은 코드라 에러가 발생하게 되는 것을 알 수 있다. 해당 코드는 Brute Force 기법을 이용하여 해결하라고 명시했기에 모든 값을 넣어 비교 하는 코드를 작성하면 된다.

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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/82ed9c23-f325-4e6d-82c8-20c9653f83ce">
</p>

`frida -U -f com.highaltitudehacks.DVIAswiftv2 -l .\Hook\iOS\1_Ui_dump.js`로 해당 코드를 실행하게 되면 처음에는 어떠한 값을 받아오지 못하지만 원하는 Ui로 이동 후 해당 코드에서 `Ctrl + S` 저장하게 되면 해당 Ui에서 다시 한 번 코드가 실행되게 된다.

그 때 위 처럼 초록색으로 어떠한 Ui로 실행되고 있는지 확인할 수 있다. 코드 인증 View에서 사용중인 Ui는 `DIVA_v2.RuntimeManipualtionDetailsViewController`임을 알 수 있다.

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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/be0dee00-8d08-4a3e-9643-f29fdc989313">
</p>

`frida -U -f com.highaltitudehacks.DVIAswiftv2 -l .\Hook\iOS\2_Method_dump.js`로 해당 코드를 실행하게 되면 해당 클래스에서 사용중인 모든 메소드가 나오게 되는데 `Validate Code` 버튼을 눌렀을 때 실행될 것으로 추측되는 메소드 `- validateCodeTapped:`를 확인할 수 있다.

### 메소드 분석

iOS에서 앱을 실행할 때는 **앱의 Binary** 자체가 실행되고 있다. 따라서 분석하기 위해서는 `ipa` 파일이 아닌 `Binary` 파일을 찾아서 분석해야한다.

단말기와 PC를 같은 네트워크에 연결하고 단말기 네트워크 IP를 통해 **SSH** 붙어서 실행중인 바이너리를 검색한다._(탈옥 후 기본 ROOT 패스워드는 **alpine**이다)_

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5a51d272-2494-4f86-9327-70ac65e6e6a8">
</p>

`ssh`로 붙은 이후 앱을 실행하고 `ps -ef | grep /var`를 입력하게 되면 사용중인 바이너리의 위치를 확인할 수 있다.

해당 파일을 **WinSCP**를 통해 PC로 이동시켜 **Ghidra**나 **IDA, Hopper**를 통해 분석을 진행하면 된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/f4ccdb50-237e-4f08-a8d9-ebb3664ca248">
</p>

확인된 메소드 `- validateCodeTapped:`에 대한 분석을 위해 IDA 프로그램으로 확인한 결과 이동할 분기로는 `_T07DVIA_v240RuntimeManipulationDetailsViewControllerC18validateCodeTappedyypF`를 제외한 중요한 분기는 보이지 않는다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/01725aa9-38a1-451a-a0ab-f50333cb8546">
</p>

해당 분기로 이동하면 `selRef_validateCode_viewController_`로 클래스 메소드가 호출되는 것을 알 수 있다. 해당 메소드가 어떠한 역할을 수행하는지 확인해본다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5ecd8bdc-73bf-4e9b-909d-ec2fe7b663da">
</p>

확인한 결과 `Offset 000000010015E3E0 CMP X9, X8`에서 **X8** 레지스터가 **X9**와 다른 경우 `B.NE`를 통해 `loc_10015E4F4`로 이동하며 **"%ld: Incorrect Code"** 입력한 코드 값과 옳지 않다는 에러를 발생시킨다.
**X8**과 **X9**가 같은 경우 `Offset 00010015E3E8`로 이동하고  **"Success" "8848: Congratulations, you cracked the code!"**를 출력하게 되고 여기서 기존의 코드가 8848인 것을 알 수 있게 된다.

Brute Force 기법을 사용하지 않고 분석을 통해서 코드 값을 확인할 수 있었지만 해당 문제는 Brute Force가 주 목적이기에 아래의 코드로 값을 비교하여 옳은 코드 값을 출력할 수 있다.
 
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

    var custom_0x15E3E0 = module_base.add(0x15E3E0); // add function offset
    console.log(colors.red, "[*] custom_0x15E3E0 : " + custom_0x15E3E0, colors.reset);
    
    Interceptor.attach(custom_0x15E3E0, {
        onEnter: function (args) {
            var code = parseInt(this.context.x8, 16);
            console.log(colors.green, "\n [+] Input x9 : " + code);
            console.log(colors.green, "[+] Code x8 : " + parseInt(this.context.x8, 16) + "\n");

            for (var cnt = 0; cnt < 10000; cnt++) {
                console.log(colors.yellow, "[*] Current Number : " + String(("000" + cnt).slice(-4)));

                if (code == String(("000" + cnt).slice(-4))) {
                    this.context.x9 = cnt;
                    console.log(colors.blue + " [+] Brute Force Complete : " + String(("000" + cnt).slice(-4)));
                    break;
                }
            }
        }
    });
}
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/8e773a85-4dcb-4b34-b523-a87b4ae68b27">
</p>

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

