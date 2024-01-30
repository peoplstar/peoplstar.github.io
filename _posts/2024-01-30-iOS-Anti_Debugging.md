---
layout: post
title: iOS DVIA-v2 | Anti Debugging
subtitle: 안티 디버그 취약점
categories: iOS
tags: [iOS, Moblie]
---

## 취약점 개요

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/88ab5b83-18f3-4ebd-8679-df85180b7128">
</p>

**앱 안티 디버깅**은 특정 모바일 앱의 디버깅을 감지하고 방지하기 위한 기술 및 메커니즘의 사용을 의미합니다. 앱을 디버깅하면 실행 중 동작을 분석하고 이해할 수 있으므로 문제 해결, 테스트 및 리버스 엔지니어링 목적에 도움이 될 수 있습니다. 그러나 공격자가 앱의 코드와 동작을 분석하여 취약성을 발견하거나 중요한 데이터를 훔치거나 익스플로잇을 개발하는 데 사용할 수도 있습니다.

앱 디버깅을 방지하기 위해 앱 개발자는 코드 난독화, 함수 포인터 조작, 중단점 감지 및 제어 흐름 난독화와 같은 다양한 디버깅 방지 기술을 구현할 수 있습니다. 이러한 기술은 공격자가 앱의 코드와 동작을 이해하기 어렵게 만들 수 있으므로 성공적인 공격을 개발하는 데 필요한 시간과 노력이 증가합니다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Anti Hooking/Debugging**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/a91af4a7-a1f9-4ce3-9efc-a7acf2f24a5b">
</p>

해당 앱은 기본적으로 디버깅 탐지를 하지 않았기에 `lldb`로 디버깅이 가능하였다. 하지만 **Disable Debugging** 버튼을 클릭하면 디버깅 보호 기법이 적용되었다고 나오게 된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5e1cfb22-3485-4938-9862-2a09744095ce">
</p>

디버깅 보호 기법이 적용된 상태에서 `lldb`로 디버깅을 시도하게 되면 **attach failed**로 디버깅이 불가능할 것을 알 수 있다.

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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/cb444b0d-823a-4304-a57e-3a37b455b952">
</p>

`frida -U -f com.highaltitudehacks.DVIAswiftv2 -l .\Hook\iOS\1_Ui_dump.js`로 해당 코드를 실행하게 되면 처음에는 어떠한 값을 받아오지 못하지만 원하는 Ui로 이동 후 해당 코드에서 `Ctrl + S` 저장하게 되면 해당 Ui에서 다시 한 번 코드가 실행되게 된다.

그 때 위 처럼 초록색으로 어떠한 Ui로 실행되고 있는지 확인할 수 있다. 코드 인증 View에서 사용중인 Ui는 `DIVA_v2.AntiAntiHookingDebuggingViewController`임을 알 수 있다.

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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/59bfe9fc-c0f0-4f24-bb8d-18a4579e644b">
</p>

`frida -U -f com.highaltitudehacks.DVIAswiftv2 -l .\Hook\iOS\2_Method_dump.js`로 해당 코드를 실행하게 되면 해당 클래스에서 사용중인 모든 메소드가 나오게 되는데 `Disable Debugging` 버튼을 눌렀을 때 실행될 것으로 추측되는 메소드 `- disableDeubbingTapped:`를 확인할 수 있다.

### 메소드 분석

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/0d33a6f8-7fc7-44af-b467-8fee5025aa84">
</p>

확인된 메소드 `- disableDeubbingTapped:`에 대한 분석을 위해 IDA 프로그램으로 확인한 결과 이동할 분기로는 `_T07DVIA_v204AntiC30HookingDebuggingViewControllerC07disableE6TappedyypF`를 제외한 중요한 분기는 보이지 않는다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/c9556a27-6005-4206-97a5-6e5104dd2f17">
</p>

해당 분기로 이동하면 `_disable_gdb`라는 분기로 이동하는 포인트가 존재한다. `gdb`란 GNU Debugger의 약자로 GNU 소프트웨어 시스템을 위한 기본 디버거다. gdb는 다양한 유닉스 기반의 시스템에서 동작하는 디버거로 이것을 **disable**한다는 것은 Anti Debugging을 진행한다는 것이기에 이 분기를 확인해볼 필요가 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/4cc05078-c5f2-45a4-ad0a-7be2ca4f5565">
</p>

* **RED** : **EXPORT**로 외부 라이브러리에서 하여 사용 가능하게 함수 공유

* **ORANGE** : `ptrace`라는 함수 주소 호출

* **YELLOW** : `W9` 레지스터에 **0x1f** 값 대입

`disable_gdb`를 통해 `ptrace` 함수를 호출하는 것을 확인하였다. `ptrace`는 *process trace*의 축약형으로 컨트롤러가 대상의 내부 상태를 조사하고 조작하게 함으로써, 한 프로세스가 다른 프로세스를 제어한다.

```c
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
```

첫번째의 파라미터 값을 통해 프로세스의 속성을 변경할 수 있고 안티 디버깅을 적용할 수 있다.

```C
#define	PT_TRACE_ME	0	/* child declares it's being traced */
#define	PT_READ_I	1	/* read word in child's I space */
#define	PT_READ_D	2	/* read word in child's D space */
#define	PT_READ_U	3	/* read word in child's user structure */
#define	PT_WRITE_I	4	/* write word in child's I space */
#define	PT_WRITE_D	5	/* write word in child's D space */
#define	PT_WRITE_U	6	/* write word in child's user structure */
#define	PT_CONTINUE	7	/* continue the child */
#define	PT_KILL		8	/* kill the child process */
#define	PT_STEP		9	/* single step the child */
#define	PT_ATTACH	10	/* trace some running process */
#define	PT_DETACH	11	/* stop tracing a process */
#define	PT_SIGEXC	12	/* signals as exceptions for current_proc */
#define PT_THUPDATE	13	/* signal for thread# */
#define PT_ATTACHEXC	14	/* attach to running process with signal exception */
#define	PT_FORCEQUOTA	30	/* Enforce quota for root */
#define	PT_DENY_ATTACH	31
#define	PT_FIRSTMACH	32	/* for machine-specific requests */
```

IDA를 본 `ptrace` 함수에서도 `MOV W9, #0x1F`로 0x1F 즉 **31**의 값을 통해 파라미터를 전달하고 있는 것을 알 수 있다. 해당 값은 **PT_DENY_ATTACH**로 프로세스에 Attach 되는 것을 막고 있다. 

W9 레지스터에 31의 값이 아닌 **PT_ATTACH 10**의 값을 넣게 된다면 프로세스가 돌아가는 와중에도 Attach가 가능하다.

```javascript
let colors = {
    "reset" : "\x1b[0m",
    "red" : "\x1b[31m",
    "green" : "\x1b[32m",
    "yellow" : "\x1b[33m",
    "blue" : "\x1b[34m"
}

Thread.sleep(3); // 앱 실행과 동시에 디버거 탐지로 인해 sleep 설정하여 frida attach

if (ObjC.available) {
    Interceptor.attach(Module.findExportByName(null, "ptrace"), {
        onEnter: function (args) { // Print debug ptrace arguments
            console.log(colors.green, "\n [ptrace] " + args[0] + " " + args[1] + " " + args[2] + " " + args[3]);
            console.log(colors.red, "[*] " + JSON.stringify(this.context))
        },
        onLeave: function (retval) {
            console.log(colors.blue, "[*] retval : " + retval);
        }
    });
}
```

Frida 코드를 이용하여 현재까지 진행한 내용의 결과가 어떻게 출력되는지 확인해본다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/457d30cb-420d-49e8-b672-4ea2cbb0d01a">
</p>

IDA로 분석한 결과 **arm64의 레지스터는 X부터 시작하기에** `X9` 레지스터의 값이 Attach를 못 하게 하는 파라미터 값 **0x1f**로 된 것을 알 수 있다.

### Frida Code

```javascript
let colors = {
    "reset" : "\x1b[0m",
    "red" : "\x1b[31m",
    "green" : "\x1b[32m",
    "yellow" : "\x1b[33m",
    "blue" : "\x1b[34m"
}

Thread.sleep(3); // 앱 실행과 동시에 디버거 탐지로 인해 sleep 설정하여 frida attach

if (ObjC.available) {
    Interceptor.attach(Module.findExportByName(null, "ptrace"), {
        onEnter: function (args) {  // Modify Debug attach mode
            console.log(colors.green, "\n [*] ptrace args : " + args[0] + " " + args[1] + " " + args[2] + " " + args[3]);
            if (args[0] == 0x1f) {
                args[0] = ptr("0xA");
            }
        },
        onLeave: function (retval) {
            console.log(colors.blue, "[*] retval : " + retval);
        }
    });
}
```

해당 코드로 첫번째 파라미터의 값이 **0x1f**가 아닌 **0xA**로 변경하여 진행하게 되면 아래와 같이 안티 디버그를 우회하여 디버깅이 가능하다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/c973c65f-fcf6-497f-a115-708e7db15bc3">
</p>

## 대응 방안

* **Using ptrace** : **PT_DENY_ATTACH**를 사용한 안티 디버깅

* **Using sysctl** : `sysctl`을 호출하여 반환된 **info.kp_proc.p_flag**플래그 확인

* **Using getppid** : 일반적인 어플리케이션의 경우 사용자 모드에서 Launched Process에 의해 실행되면 `PID`가 1, 디버거에 의해 실행되는 경우 `getppid`가 1이 아닌 다른 값

## Reference

* [https://ko.wikipedia.org/wiki/GNU_%EB%94%94%EB%B2%84%EA%B1%B0](https://ko.wikipedia.org/wiki/GNU_%EB%94%94%EB%B2%84%EA%B1%B0)

* [https://ko.wikipedia.org/wiki/Ptrace](https://ko.wikipedia.org/wiki/Ptrace)

* [https://mobile-security.gitbook.io/mobile-security-testing-guide/ios-testing-guide/0x06j-testing-resiliency-against-reverse-engineering#anti-debugging-detection](https://mobile-security.gitbook.io/mobile-security-testing-guide/ios-testing-guide/0x06j-testing-resiliency-against-reverse-engineering#anti-debugging-detection)