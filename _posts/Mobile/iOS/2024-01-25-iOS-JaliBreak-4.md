---
layout: post
title: iOS DVIA-v2 | JailBreak Detection - 4
subtitle: 탈옥 탐지 우회 - 4
categories: iOS
tags: [iOS, Moblie]
---

## 취약점 개요

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/3750218b-f110-4233-9c3a-c4ce0b44e67f">
</p>

**iOS 운영체제 탈옥**이란, 유닉스(Unix)로 만들어진 iOS의 샌드박스 제한을 풀어서, 임의로 시스템 상의 코드를 수정하거나 번경하는 행위를 말합니다. **즉 iOS 운영체제의 제한을 풀어서 사용자가 기능을 추가하거나, 숨겨진 기능을 불러온다는 것입니다.**

탈옥은 일반적으로 iOS 운영 체제의 보안 취약점을 악용하여 보안 조치를 우회하여 사용자가 일반적으로 제한되는 시스템 파일 및 설정에 액세스할 수 있도록 합니다. 장치가 탈옥되면 사용자는 타사 소스에서 앱을 설치하고, 장치의 모양과 기능을 사용자 지정하고, 사전 설치된 앱 및 Apple에서 부과한 기타 제한 사항을 제거할 수 있습니다.

탈옥은 더 넓은 범위의 앱에 대한 액세스 및 조정, 개인 취향에 맞게 장치를 사용자 정의하는 기능, 탈옥되지 않은 장치에서는 불가능한 고급 작업을 수행하는 기능과 같은 여러 가지 이점을 제공할 수 있습니다.

탈옥은 잠재적으로 악성 앱이 장치에 설치되도록 허용하고 운영 체제의 보안 및 안정성을 손상시킬 수 있고 **루트 권한**으로 해당 APP을 공격할 수 있는 가능성이 존재하여 악의적인 사용자에 의해 제작자의 의도와 다르게 수정, 조작될 수 있습니다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Jailbreak Detection**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/c18ed7f6-b20e-4977-9ad8-8dd42341f14d" width = 450>
</p>

**Jailbreak Test 4** 버튼 클릭 시 다음과 같이 `Device is Jailbroken, Exiting !`으로 탈옥 감지 되었음을 Alert이 발생하고 잠시 후 앱이 종료된다.

### Frida-trace

`Jailbreak` 관련 클래스명과 함수명을 찾기 위해 `frida-trace`와 `-m` 파라미터를 두 번 입력하여 해당 `jail` String이 포함된 클래스 및 메소드가 호출되는지 파악한다.

```
frida-trace -U -f com.highaltitudehack.DVIAswiftv2 -m "*[* *jail*]" -m "*[* *jail*]"
```

* **Objective-C**의 경우 함수 표현 방식이 다른 언어와는 차별점이 있기에 아래 내용을 숙지해야 한다.

    * `+[Class Method]` : 해당 메소드는 클래스에 대한 메소드

    * `-[Class Method]` : 해당 메소드는 인스턴스에 대한 메소드

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/4874712a-cc34-4212-a3fc-5d0169f61371">
</p>

`jailbreaTest1Tapped`을 비롯한 `jailbreaTest5Tapped`까지 모두 확인되고 `Jailbreak Test4` 클릭 시 `-[DVIA_v2.JailbreakdDetectionViewController jailbreakTest4Tapped:0x1048d2d00]`함수가 호출되는 것을 확인할 수 있다.

iOS에서 앱을 실행할 때는 **앱의 Binary** 자체가 실행되고 있다. 따라서 분석하기 위해서는 `ipa` 파일이 아닌 `Binary` 파일을 찾아서 분석해야한다.

단말기와 PC를 같은 네트워크에 연결하고 단말기 네트워크 IP를 통해 **SSH** 붙어서 실행중인 바이너리를 검색한다._(탈옥 후 기본 ROOT 패스워드는 **alpine**이다)_

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5a51d272-2494-4f86-9327-70ac65e6e6a8">
</p>

`ssh`로 붙은 이후 앱을 실행하고 `ps -ef | grep /var`를 입력하게 되면 사용중인 바이너리의 위치를 확인할 수 있다.

해당 파일을 **WinSCP**를 통해 PC로 이동시켜 **Ghidra**나 **IDA, Hopper**를 통해 분석을 진행하면 된다.


<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/3170c435-c561-4e3a-8b8a-fa949512ee49">
</p>

해당 함수로 이동하여 호출 분기에서 의심되는 부분은 `jailbreatkTest4TappedyypF`만이 존재한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/af8e4796-144d-4810-99fd-5474b505f3b5">
</p>

`jailbreatkTest4TappedyypF`에는 많은 분기가 존재 하는데 분기를 따라가보면 `loc_1001936DC`를 분기에서 Jailbreak의 여부에 따른 탐지가 되었는지 되지 않았는지 판단하는 것을 알 수 있다.

`offset 1001936E4 TBZ W8, #0, loc_100193B70` W8 레지스터의 값이 0과 같으면 `Not Jailbroken`이기에 W8의 레지스터 값을 `0`이 되게 만들면 탈옥 탐지 우회가 가능하다.

### Frida Code

```javascript
var colors = {
    "reset" : "\x1b[0m",
    "red" : "\x1b[31m",
    "green" : "\x1b[32m",
    "yellow" : "\x1b[33m",
    "blue" : "\x1b[34m"
}

if (ObjC.available) {
    var module_base = Module.findBaseAddress("DVIA-v2"); // get base addr
    console.log(colors.red, "[*] module_base : " + module_base, colors.reset);

    var custom_0x1936E4 = module_base.add(0x1936E4); // add function offset
    console.log(colors.red, "[*] custom_0x1936E4 : " + custom_0x1936E4, colors.reset);

    Interceptor.attach(custom_0x1936E4, {
        onEnter: function (args) {
            console.log(colors.green, "\n [+] Register x8 : " + JSON.stringify(this.context.x8));
            this.context.x8 = 0x0;
            console.log(colors.green, "\n [+] Change x8 : " + JSON.stringify(this.context.x8) + "\n");
        },
    });
}
```
<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/df7f07b5-34a6-492f-98a3-a4f5eddf5831">
</p>

Jailbreak 여부를 판단하는 `x8` 레지스터의 값이 정상적으로 변경되는 것을 확인할 수 있고

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/8d549e83-1491-4337-96af-b1713224c034" width = 450>
</p>

버튼 클릭 시 Jailbreak 탐지가 되지 않을 것을 알 수 있다.

## 대응 방안

* **특정 파일 및 디렉토리 존재 파악**

```objectivec
static var suspiciousAppsPathToCheck: [String] {
    return ["/Applications/Cydia.app",
            "/Applications/blackra1n.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app"
    ]
}

static func isContainsSuspiciousApps() -> Bool {
    for path in suspiciousAppsPathToCheck {
        if FileManager.default.fileExists(atPath: path) {
            return true     // Device is jailbroken
        }
    }
    return false            // Device is not jailbroken
}
```

* **딥링크 API를 통한 Tweak 파악**

```objectivec 
if UIApplication.shared.canOpenURL(URL(string: "cydia://package/com.example.package")!) {
    // Device is jailbroken
} else {
    // Device is not jailbroken
}
```

* **Tweak 관련 경로 확인**

```objectivec
static var suspiciousSystemPathsToCheck: [String] {
    return ["/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/private/var/lib/apt",
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/bin/bash",
            "/Library/MobileSubstrate/MobileSubstrate.dylib"
    ]
}

static func isSuspiciousSystemPathsExists() -> Bool {
    for path in suspiciousSystemPathsToCheck {
        if FileManager.default.fileExists(atPath: path) {
            return true    // Device is jailbroken
        }
    }
    return false           // Device is not jailbroken
}
```

## Reference

* [https://github.com/Nikilicious09/Preventing-Jailbreak-in-iOS/blob/main/SecurityUtils.swift?source=post_page-----c1364c833c08--------------------------------](https://github.com/Nikilicious09/Preventing-Jailbreak-in-iOS/blob/main/SecurityUtils.swift?source=post_page-----c1364c833c08--------------------------------)