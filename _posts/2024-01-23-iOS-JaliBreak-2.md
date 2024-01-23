---
layout: post
title: iOS DVIA-v2 | JailBreak Detection - 2
subtitle: 탈옥 탐지 우회 - 2
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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/9a288675-f6d3-4348-a8f9-d48edc109a7a" width = 450>
</p>

**Jailbreak Test 2** 버튼 클릭 시 다음과 같이 `Device is Jailbroken`으로 탈옥 감지 되었음을 Alert이 발생한다.

### Frida-trace

`Jailbreak` 관련 클래스명과 함수명을 찾기 위해 `frida-trace`와 `-m` 파라미터를 두 번 입력하여 해당 `jail` String이 포함된 클래스 및 메소드가 호출되는지 파악한다.

```
frida-trace -U -f com.highaltitudehack.DVIAswiftv2 -m "*[* *jail*]" -m "*[* *jail*]"
```

* **Objective-C**의 경우 함수 표현 방식이 다른 언어와는 차별점이 있기에 아래 내용을 숙지해야 한다.

    * `+[Class Method]` : 해당 메소드는 클래스에 대한 메소드

    * `-[Class Method]` : 해당 메소드는 인스턴스에 대한 메소드

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5176f19c-8396-4b10-b2fe-811d2cd80c12">
</p>

현재 `jailbreaTest1Tapped`을 비롯한 `jailbreaTest5Tapped`까지 모두 확인되고 `Jailbreak Test2` 클릭 시 `+[JailbreakDetection isJailbroken]`이 호출되는 것을 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/f4a1675a-4fbe-48a1-aa12-e6399ac0f848">
</p>

IDA를 통해 해당 함수를 확인한 결과 여러 분기가 있으며 각 분기는 `classRef_NSFileManager`를 호출하여 디렉토리에 **Jailbreak**로 의심되는 디렉토리 및 파일이 존재하는지 검사하는 로직이다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5429a645-0116-400c-877c-9b58edea0eb1">
</p>

해당 함수의 Return Type을 확인해보면 `Bool`이기에 함수가 호출되고 Return할 때 Return 값을 변경하게 되면 Jailbreak가 탐지 되지 않은 것처럼 조작이 가능하다.

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

    var custom_0x16D2D8 = module_base.add(0x16D2D8); // add function offset
    console.log(colors.red, "[*] custom_0x16D2D8 : " + custom_0x16D2D8, colors.reset);

    Interceptor.attach(custom_0x16D2D8, {
        onEnter: function (args) {
        },

        onLeave: function (retval) { // method return 변경을 위한 함수 나갈 때를 의미하는 onLeave 사용
            retval.replace(0x0);
            console.log(colors.green, " [+] JailbreakDetection Bypass");
        }
    });
}
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/719aa9a7-ce43-44df-890c-2b59a923b5a9" width = 450>
</p>

`onLeave`를 통해 해당 함수가 return 될 때의 값을 변경하여 실행하게 되면 위와 같이 **Jailbreak Test2** 버튼 클릭 시 탈옥 탐지를 우회할 수 있다.

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