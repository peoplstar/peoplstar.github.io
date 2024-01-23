---
layout: post
title: iOS DVIA-v2 | JailBreak Detection - 3
subtitle: 탈옥 탐지 우회 - 3
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
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/7f59bf9f-1244-4432-90c5-5d909ad74b83" width = 450>
</p>

**Jailbreak Test 3** 버튼 클릭 시 다음과 같이 `Device is Jailbroken, the application will now exit`으로 탈옥 감지 되었음을 Alert이 발생한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/fb283735-082f-41ff-a0d8-dfc8b4543bd8">
</p>

앱에서 해당 String을 검색하여 어느 부분에서 해당 String을 이용하는지 확인한다. 확인 결과 `JailbreakDetectionViewController.jailbreakTest3()`에서 호출되는 것을 알 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/12160a08-2709-4457-818f-f94f0e3ff8ba">
</p>

빨간 네모 부분이 Jailbreak 탐지 되었을 경우이며 주황 네모 부분이 Jailbreak 탐지가 안 되었을 때의 분기인 것을 알 수 있다. 이후 분기의 기준을 보면 다음과 같다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/6eaebd8e-5382-4e24-910d-2c713f2ba4c8">
</p>

`offset 1001959DC TBZ W8, #0, loc_100195DA8`로 `W8`의 레지스터 값이 0과 같으면 이면 `loc_100195DA8`로 이동하는데 해당 분기는 Jailbreak 탐지가 되지 않았을 경우다. 즉 Jailbreak 탐지 시 `W0` 레지스터의 값을 **1**이 될 것이고 탐지 되지 않은 경우 **0**이 될 것이다.

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

    var custom_0x1959DC = module_base.add(0x1959DC); // add function offset
    console.log(colors.red, "[*] custom_0x1959C4 : " + custom_0x1959DC, colors.reset);

    Interceptor.attach(custom_0x1959DC, {
        onEnter: function (args) {
            console.log(colors.green, "\n [+] Register\n " + JSON.stringify(this.context) + "\n");
            this.context.x8 = 0x0;
            console.log(colors.green, "[+] Register\n" + JSON.stringify(this.context) + "\n");
        },
    });
}
```
<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/2acc22c2-fe8c-440e-9cac-8ad5f8e89d5d">
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