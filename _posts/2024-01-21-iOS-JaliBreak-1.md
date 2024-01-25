---
layout: post
title: iOS DVIA-v2 | JailBreak Detection - 1
subtitle: 탈옥 탐지 우회 - 1
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

**Jailbreak Test 1** 버튼 클릭 시 다음과 같이 `Device is Jailbroken`으로 탈옥 감지 되었음을 Alert이 발생한다.

### Frida-trace

`Jailbreak` 관련 함수명을 찾기 위해 `frida-trace`를 통해 해당 `jail` String이 포함된 메소드가 호출되는지 파악한다.

```
frida-trace -U -f com.highaltitudehack.DVIAswiftv2 -m "*[* *jail*]"
```

* **Objective-C**의 경우 함수 표현 방식이 다른 언어와는 차별점이 있기에 아래 내용을 숙지해야 한다.

    * `+[Class Method]` : 해당 메소드는 클래스에 대한 메소드

    * `-[Class Method]` : 해당 메소드는 인스턴스에 대한 메소드

    * 따라서 `jail`이라는 클래스를 찾고 싶으면 아래와 같이 입력하면 된다.

    ```
    frida-trace -U -f com.highaltitudehack.DVIAswiftv2 -m "*[*jail* *]"
    ```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/c4b8280a-dab0-4b75-a037-b02ac50e0488">
</p>

현재 `jailbreaTest1Tapped`을 비롯한 `jailbreaTest5Tapped`까지 모두 확인되고 `Jailbreak Test1` 클릭 시 `-[DVIA_v2.JailbreakDetectionViewController jailbreakTest1Tapped:0x10ce0b580]`이 호출되는 것을 확인할 수 있다.

iOS에서 앱을 실행할 때는 **앱의 Binary** 자체가 실행되고 있다. 따라서 분석하기 위해서는 `ipa` 파일이 아닌 `Binary` 파일을 찾아서 분석해야한다.

단말기와 PC를 같은 네트워크에 연결하고 단말기 네트워크 IP를 통해 **SSH** 붙어서 실행중인 바이너리를 검색한다._(탈옥 후 기본 ROOT 패스워드는 **alpine**이다)_

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5a51d272-2494-4f86-9327-70ac65e6e6a8">
</p>

`ssh`로 붙은 이후 앱을 실행하고 `ps -ef | grep /var`를 입력하게 되면 사용중인 바이너리의 위치를 확인할 수 있다.

해당 파일을 **WinSCP**를 통해 PC로 이동시켜 **Ghidra**나 **IDA, Hopper**를 통해 분석을 진행하면 된다.


<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/cb9a01b1-4e92-4e74-9686-9fb13b59ff11">
</p>

IDA를 통해 확인하면 호출 분기에서 의심되는 부분은 `jailbreatkTest1TappedyypF`만이 존재한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/1aae8de7-3221-4ad5-bbad-91333ab5d8e9">
</p>

해당 분기로 접근하였을 때 어떠한 Jailbreak 탐지 요소가 보이지 않기에 `lldb-10`를 통한 디버깅으로 파악해야한다.

### 바이너리 보호 기법 

Cydia에서 `Darwin CC Tools` 패키지 설치 이후 `otool` 명령어를 통해 바어니리 보호 기법을 확인할 수 있다.

```
XX-iPhone:/var/containers/Bundle/Application/6FB77D3F-8B52-4BAF-8FEF-3A7801805027/DVIA-v2.app root# otool -vh DVIA-v2
DVIA-v2:
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64   ARM64        ALL  0x00     EXECUTE    65       7112   NOUNDEFS DYLDLINK TWOLEVEL WEAK_DEFINES BINDS_TO_WEAK PIE
```

`PIE` 보호기법으로 메모리상의 명령어들의 위치가 실행할 때 마다 변경되기에 바이너리에서 확인된 함수의 주소로 직접 호출이 불가능하다.

따라서 확인된 함수의 주소를 알기 위해서는 `Method Start Address - Image Address + Method Offset`의 과정으로 알 수 있고 계산된 주소로 함수 호출이 가능하다.

### LLDB-10

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/ee2ffe7f-89db-4291-a9fe-5928afd811f3">
</p>

Cydia에서 `LD64` 패키지를 설치하고 `lldb-10 -p {process_id}` 혹은 `lldb-10 -n {APP-NAME}`으로 디버깅을 진행할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/76782e1f-1176-4957-8c1d-fac8c37ed912">
</p>

`image dump sections {APP-NAME}`을 통해 해당 앱에 메모리 섹션을 확인할 수 있다. 이후 **#LLDB-10** 에서 설명한 방법으로 함수의 위치를 찾아야 한다.

* **빨간 네모** : `Method Start Address`

* **주황 네모** : `Image Address`

    * 따라서, `ASLR offset`은 `0x3e8000`

Method Offset은 frida-trace를 통해 `jailbreakTest1Tapped`를 확인했기에 IDA를 통해 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/00db46cf-caf7-4496-8b5f-45de05af9c29">
</p>

해당 함수의 Offset은 `0000000100192C10`이며 실질적인 함수의 주소는 `0x3e8000+0x00000100192C10` 가 된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/55c669b4-0ac6-4ee2-9378-ac0d8b93d5cf">
</p>

`lldb`로 해당 앱을 디버그 잡은 상태에서 `br s -a 0x3e8000+0x00000100192C10` 명령어로 Breakpoint 설정하고 **c(continue)**를 통해 실행이 가능하다. 이 상태에서 다시 **Jailbreak Test1** 버튼 클릭 시 해당 Breakpoint에서 멈추는 것을 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/392c8154-85d1-4565-bd67-0019a17fade7">
</p>

`n(next)`로 한 줄씩 넘어가면 `0x10057ac94 <+132>` 라인에서 `blr x9` 코드를 만날 수 있는데 해당 코드는 x9 레지스터의 값으로 **branch**, 즉 해당 주소로 넘어 가는 코드로 `register read x9`로 레지스터의 값을 확인하면 `showAlert......IsJailBroken`의 함수로 이동하는 것을 알 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/2b7aa780-fb91-49c6-8cfd-0d15d04bac29">
</p>

`showAlert` 함수를 확인하면 두 가지의 분기가 나오게 되는데 어느 한 값을 통해서 `Device is Jailbroken` 혹은 `Device is Not Jailbroken`의 Alert을 나타나게 되는 것을 알 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/101fb265-d717-4947-9955-ee5fb45758e0">
</p>

`blr x9`에서 `s(step in)` 명령어로 해당 분기로 진입하여 흐름을 진행하다보면 `0x1005b3dd0 <+36>` 분기를 만나는데 `tbz w0, #0x0, 0x1005b417c` 코드를 만날 수 있다.

w0 레지스터의 값이 0x0과 같은 경우 `0x1005b417c` 분기를 가게 되는데 해당 분기는 탈옥이 감지 되지 않았을 때의 분기이다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/5227f25d-11df-43dd-b4b5-87944db96c9b">
</p>

해당 분기에서 `register read w0`로 레지스터의 값을 확인한 결과 `0x1`이기에 탈옥 감지 Alert의 분기로 가게 된다. `register write w0 0` 명령어로 해당 분기를 통과하기 위해 값을 변경하여 진행한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/1f402c5f-3ad2-4894-90ed-dfa6bd1586c3" width = 450>
</p>

이후 `c(continue)` 명령어를 통해 진행하게 되면 `Device is Not Jailbroken` Alert가 발생하며 탈옥 감지 우회가 가능하다.

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

    var custom_0x1CBDD0 = module_base.add(0x1CBDD0); // add function offset
    console.log(colors.red, "[*] custom_0x1CBDD0 : " + custom_0x1CBDD0, colors.reset);

    Interceptor.attach(custom_0x1CBDD0, {
        onEnter: function (args) {
            // console.log(colors.blue, "[*] jailbreakTest1Tapped Entered", colors.reset);
            console.log(colors.green, "\n[+] Register\n" + JSON.stringify(this.context) + "\n");
            this.context.x0 = 0x0;
            console.log(colors.green, "[+] Register\n" + JSON.stringify(this.context) + "\n");
        }
    });
}
```

IDA를 통해서 `tbz w0, #0x0, 0xoooooooo` 분기를 확인하여 해당 함수의 offset을 확인하면 `0x1CBDD0` 임을 알 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/57f39e93-c7e5-436a-89fe-137657ea8022">
</p>

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