---
layout: post
title: iOS DVIA-v2 | Side Channel Data Leakage (Keystroke Logging)
subtitle: Key Logging 정보 취약점
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

* **좌측 상단 메뉴 > Side Channel Data Leakage > Keystroke Logging**

**iOS 8.0**부터 Apple에서는 커스텀 키보드와 같은 iOS용 커스텀 확장 프로그램을 설치할 수 있다. 설치된 커스텀 키보드는 **설정 > 일반 > 키보드 > 키보드**를 통해 관리할 수 있는데 이러한 커스텀 키보드는 입력 시 발생하는 데이터를 공격자 서버로 전송하는데 사용할 수도 있기에 주의가 필요하다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/b8262973-2c14-4f29-bd83-054cd249b322" width = 450>
</p>

텍스트 필드에 아무런 값을 입력하고 아래의 디렉토리로 이동하여 파일이 생성 되어 있는지 확인해본다.

```
applications sandbox in Library/Keyboard/{locale}-dynamic-text.dat

/private/var/mobile/Library/Keyboard/dynamic-text.dat

/private/var/mobile/Library/Keyboard/{locale}-dynamic.lm/dynamic-text.dat
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/bf291c11-4aa0-48eb-a5d7-fac2d800346a">
</p>

현재 확인된 파일로는 `dynamic-lexicon.dat`로 iOS에서 제공하고 있는 커스텀 `UiLexicon` 키보드인 것으로 확인된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/6ff0f993-4629-424e-8a81-349f2d425e46">
</p>

키보드에 입력했던 내용이 파일에 저장되어 있는 것을 확인할 수 있다. 모든 키보드에서의 로깅이 적용되는 것이 아닌 커스텀 키보드으로 적용된 경우 입력 시 파일이 자동으로 저장된다.

## 대응 방안

* 앱 자체에서 커스텀 키보드를 제공하는 것이 아니라면 별도의 키보드를 설치하여 사용하지 않는 것을 권장한다.

* 자동 완성 기능을 해제시켜 캐싱이 활성화 하는 것을 방지 할 수 있다. 또한, PIN 및 비밀번호와 같이 주요 정보에 대한 데이터를 마스킹 처리한다.

    ```swift
    textObject.autocorrectionType = UITextAutocorrectionTypeNo;
    textObject.secureTextEntry = YES;
    ```

    ```swift
    UITextField *textField = [ [ UITextField alloc ] initWithFrame: frame ];
    textField.autocorrectionType = UITextAutocorrectionTypeNo;
    ```

## Reference

* [https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting#custom-keyboards-keyboard-cache](https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting#custom-keyboards-keyboard-cache)