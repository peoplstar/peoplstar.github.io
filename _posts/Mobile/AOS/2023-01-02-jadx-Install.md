---
layout: post
title: Jadx 설치
subtitle: Frida Android Rooting Detection Bypass
categories: AOS
tags: [Android, frida, rooting]
---

## Jadx

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210162785-dfae7e1f-f5b6-4545-86d2-10f1bd1558ca.png" width = 240>
</p>

안드로이드 Dex 및 APK 파일에서 자바 소스 코드를 생성해 보여는 CLI 및 GUI 도구인 `jadx` 프로그램이다. 

안드로이드 apk 분석 디컴파일러인 jadx-gui 디컴파일러는 기존 jd-gui의 불편한 점(dex2jar를 이용한 dex→jar 변환)을 개선하여, dex2jar 도구의 없이도 apk 디컴파일이 가능하다.

또한, 소스코드 뿐만 아니라 리소스 부분도 확인이 가능하도록 기능을 확장하였다.

`jadx`는 Git Release에서 원하는 버전을 다운받아서 사용하시면 됩니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210162823-c9c11198-4eb1-41a2-a0e6-36a7301c6798.png" width = 440>
</p>

* [jadx github](https://github.com/skylot/jadx/releases/)

또한, `jadx`는 JRE(Java Runtime Environmenet)의 최신 버전은 선호하기에 cmd를 키고 `java -version`를 입력했을 때 없다고 나오는 분은 **JRE** 설치를 하셔야 합니다.

* [Oracle JRE](https://www.oracle.com/java/technologies/downloads/#jdk19-windows)

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210162851-9dc60cef-8d2c-46e8-8e2a-4bd0764590b6.png" width = 540>
</p>

각 운영체제에 맞게 JRE를 설치하고나서 아래의 명령 프롬프트를 키고

```
C:\Users\users>java -version
java version "19.0.1" 2022-10-18
Java(TM) SE Runtime Environment (build 19.0.1+10-21)
Java HotSpot(TM) 64-Bit Server VM (build 19.0.1+10-21, mixed mode, sharing)
```

제대로 설치된 것을 알 수 있다.

이렇게 되면 비로소 `jadx`를 사용해볼 수 있다.

`jadx-1.4.5 > bin > jadx-gui.bat` 해당 배치 파일을 실행하면 아래처럼 성공적으로 작동하는 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210162991-577482e4-1fac-4dee-8961-433bc5acefc4.png" width = 540>
</p>