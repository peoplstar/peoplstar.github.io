---
layout: post
title: WinDbg 디버깅 
subtitle: WinDbg 설치 및 사용법
categories: Fuzzing
tags: [pwnable, reversing]
---

## What is WinDbg ?

마이크로소프트에서 만든 윈도우 디버깅 프로그램으로 `Windows DDK`(드라이버 개발 SDK) 설치 시 기본적으로 제공된다. 이 프로그램은 윈도우 커널을 디버깅하여 버그를 찾는데 사용하는데, 기존 CTF pwnable 문제 풀이할 때에는 Linux 환경의 `ELF` 파일을 많이 사용했다.

윈도우 관련 프로그램 리버싱을 준비하면서 윈도우 환경에 맞는 디버거를 사용하기에는 이를 사용한다.

2017년에 UI가 전체적으로 바뀌며 `Windows DDK` 별도 설치 없이 Micro Store에서 쉽게 설치가 가능하다.

## Install

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/229695024-d521ca66-5d5c-41f5-90ac-a0c9ffcbf362.png" width = 600> 
</p>

앞서 말씀드린 바와 같이 **Microsoft Store**를 통해 쉽게 다운 받을 수 있습니다. 설치 후 열어보면 아래와 같은 UI 입니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/229695229-3fa0fb12-0f98-4983-bed1-6967a0b85031.png" width = 600> 
</p>

## Command

### k : STACK TRACE 

현재 스레드의 `CallStack`을 출력

> **`k + 옵션`**

* `b` : 함수의 Argument

* `n` : Frame Sequence Number

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/229695562-4c2958a2-4698-4b24-be8d-c96a92314365.png" width = 500> 
</p>

* `.frame /c \[Frame Num\]` : 확인된 Call Stack으로 이동

### ~ : THREAD CONTROL

특정 thread로 Context 스위치를 하거나 특정 thread에 대한 정보를 표시

> **`~ + Thread number + command`**

* `~` : 현재 스레드 확인 (정보 출력)

* `~*` : 현재 스레드에 대한 자세한 정보 출력

* `~*k` : 현재 프로세스에서 실행 중인 모든 스레드의 `Call Stack` 출력

* `~12` : 12번 스레드의 정보 출력

* `~12s` : 12번 스레드로 **Context Switch**, 해당 스레드 Context에서 변수 조회나 Call Stack 확인 가능

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/229695797-2d4b138d-229f-4cab-adf9-7b59dc9a9b43.png" width = 500> 
</p>

스레드 관련 출력은 위 그림과 같이 하단의 **Thread** 메뉴에도 함께 자세히 나온다.

* `.cxr` : Call Stack 및 Thread Context Switch 초기화

### Display 계열

* `db` : Data **1byte** 단위 Byte 출력

* `dd` : Data **4byte DWORD** 단위로 Byte 출력

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/229696846-0950c004-a067-478a-b2fe-a18326481239.png" width = 300> 
</p>

* `du/da` : Data 유니코드 / ANSI(ASCII 확장) 문자열 출력

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/229695797-2d4b138d-229f-4cab-adf9-7b59dc9a9b43.png" width = 500> 
</p>

* `dt [module]!DataType [Address]` : 구조체 파싱

### Unassemble

* `u [Address]` : 해당 주소의 어셈블리 코드 출력

* `uf [FunctionName]` : 주어진 함수 전체의 어셈블리 출력

* `u reg L10` : 해당 레지스터로부터 10개의 어셈블리 출력

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/229697206-2c7e2212-ad06-4dd2-bbff-9e3bb09f0f6a.png" width = 500> 
</p>

### Break Point

* `bp [Address]` : 해당 주소에 1회성 Break Point 설정

    * 재시작 시 사라짐

* `bu [Address]` : bp와 달리 영구적 Break Point 설정

* `bl` : 현재 설정한 Break Point 목록 출력

WinDbg는 해당 Break Point 목록을 출력할 때 뿐만 아니라 여러 명령어에서도 Command창에 출력된 링크를 클릭하여 **BreakPoint 해제**, **문자별 모듈 출력**등 많은 기능을 지원한다.

### Loaded Module

* `lm` : 현재 로딩된 모듈 리스트

* `lmvm [ModuleName]` : 특정 모듈에 대한 정보 출력

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/229697745-4391137f-efa8-498b-8464-a9df5eed3f37.png" width = 500> 
</p>


> 참고

[https://fliphtml5.com/gvunv/sefc/basic](https://fliphtml5.com/gvunv/sefc/basic)