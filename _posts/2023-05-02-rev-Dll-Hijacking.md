---
layout: post
title: DLL Hijacking
subtitle: DLL Hijacking 정의 및 실습
categories: Reversing
tags: [Reversing, DLL]
---

## DLL Hijacking 정의

[Harness를 이용한 WinAFL](https://peoplstar.github.io/fuzzing/2023/04/11/etc-WinAFL-Harness.html#h-dll)에서 **DLL**을 제작하면서 **DLL**이 무엇인지를 설명했습니다.

`DLL`은 **Dynamic Link Library**로 여러 프로그램에서 동시에 사용할 수 있는 코드와 데이터를 포함한 라이브러리로, 어떤 프로그램을 실행할 때 거의 필수적으로 참조하는 것이 동적 라이브러리 파일인 DLL이다.

이 **DLL 파일**을 공격자가 악의적인 코드로 제작하여 프로그램이 실행될 때 참조하게 만듬으로써 공격자가 원하는 기능이 수행되게 되는 것을 DLL 하이재킹(DLL Hijacking)이라고 한다.

어느 한 프로그램이 DLL을 참조하기 위해서 디렉토리를 탐색하며 파일을 찾게 되는데 아래의 경로를 탐색하게 된다.

* `.` : 프로그램이 존재하는 현재 디렉토리로, 가장 우선순위가 높으며 먼저 탐색을 진행

* `windows`

* `windows/system32`

* `windows/sysWOW64` : 우선순위가 가장 낮고, 가장 마지막에 탐색이 진행

## Process Monitor

해당 프로그램이 어떤 DLL 파일을 참조하려고 하는지 확인을 하기 위해서 `Process Monitor`라는 프로그램이 필요하다.

* [https://learn.microsoft.com/en-us/sysinternals/downloads/procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

`프로세스 모니터`는 실시간 파일 시스템, 레지스트리 및 프로세스/스레드 작업을 보여 주는 Windows용 고급 모니터링 도구입니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/232651404-029ed308-d364-480d-9c0a-e07727851f5a.png">
</p>

이러한 UI를 가지고 있으며 `Filter` 기능을 통해 해당 프로그램에 대한 로그만 뽑을 수 있다.

* Process Name is `Example.exe`

* Path contains `dll`

* Result contains `NAME NOT FOUND`

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/232651737-dcd5f864-c94a-437a-a7a4-d3c4ddab4367.png">
</p>

이 처럼 필터 기능을 활성화 시키고 타케팅했던 프로그램을 실행하게 되면 이렇게 제대로 참조하지 못하는 `dll` 파일들만 보여준다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/232652394-a973edf8-6202-44f2-93db-796cc4a9f9d7.png">
</p>

제일 우선순위가 높은 탐색 구조인 `.` 현재 경로를 통해 참조하지 못한 DLL파일을 임의로 작성하여 실행하여 해당 DLL 파일이 실행된다면 `DLL Hijacking`

### DLL

```cpp
#include <Windows.h>
#include <iostream>
#include <string>
using namespace std;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH: {
            // DLL이 프로세스에 연결될 때 실행되는 코드
            DWORD pid = GetCurrentProcessId(); // 현재 프로세스 ID를 가져옴
            char buf[256];
            sprintf(buf, "PROCESS ID: %d", pid); // 메세지 박스에 표시할 문자열 생성
            MessageBoxA(NULL, buf, "PROCESS ID", MB_OK); // 메세지 박스 생성
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}
```

```bash
i686-w64-mingw32-gcc main.cpp -shared -o output.dll -lstdc++ # 32BIT
x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll -lstdc++ # 64BIT
```
지금 실행중인 Process의 ID 즉 `PID`를 `MessageBox`를 이용해 출력하는 DLL입니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/232793023-924c0484-cf0e-4b62-b1ea-c043ab021eb1.png">
</p>

이후 악성프로그램 실행, 레지스트리 수정 등 거의 모든 동작이 가능하여 권한 상승 공격으로도 많이 연계된다고 합니다.

또한 `kali`의 `msfvenom`을 이용한 리버스 쉘까지 가능하며 많은 공격 기법으로 연계가 가능합니다.

> 참고

* [효투의 세상](https://hyotwo.tistory.com/168)

* [https://pentesttools.net/robber-robber-is-open-source-tool-for-finding-executables-prone-to-dll-hijacking/](https://pentesttools.net/robber-robber-is-open-source-tool-for-finding-executables-prone-to-dll-hijacking/)
