---
layout: post
title: API Hooking
subtitle: API Hooking 정의 및 실습
categories: Reversing
tags: [Reversing, DLL]
---

## API ?

**API**란 `Application Programming Interface`로 운영체제가 응용 프로그램을 위해 제공하는 함수의 집합으로 응용 프로그램과 디바이스를 연결해주는 역할이다.

일반 응용 프로그램은 메모리, 파일, 네트워크 등 시스템 자원을 사용하고 싶어도 직접 접근할 수 없다. 이러한 자원은 운영체제가 보안이나 효율 등 면에서 응용 프로그램이 접근할 수 없도록 차단하기 위해 직접 관리한다.

해당 자원을 사용하기 위해 `Win32 API`를 이용하게 되며 이러한 `API 함수`가 없으면 시스템 자원에 접근 할 수 있는 프로그램을 만들 수 없게 된다.

윈도우 응용 프로그램은 상당히 많은 DLL을 로딩하게 되는데, 모든 프로세스는 `kernel32.dll`이 로딩되며, `kerner32.dll`은 `ntdll.dll`을 로딩하게 된다.

> 이 `ntdll.dll`의 역할이 사용자 모드에서 커널 모드로 요청하는 작업을 수행해 시스템 자원에 접근할 수 있게 한다.

## API Hooking?

`Hooking`이란 이미 운영 체제나 응용 소프트웨어 등의 각종 컴퓨터 프로그램에서 소프트웨어 구성 요소 간에 발생하는 함수 호출, 메시지, 이벤트 등을 중간에서 바꾸거나 가로채는 명령, 방법, 기술이나 행위로

이때 이러한 간섭된 함수 호출, 이벤트 또는 메시지를 처리하는 코드를 `Hook`이라고 한다.

`API Hooking`이라 하면 시스템 자원을 사용할 수 있게 하는 `Win32 API`가 호출될 때 이를 가로채어 제어권을 얻는 것이다.


## User Mode Hooking

Windows에서는 `User mode`와 `Kernel Mode`가 있는데 이 두 모드의 후킹으로 나누어진다. 차이점을 간단히 말씀드리면 시스템 자원에 대해 접근, 명령을 할 수 있는가 없는가로 나눌 수 있다. 

### IAT Hooking

`IAT(Import Address Table)` 후킹은 말 그대로 `Import 주소 테이블`을 후킹하는 것으로 어느 프로그램이 어떠한 라이브러리에서 어떤 함수를 사용하고 있는지 정리된 테이블이다. 

## Message Hooking

> HookMain.cpp

```cpp

#include "stdio.h"
#include "conio.h"
#include "windows.h"

#define DEF_DLL_NAME  L"KeyHook.dll"
#define DEF_HOOKSTART  "HookStart"
#define DEF_HOOKSTOP  "HookStop"

typedef void (*PFN_HOOKSTART)();
typedef void (*PFN_HOOKSTOP)();

void main()
{
    HMODULE   hDll = NULL;
    PFN_HOOKSTART HookStart = NULL;
    PFN_HOOKSTOP HookStop = NULL;
    char   ch = 0;

    // KeyHook.dll 로딩
    hDll = LoadLibrary(DEF_DLL_NAME);

    // export 함수 주소 얻기
    HookStart = (PFN_HOOKSTART)GetProcAddress(hDll, DEF_HOOKSTART);
    HookStop = (PFN_HOOKSTOP)GetProcAddress(hDll, DEF_HOOKSTOP);

    // 후킹 시작
    HookStart();

    // 사용자가 'q' 를 입력할 때까지 대기
    printf("press 'q' to quit!\n");
    while (_getch() != 'q');

    // 후킹 종료
    HookStop();

    // KeyHook.dll 언로딩
    FreeLibrary(hDll);
}
```

> KeyHook.cpp

```cpp
#include "stdio.h"
#include "windows.h"
#include "pch.h"

#define DEF_PROCESS_NAME  "notepad.exe"

HINSTANCE g_hInstance = NULL;
HHOOK g_hHook = NULL;
HWND g_hWnd = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        g_hInstance = hinstDLL;
        break;
        
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    char szPath[MAX_PATH] = { 0, };
    char* p = NULL;

    if (nCode >= 0)
    {
        // bit 31 : 0 => key press, 1 => key release
        if (!(lParam & 0x80000000))
        {
            GetModuleFileNameA(NULL, szPath, MAX_PATH);
            p = strrchr(szPath, '\\');

            // 현재 프로세스 이름을 비교해서 만약 notepad.exe 라면 0 아닌 값을 리턴함
            // => 0 아닌 값을 리턴하면 메시지는 다음으로 전달되지 않음
            if (!_stricmp(p + 1, DEF_PROCESS_NAME))
                return 1;
        }
    }

    // 일반적인 경우에는 CallNextHookEx() 를 호출하여
    // 응용프로그램 (혹은 다음 훅) 으로 메시지를 전달함
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

#ifdef __cplusplus
extern "C" {
#endif
    __declspec(dllexport) void HookStart()
    {
        g_hHook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, g_hInstance, 0);
    }
    __declspec(dllexport) void HookStop()
    {
        if (g_hHook)
        {
            UnhookWindowsHookEx(g_hHook);
            g_hHook = NULL;
        }
    }
#ifdef __cplusplus
}
#endif
```