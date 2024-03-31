---
layout: post
title: Harness를 이용한 WinAFL
subtitle: WinAFL Harness 작성
categories: Fuzzing
tags: [Reversing, fuzzing]
---

[저번 내용](https://peoplstar.github.io/fuzzing/2023/04/10/etc-WinAFL.html)에서는 단순히 함수의 `offset`을 가지고 Fuzzing을 시도해봤습니다.

많은 프로그램들이 **Windows** 대상이다 보니 `WinAFL`을 사용했는데 이전처럼 단순히 함수의 `offset`을 가지고 퍼징하기에는 어려움이 있습니다.

왜냐? 한번쯤은 보셨을 법한 `DLL`이라는 내용이 있기 때문입니다.

**DLL**이 무엇인지 간단히 집고 넣어 가겠습니다.

## DLL

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/231070047-84320e31-44f6-4fb6-b1fa-6f4833b6d11d.png" width = 400>
</p>

**Dynamic Link Library**로 여러 프로그램에서 동시에 사용할 수 있는 코드와 데이터를 포함한 라이브러리입니다.

메모장, 그림판, 한글 워드와 같이 다양한 윈도우용 프로그램을 보면 파일 열기와 같은 기능이 있는데 이를 누를 시 어떤 파일을 선택할 지 창이 뜨는 것을 볼 수 있는데

**파일 선택 창**의 기능을 담당하는 `DLL`을 불러오기 때문이라 생각하면 됩니다.

파일 자체 실행 시 **파일 선택**의 함수는 연결되어 있지 않지만, **파일 선택**을 선택하면 해당 함수가 `DLL 파일` 내에 있는 해당 함수 주소를 로딩시키는 `동적 링크 라이브러리`입니다.

대부분의 프로그램이 하나의 `.exe`에서 모든 함수를 불러오는게 아니라 이 `DLL` 파일을 이용하여 함수를 로딩하기에 저번과 달리 `Harness`라는 작업을 이용할 계획입니다.

## 준비 단계

### DLL 작성

`Harness` 작업을 하기 위해서는 `DLL`이 있어야 하는데 [이젠 테스트 파일](https://peoplstar.github.io/fuzzing/2023/04/10/etc-WinAFL.html#h-test-file)과 같은 로직으로 진행하도록 하여 만들겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/231074868-6ddd166d-c9a7-4912-aad9-a95ae723347c.png" width = 700>
</p>

Visual Studio에서 프로젝트 생성 **DLL(동적 연결 라이브러리)** 를 선택하면 소스 파일에는 `dllmain.cpp, pch.cpp`, 헤더 파일에는 `framework.h, pch.h`가 존재합니다.

소스 파일 -> 우클릭 -> 추가, 새 항목을 선택하여 `cpp` 파일을 생성합니다.

```C
#include "pch.h"
#include <windows.h>
#include <stdio.h>
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

extern "C" __declspec(dllexport) int Parsing(char* path) {

    char tmp[30];
    char buf[1024];
    FILE* fp;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        printf("CAN NOT LOAD FILE!\n");
        return 1;
    }

    fgets(buf, 1024, fp);
    fclose(fp);
    strcpy(tmp, buf);
    printf("%s\n", tmp);

    return 0;
}
```

해당 내용을 적고 **컴파일(Ctrl + F7)**, **디버그 하지 않고 시작(Ctrl + F5)** 이후 해당 프로젝트 내에 `Debug` 디렉토리로 가면 아래처럼 `dll`파일이 생성된 것을 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/231075967-1bbc026d-e7a3-4887-b759-99ded0bf7bca.png" width = 600>
</p>

### DLL 로드 프로그램

다시 Visual Studio로 돌아와서 **솔루션 탐색기**에서 **솔루션 -> 우클릭 -> 추가, 새 프로젝트**에서 **빈 프로젝트**를 생성하면 아래처럼 두 가지의 프로젝트가 열린 것을 볼 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/231077059-f6dff0dd-48c1-4df4-a847-2e857d4dd191.png" width = 400>
</p>

새로 생성한 프로젝트의 소스 파일에서 `load.cpp`라는 파일을 생성하고 

```C
#include <stdio.h>
#include <Windows.h>

typedef int(*METHOD)(char *path);
METHOD p_sum;

int main(int argc, char* argv[]) {
	HINSTANCE sum_dll = LoadLibrary(L"CreateDLL.dll");
	p_sum = (METHOD)GetProcAddress(sum_dll, "Parsing");
	
	(*p_sum)(argv[1]);
	return 0;
}
```

해당 내용을 적으면 `파일 열기, 파싱 하기, 닫기, return`의 과정을 담은 `CreateDLL.dll`의 `Parsing` 함수를 로드하여 실행하는 프로그램을 만들 수 있습니다.

* 해당 링크에 해당 파일을 첨부해드리겠습니다. [Peoplstar's Github](https://github.com/peoplstar/C-plus-plus-DLL-Link)

## Harness

지금은 `파일 열기, 파싱 하기, 닫기, return`의 과정의 함수 하나만을 간단하게 프로그램했지만 실제로는 무수히 많은 로직과 GUI 로딩이 있을 겁니다.

불필요한 리소스를 제외하고 원하는 과정 하나만 무수히 퍼징하기 위해서 이 `Harness`를 작성하게 됩니다.

퍼징 과정과 `Harness`에 대한 내용은 링크 첨부하겠습니다. [Peoplstar's Note](https://peoplstar.github.io/fuzzing/2023/04/04/Fuzzing-what-is-fuzz.html#h-harness)

`Harness`의 로직은 아래와 같습니다.

* 타겟으로 하는 `DLL` 로드

* `DLL` 내부 타겟 함수 로드

* **퍼징 !**

> 코드로 보면 이렇습니다.

```C
#include <stdio.h>
#include <Windows.h>
#include <iostream>
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

typedef int(*TARGET)(wchar_t* filename);
TARGET Inspect;

extern "C" __declspec(dllexport) __declspec(noinline) int fuzz_me(wchar_t* path);

wchar_t* charToWChar(const char* text)
{
    size_t size = strlen(text) + 1;
    wchar_t* wa = (wchar_t*)malloc(sizeof(wchar_t) * size);
    mbstowcs(wa, text, size);
    return wa;
}

int fuzz_me(wchar_t* filename) {
    Inspect(filename);
    return 0;
}

int main(int argc, char** argv)
{
    HMODULE DLLHandle = LoadLibrary(L"DLL PATH");
    int isDetected = 0;

    if (DLLHandle == 0) {
        fprintf(stderr, "[*] Error: Unable to open target dll\n");
        return -1;
    }
    // Inspect = (TARGET)GetProcAddress(DLLHandle, "Parsing"); <-- Here
    
    Inspect = (TARGET)((char*)DLLHandle + 0x11262);

    int result = fuzz_me(charToWChar(argv[1]));
    printf("%d\n", result);
}
```

타겟으로 하는 함수의 인자 개수가 적을수록 로딩 속도도 빠르고, `Harness` 작성에도 유리합니다.

주석 처리한 `GetProcAddress`함수에 대해서 설명드리면 `LoadLibrary`를 통해서 `DLL Base address`를 가져오고 이를 통해 내부의 함수 이름을 가져와 그 함수를 로딩하게 됩니다.

하지만 `GetProcAddress`가 포함되어 있지 않는 DLL의 경우에는 아래처럼 base address에 해당 함수의 offset을 직접 넣어 로드하는 방법이 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/231082376-eeb7cd29-fac7-47c6-8d7d-79e2ad61b2a9.png">
</p>

이처럼 `IDA`를 이용해 해당 DLL파일을 열어 `Exports` 테이블에 알고자 하는 함수를 클릭하여 `offset`이 몇인지 확인할 수 있습니다.

## Debug TEST

이렇게 작성한 `Harness`가 제대로 작동하는지 확인하기 위해 디버그 테스트를 진행하도록 하겠습니다.

이는 이전 [WinAFL 설치 및 사용](https://peoplstar.github.io/fuzzing/2023/04/10/etc-WinAFL.html#h-debug-test)과 비슷하지만 내부에 들어가는 옵션에 대해서 조금씩은 다르기에 언제, 어떻게 값을 넣어야 할 지 확인을 잘 해야 합니다.

이번 프로그램을 작성하면서 64bit로 진행했기에 `DynamoRIO`, `winafl` 모두 64bit 파일을 활용합니다.

```bash
cd %DynamoRIO%/bin64
drrun.exe -c %winafl/build64/bin/Release/winafl.dll% -debug -target_module harness.exe -coverage_module %TargetDLLPath% -target_method fuzz_me -fuzz_iterations 10 -nargs 1 -- %Harness.exePath% %InputFilePath%
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/231083936-cde438a3-5522-49f1-8fb5-f1855aaf25cf.png" width = 400>
</p>

`DynamoRIO/bin64` 디렉토리에 가면 디버그 테스트한 로그 파일이 남는데 `Everything appears to be running normally.`가 있다면 성공적으로 작성한 것을 의미합니다.

## FUZZ !

작성한 `Harness`가 정상 작동하는 것을 확인했으므로 바로 퍼징을 진행하면 됩니다.

```bash
cd %winafl%/build64/bin/Release
afl-fuzz.exe -i ./afl_in -o ./afl_out -D C:/_fuzz/DynamoRIO-Windows-9.0.1/bin64 -t 10000+ -- -coverage_module %TargetDLL% -target_module Harness.exe -target_method fuzz_me -fuzz_iterations 5000 -nargs 1 -- %HarnessFilePath% \@@
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/231084986-aa9d6db4-fd7e-4bd5-b968-09300ef859da.png">
</p>

이로써 간단한 프로그램에 대해서 `Winafl`를 활용한 퍼징 튜토리얼을 마치도록 하겠습니다 !

> 참고

* [https://blog.naver.com/PostView.nhn?blogId=tipsware&logNo=221359282016&parentCategoryNo=&categoryNo=83&viewDate=&isShowPopularPosts=true&from=search](https://blog.naver.com/PostView.nhn?blogId=tipsware&logNo=221359282016&parentCategoryNo=&categoryNo=83&viewDate=&isShowPopularPosts=true&from=search)

* [https://f01965.com/2020/11/07/winAFL%E5%AE%9E%E8%B7%B5/](https://f01965.com/2020/11/07/winAFL%E5%AE%9E%E8%B7%B5/)

* [https://binarygenes.com/posts/2020-04-11-greybox-fuzzing-with-winafl](https://binarygenes.com/posts/2020-04-11-greybox-fuzzing-with-winafl)