---
layout: post
title: WinAFL 설치 및 사용
subtitle: Windows American Fuzzy Lob
categories: fuzzing
tags: [Reversing, fuzzing]
---

## WinAFL ?

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/229335223-bb28e81c-81ae-49a6-b2bb-57b43dee3ec5.png" width = 600>
</p>

**WinAFL**을 설명하기 앞서 **AFL**이 무엇인지 말씀드리겠습니다.

**AFL**(American Fuzzy Lob)은 `Coverage-Guided` 퍼징 툴입니다. 기존 AFL은 리눅스 환경만을 위해 만들어졌기에 Windows 환경에서는 구조상 차이로 인해 이용하지 못했다. 이후 Windows에서 AFL을 동작할 수 있게 만든 것이 **WinAFL**입니다.

[이전](https://peoplstar.github.io/fuzzing/2023/04/04/Fuzzing-what-is-fuzz.html#h-%ED%94%84%EB%A1%9C%EA%B7%B8%EB%9E%A8-%EC%84%A0%ED%83%9D)에 설명드린 것과 마찬가지로 총 **5가지**의 방식으로 루틴을 진행하기에 빠른 퍼징 속도를 자랑합니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/230567659-d1e9b010-f1e5-4373-917a-52bb65222326.png" width = 600>
</p>

이처럼 가장 많이 사용되고 있는 운영체제는 **Windows**로 많은 이용자가 Windows를 사용하여 이에 대한 프로그램을 사용하고 있습니다.

그렇기에 fuzzing을 하기에는 `WinAFL`가 통상적으로 많이 사용될 것으로 예상하고 진행하였습니다.

## Install

WinAFL을 사용하기에 앞서 준비물이 필요합니다.

* [`Visual Studio`](https://visualstudio.microsoft.com/ko/downloads/)

* [`DynamoRIO`](https://dynamorio.org/page_releases.html)

* [`Cmake`](https://cmake.org/download/)

* [`WinAFL`](https://github.com/googleprojectzero/winafl)

이렇게 네 개의 준비물이 필요합니다. WinAFL에 대한 자료를 보면 대부분 최신 버전을 이용하고 있지 않지만 저는 최신 버전을 이용해서 진행하도록 하겠습니다.

`Visual Studio`는 설치 시 `C++를 활용한 데스크탑 개발` 항목을 설치해야합니다. 만일 해당 항목을 설치 못했다면 Visual Studio 접근하면 `상단바 - 도구 - 도구 및 기능 가져오기`를 통해서 설치하실 수 있습니다.

(`DynamoRio`와 `WinAFL` 접근을 편하게 하기 위해 `C:\`에 두는 것도 나쁘지 않은 거 같습니다.)

이후 아래와 같은 방법을 통해서 `winafl compile`을 하면 됩니다.

```bash
mkdir build32
cd build32
cmake -G"Visual Studio 17 2022" -A Win32 .. -DDynamoRIO_DIR=%DynamoRIO경로%/cmake
cmake --build . --config Release
```

대상 프로그램이 **32bit**가 아닌 **64bit**라한다면 `Win32` 대신 `x64`로 하면 됩니다.

## 사용법

WinAFL을 사용하기 위해서는 일단 Fuzzing 대상이 될 프로그램이 필요합니다. 이후 앞서 설명드렸던 네 가지 과정이 필요하므로 해당 프로그램에 대해 `untrust input 받는 method`가 있어야 하고, `parsing`, `return` 과정이 있어야 합니다. 

- (네 가지 과정에 대해서 설명한 부분 : [Peoplstar's Note](https://peoplstar.github.io/fuzzing/2023/04/04/Fuzzing-what-is-fuzz.html#h-%ED%83%80%EA%B2%9F-%ED%95%A8%EC%88%98-%EC%84%A0%EC%A0%95))

그래서 아래와 같이 간단한 프로그램을 작성하고 **32bit**로 컴파일하도록 하겠습니다.

### Test File

```C
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    
    char tmp[30];
    char buf[1024];
    FILE* fp;

    if (argc >= 2) {
        fp = fopen(argv[1], "rb");
        if (fp == NULL) {
            printf("CAN NOT LOAD FILE!\n");
            return 1;
        }
        fgets(buf, 1024, fp);
        fclose(fp);
        strcpy(tmp, buf);
        printf("%s\n", tmp);
        return 1;
    }
    return 0;
}
```

### 분석

간단하게 진행하기 위해 `파일 열기, 파일 파싱, 파일 닫기, return`을 `main`함수에 다 넣었습니다. 이렇다는건 `main` 함수를 타겟할 수 있다는 거고 이를 대상으로 퍼징을 할 수 있다는 것 입니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/230867759-60a6517e-c240-4285-bf81-f303e3e51cb8.png" width = 600>
</p>

main의 주소는 `0x401010` 이지만 base 주소를 제외하고 해당 offset은 `0x1010`이 됩니다.

### Cmake Compile

해당 파일이 저장된 디렉토리에 `cmake`를 위한 `CmakeLists.txt` 파일을 만들어 아래와 같이 입력한다.

```cmake
cmake_minimum_required(VERSION 3.0)

project(%PROJECT_NAME%)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(${PROJECT_NAME} %C_SOURCE_FILE_NAME%)
```

해당 파일이 저장된 디렉토리로 접근하여 아래와 같은 명령어를 입력합니다.

```bash
mkdir build
cd build
cmake -G"Visual Studio 17 2022" -A Win32 .. 
cmake --build . --config Release
```

만약 **32bit**가 아닌 **64bit**를 희망하신다면 `Win32` 대신 `x64`를 입력하여서 하신다면 **64bit** 컴파일이 됩니다.

`cmake -G"Visual Studio 17 2022" -A Win32 ..` 입력 후 아래와 같은 화면이 나와야 하고

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/230570393-f90882f1-f023-47fb-a7a4-ddc567623e66.png" width = 600>
</p>

`cmake --build . --config Release` 입력하고 아래와 같이 나오면 컴파일은 끝났습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/230571066-787b3571-4459-46cd-8f51-c84e13428487.png" width = 600>
</p>

`build/bin/Release`를 확인해보면 컴파일된 프로그램이 있습니다.

### Debug Test

퍼징을 하기 앞서 타겟팅하고 있는 함수에 대해서 정상 작동하는지 확인해볼 필요가 있습니다.

`DynamoRIO`를 통해서 타겟 함수 디버깅을 통해서 퍼징에 적합한지 검사합니다.

```bash
cd %DynamoRIO%/bin32
drrun.exe -c %winafl-master_PATH%/build32/bin/Release/winafl.dll -debug -coverage_module target.exe OR .dll_name -target_module target.exe -target_offset 0x1010 -fuzz_iterations 10 -nargs 2 -- %타겟경로% %argv%
```

테스트가 끝나면 `DynamoRIO/bin32`에 테스트 로그가 남으며 마지막에 `Everything appears to be running normally.`로 끝나면 퍼징에 적합하다는 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/230861762-d6fef3c9-b3e5-46b3-a8e2-5bb33695d5df.png" width = 350>
</p>

### Coverage

프로그램이 실행될 때 `Code Coverage`를 분석해주는 도구로, 실행 중 어떤 **block**들을 거쳐갔는지 로깅(logging)을 해줍니다.

```bash
cd %DynamoRIO%/bin32
drrun.exe -t drcov -- %FILE_NAME%
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/230857696-f59e0d2b-37da-4c87-98e2-4bf95f0debd8.png" width = 600>
</p>

해당 로그파일은 `IDAPro lighthouse Plugin`을 활용하면 coverage 정보를 쉽게 확인할 수 있습니다.

사용하는 방법은 [링크](https://cosyp.tistory.com/236)를 통해서 확인해보시면 됩니다!

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/230858446-898aa436-a62f-4b31-9cd6-6d139c7bb67e.png" width = 600>
</p>


### Mininum Corpus

해당 작업을 하기 앞서 파일 수정이 필요합니다.

`%winafl경로%/winafl-cmin.py` 파일을 `afl-fuzz.exe`가 있는 경로로 옮긴 후 파일을 열고 **@@**의 문자열을 **\@@**로 모두 바꾸시면 됩니다.

이후 Input Data의 파일이 담긴 디렉토리, `cmin` 작업 결과를 저장할 디렉토리를 만들고 아래와 같이 진행하고 결과물이 생성되었는지 확인하면 됩니다.

```bash
python ./winafl-cmin.py -D C:/_fuzz/DynamoRIO-Windows-9.0.1/bin32 -t 100000 -i %input_dir% -o %output_dir% -covtype edge -coverage_module target.exe -target_offset 0x1010 -target_method %method_name% -nargs 2 -- %타겟경로% \@@ 
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/230856914-0c6febd9-aa88-425d-9671-5f1adbe6bb94.png" width = 600>
</p>

### Let's fuzz

모든 과정이 끝났기에 아래 명령어를 입력하여 진행하면 됩니다.

```bash
cd %winafl%/build32/bin/Release
./afl-fuzz.exe -i %input_dir% -o %output_dir% -D %DynamoRio/bin32% -t 5000+ -- -target_module target.exe -target_offset 0x1010 -coverage_module target.exe -nargs 2 -- %타겟경로% \@@
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/230868960-2aa94805-050b-4387-8a7f-9e3ebbaa651f.png" width = 600>
</p>

퍼징을 진행하면서 `uniq crashes`된 경우 로그 파일을 확인하여 어떠한 문제 있었는지 확인할 수 있습니다.

(그리고 명령어 중 `target_offset` offset 값을 넣었는데 추후 Harness 작성하게 되면 Harness 내부 함수를 사용하게 되는데 이때는 `target_method` 인자로 변경하여 사용이 가능하다.)


## 참고 

* [Hackyboiz](https://hackyboiz.github.io/2021/05/23/fabu1ous/winafl-1/)

* [https://blog.csdn.net/qq_41988448/article/details/115176224](https://blog.csdn.net/qq_41988448/article/details/115176224)
