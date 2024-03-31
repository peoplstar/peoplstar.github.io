---
layout: post
title: Reversing | Dreamhack Inject ME!!!
subtitle: Inject ME!!! 문제 풀이
categories: dreamhack.io
tags: [Reversing, dreamhack, Assembly]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/3ffb431a-f8d8-438d-a186-512e17924405" width = 550>
</p>

해당 문제에 대한 파일은 DLL 파일 하나이며 해당 DLL파일을 조건에 맞춰 로드시키라고 되어 있는 문제입니다.

주어진 DLL 파일을 임의의 파일을 통해 로드시키면 될 것으로 보입니다.

### prob_rev.dll

```C
BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  if ( fdwReason == 1 )
    sub_1800011A0(hinstDLL);
  return 1;
}
```

* `if ( fdwReason == 1 )` : `fdwReason`으로는 DLL 진입점 함수가 호출되는 이유에 대한 값으로, **1**인 경우 `LoadLibrary`를 통한 호출의 결과일 경우를 뜻한다.

즉, 임의의 프로그램에서 **prov_rev.dll** 파일은 Load 하면 이후 함수로 진입이 가능하다는 것이다.

### sub_1800011A0(hinstDLL)

기본 인자로 `hinstDLL`가 포함되어 있는데 이는 DLL 파일의 기본 주소를 뜻한다.

```C
int sub_1800011A0()
{
  int result; // eax
  unsigned __int64 i; // [rsp+20h] [rbp-2D8h]
  unsigned __int64 k; // [rsp+28h] [rbp-2D0h]
  unsigned __int64 j; // [rsp+30h] [rbp-2C8h]
  char *Str1; // [rsp+38h] [rbp-2C0h]
  CHAR Text[4]; // [rsp+58h] [rbp-2A0h] BYREF
  int v6; // [rsp+5Ch] [rbp-29Ch]
  int v7; // [rsp+60h] [rbp-298h]
  int v8; // [rsp+64h] [rbp-294h]
  int v9; // [rsp+68h] [rbp-290h]
  int v10; // [rsp+6Ch] [rbp-28Ch]
  int v11; // [rsp+70h] [rbp-288h]
  int v12; // [rsp+74h] [rbp-284h]
  int v13; // [rsp+78h] [rbp-280h]
  int v14; // [rsp+7Ch] [rbp-27Ch]
  int v15[16]; // [rsp+80h] [rbp-278h] BYREF
  CHAR Filename[272]; // [rsp+C0h] [rbp-238h] BYREF
  CHAR pszPath[272]; // [rsp+1D0h] [rbp-128h] BYREF

  GetModuleFileNameA(0i64, Filename, 0x104u);
  Str1 = PathFindFileNameA(Filename);
  result = strncmp(Str1, "dreamhack.exe", 0xDui64);
  if ( !result )
  {
    memset(v15, 0, sizeof(v15));
    for ( i = 0i64; i < 0x10; ++i )
    {
      GetModuleFileNameA(0i64, pszPath, 0x104u);
      v15[i] = __ROL4__(*(_DWORD *)PathFindFileNameA(pszPath), i);
    }
    sub_180001010(v15);
    for ( j = 0i64; j < 0x64; ++j )
      sub_180001060();
    *(_DWORD *)Text = 1775475848;
    v6 = 926668331;
    v7 = 2010799913;
    v8 = 1005204386;
    v9 = -999457954;
    v10 = 1958751758;
    v11 = -1319895682;
    v12 = 1873281418;
    v13 = 1481654649;
    v14 = -671573750;
    for ( k = 0i64; k < 0xA; ++k )
      *(_DWORD *)&Text[4 * k] ^= sub_180001060();
    return MessageBoxA(0i64, Text, "flag", 0);
  }
  return result;
}
```

`!result` 분기만 통과하면 어떠한 값이 기준이 되는 것이 아는 순차적으로 복잡한 복호화 과정을 통해 `MessageBoxA`를 통해 Flag를 추출해주는 것으로 보인다.

```C
  GetModuleFileNameA(0i64, Filename, 0x104u);
  Str1 = PathFindFileNameA(Filename);
  result = strncmp(Str1, "dreamhack.exe", 0xDui64);
  if ( !result )
```

해당 분기를 들어가기 위해서는 **prob_rev.dll** 파일을 로드하는 프로그램의 이름이 **dreamhack.exe**이면 되는 것으로 보인다.

```C
#include <windows.h>

int main() {
    LoadLibraryA("prob_rev.dll");
    return 0;
}
```

해당 코드를 통해 단순히 Dll파일을 로드합니다. Dll 파일을 명시할 때 해당 파일의 경로를 확실히 입력하여야 합니다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/7d7fba7d-577b-4b08-b031-7190800c3bcd" width = 400>
</p>