---
layout: post
title: Reversing | Dreamhack rev-basic-2
subtitle: rev-basic-2 문제 풀이
categories: Reversing
tags: [Reversing, dreamhack, Assembly]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/227756677-eb6473d0-bab2-492e-afb3-912a2d212ba7.png" width = 550>
</p>

해당 프로그램을 통해 문자열 입력을 받아 옳은 입력 값임을 증명해야한다. 바이너리 분석을 위해 IDA를 사용하겠습니다.

### 분석

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[256]; // [rsp+20h] [rbp-118h] BYREF

  memset(v4, 0, sizeof(v4));
  sub_1400011B0("Input : ", argv, envp);
  sub_140001210("%256s", v4);
  if ( (unsigned int)sub_140001000(v4) )
    puts("Correct");
  else
    puts("Wrong");
  return 0;
```

입력 값을 256자를 받으며 해당 `v4[256]` 배열에 저장한다.

해당 값이 `sub_140001000(v4)` 함수를 통해 return 값이 1이면 해결된다.

### sub_140001000(v4)

```C
__int64 __fastcall sub_140001000(__int64 a1)
{
  int i; // [rsp+0h] [rbp-18h]

  for ( i = 0; (unsigned __int64)i < 0x12; ++i )
  {
    if ( *(_DWORD *)&aC[4 * i] != *(unsigned __int8 *)(a1 + i) )
      return 0i64;
  }
  return 1i64;
}
```

입력 받은 값 하나와 `aC` 배열을 하나씩 비교한다.

`aC`의 인덱스를 하나씩 증가하는 것이 아닌 4의 배수로 진행하고 있는 것을 알 수 있다.

```armasm
.text:000000014000101A loc_14000101A:                          ; CODE XREF: sub_140001000+10↑j
.text:000000014000101A                 movsxd  rax, [rsp+18h+var_18]
.text:000000014000101E                 cmp     rax, 12h
.text:0000000140001022                 jnb     short loc_140001048
.text:0000000140001024                 movsxd  rax, [rsp+18h+var_18]
.text:0000000140001028                 lea     rcx, aC         ; "C"
.text:000000014000102F                 movsxd  rdx, [rsp+18h+var_18]
.text:0000000140001033                 mov     r8, [rsp+18h+arg_0]
.text:0000000140001038                 movzx   edx, byte ptr [r8+rdx]
.text:000000014000103D                 cmp     [rcx+rax*4], edx // <-- HERE
.text:0000000140001040                 jz      short loc_140001046
.text:0000000140001042                 xor     eax, eax
.text:0000000140001044                 jmp     short loc_14000104D
```

`.text:000000014000103D`을 보면 디스어셈블한 코드와 같이 4의 배수로 값을 가져와 비교하는 것을 알 수 있다.

그래서 비교 대상인 `aC`를 확인해보면 아래와 같다.

```armasm
.data:0000000140003000 aC              db 'C',0                ; DATA XREF: sub_140001000+28↑o
.data:0000000140003002                 align 4
.data:0000000140003004 aO              db 'o',0
.data:0000000140003006                 align 8
.data:0000000140003008 aM              db 'm',0
.data:000000014000300A                 align 4
.data:000000014000300C aP              db 'p',0
.data:000000014000300E                 align 10h
.data:0000000140003010 a4              db '4',0
.data:0000000140003012                 align 4
.data:0000000140003014 aR              db 'r',0
.data:0000000140003016                 align 8
.data:0000000140003018 aE              db 'e',0
.data:000000014000301A                 align 4
.data:000000014000301C                 db '_',0
.data:000000014000301E                 align 20h
...
```

데이터의 주소 또한 4의 배수로 진행되고 있었고, 값 하나 하나를 조합하게 되면 플래그인 것을 알 수 있다.