---
layout: post
title: Reversing | Dreamhack rev-basic-1
subtitle: rev-basic-1 문제 풀이
categories: dreamhack.io
tags: [Reversing, dreamhack, Assembly]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/227756440-f60fe339-373d-4eaa-98f0-5e7c22136556.png" width = 550>
</p>

해당 프로그램을 통해 문자열 입력을 받아 옳은 입력 값임을 증명해야한다. 바이너리 분석을 위해 IDA를 사용하겠습니다.

### 분석

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[256]; // [rsp+20h] [rbp-118h] BYREF

  memset(v4, 0, sizeof(v4));
  sub_140001190("Input : ", argv, envp);
  sub_1400011F0("%256s", v4);
  if ( (unsigned int)sub_140001000(v4) )
    puts("Correct");
  else
    puts("Wrong");
  return 0;
}
```

입력 값을 256자를 받으며 해당 `v4[256]` 배열에 저장한다.

해당 값이 `sub_140001000(v4)` 함수를 통해 return 값이 1이면 해결된다.

### sub_140001000(v4)

```C
_BOOL8 __fastcall sub_140001000(_BYTE *a1)
{
  if ( *a1 != 67 )
    return 0i64;
  if ( a1[1] != 111 )
    return 0i64;
  if ( a1[2] != 109 )
    return 0i64;
  if ( a1[3] != 112 )
    return 0i64;
  if ( a1[4] != 97 )
    return 0i64;
  if ( a1[5] != 114 )
    return 0i64;
  if ( a1[6] != 51 )
    return 0i64;
  if ( a1[7] != 95 )
    return 0i64;
  if ( a1[8] != 116 )
    return 0i64;
  if ( a1[9] != 104 )
    return 0i64;
  if ( a1[10] != 101 )
    return 0i64;
  if ( a1[11] != 95 )
    return 0i64;
  if ( a1[12] != 99 )
    return 0i64;
  if ( a1[13] != 104 )
    return 0i64;
  if ( a1[14] != 52 )
    return 0i64;
  if ( a1[15] != 114 )
    return 0i64;
  if ( a1[16] != 97 )
    return 0i64;
  if ( a1[17] != 99 )
    return 0i64;
  if ( a1[18] != 116 )
    return 0i64;
  if ( a1[19] != 51 )
    return 0i64;
  if ( a1[20] == 114 )
    return a1[21] == 0;
  return 0i64;
}
```

각 글자별로 해당 아스키 값과 같은지를 비교한다.

총 글자수는 22자임을 알 수 있고, 해당 값을 아스키로 변환한다면 플래그는 쉽게 찾을 수 있을 것이다.

```python
data = [67, 111, 109, 112, 97, 114, 51, 95, 116, 104, 101, 95, 99, 104, 52, 114, 97, 99, 116, 51, 114, 0]
rst = ''

for i in data:
    rst += chr(i)

print(rst)
```

`Coxxxxx_xxx_xxxxxxxxr`와 같은 플래그가 나오는 것을 확인할 수 있습니다.