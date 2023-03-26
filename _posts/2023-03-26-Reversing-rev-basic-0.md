---
layout: post
title: Reversing | Dreamhack rev-basic-0
subtitle: rev-basic-0 문제 풀이
categories: Reversing
tags: [Reversing, dreamhack, Assembly]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/227756269-2a8e8ad7-eeda-4d3f-bf8b-2f6acd43f7c4.png" width = 550>
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
_BOOL8 __fastcall sub_140001000(const char *a1)
{
  return strcmp(a1, "Compar3_the_str1ng") == 0;
}
```

입력 값 `a1`를 파라미터로 전달받아 **Compar3_the_str1ng**와 같은지 비교하기에 해당 문구가 플래그인 것을 알 수 있다.

단순히 IDA나 다른 디버거를 통해 바이너리를 확인할 수 있는지에 대한 기본 문제인 것으로 보인다.