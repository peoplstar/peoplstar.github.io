---
layout: post
title: Reversing | Dreamhack rev-basic-8
subtitle: rev-basic-8 문제 풀이
categories: dreamhack.io
tags: [Reversing, dreamhack, Assembly]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/78e52e29-cde8-4dae-9ec5-b001f4d80bb2" width = 850>
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
}
```

입력 값을 256자를 받으며 해당 `v4[256]` 배열에 저장한다.

해당 값이 `sub_140001000(v4)` 함수를 통해 return 값이 1이면 해결된다.

### sub_140001000(v4)

```C
__int64 __fastcall sub_140001000(__int64 a1)
{
  int i; // [rsp+0h] [rbp-18h]

  for ( i = 0; (unsigned __int64)i < 0x15; ++i )
  {
    if ( (unsigned __int8)(-5 * *(_BYTE *)(a1 + i)) != byte_140003000[i] )
      return 0i64;
  }
  return 1i64;
}
```

단순히 생각해서 보면 입력 값 `a1 + 1`을 -5로 곱해서 `byte_3000`이 일치한지를 비교한다고 하는데 대체 이해를 할 수 없는 수식이기에 어셈블리로 확인해보겠습니다.

```armasm
movsxd  rax, [rsp+18h+var_18]
mov     rcx, [rsp+18h+arg_0]
movzx   eax, byte ptr [rcx+rax] ; a1 + i 값 대입
imul    eax, 0FBh               ; a1 + i imul 0FBh
and     eax, 0FFh               ; a1 + i and  0FFh
movsxd  rcx, [rsp+18h+var_18]
lea     rdx, byte_140003000
movzx   ecx, byte ptr [rdx+rcx] ; byte_14003000[i] 대입
cmp     eax, ecx
jz      short loc_140001053
```

마지막 비교 구문을 통해서 어떤 것을 비교하는지 보게 되면 `((a1 + i) imul 0FBh) and 0FFh`와 `byte_14003000[i]`이 둘을 비교하게 된다.

* `imul eax, [var]` : var 포인터가 가리키는 값 * eax 를 eax에 저장한다.

* `imul esi, edi, 25` : esi 에 edi * 25를 저장한다.

이 수식을 역연산이 불가하고 규칙을 찾을 수 없기에 **Brute-Force(무작위 대입)** 기법을 통해 해결할 수 있다.

한 글자가 나타낼 수 있는 값의 10진수 범위는 0 ~ 255 **0xFF**이기에 `a1`을 0 부터 255까지 대입시켜 `byte_3000`과 동일한지 비교하면 된다.

```python
data = '''
0ACh, 0F3h, 0Ch, 25h, 0A3h, 10h, 0B7h, 25h, 16h, 0C6h
0B7h, 0BCh, 7, 25h, 2, 0D5h, 0C6h, 11h, 7, 0C5h
'''

rst = ''
lst_3000 = list(filter(None, data.replace('h', '').replace(',', '').replace('\n', ' ').split(' ')))

for i in range(len(lst_3000)):
    for j in range(256):
        x = ((j * 0xFB) & 0xFF)
        if x == int(lst_3000[i], 16):
            rst += chr(j)

print(rst)
```