---
layout: post
title: Reversing | Dreamhack rev-basic-7
subtitle: rev-basic-7 문제 풀이
categories: Reversing
tags: [Reversing, dreamhack, Assembly]
use_math: true
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/3d6d31d9-fdf5-4208-ba16-f3482d4bc252" width = 850>
</p>

해당 프로그램을 통해 문자열 입력을 받아 옳은 입력 값임을 증명해야한다. 바이너리 분석을 위해 IDA를 사용하겠습니다.

### 분석

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[256]; // [rsp+20h] [rbp-118h] BYREF

  memset(v4, 0, sizeof(v4));
  sub_140001120("Input : ", argv, envp);
  sub_1400011B0("%256s", v4);
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

  for ( i = 0; (unsigned __int64)i < 0x1F; ++i )
  {
    if ( (i ^ (unsigned __int8)__ROL1__(*(_BYTE *)(a1 + i), i & 7)) != byte_140003000[i] )
      return 0i64;
  }
  return 1i64;
}
```

`__ROL1__`이란 함수에 인자로 `(a1 + i), (i & 7)` 두 개가 들어가고 해당 return 값을 `byte_3000`과 비교하게 된다. `__ROL1__`이란 함수가 따로 정의 되어 있는지 확인해보면 내장 함수인 것을 알 수 있다.

```armasm
rol     al, cl
```

해당 함수의 어셈블리는 이렇게 한 줄의 어셈블리로 끝나게 되는데 어떤 역할을 하는지 확인해볼 필요가 있다.

**ROL, ROR, LSL, LSR**이 어셈블리는 `<<, >>`와 같이 쉬프트 연산으로 이용되고 **LSL, LSR**은 쉬프트 연산하고 빈자리를 0으로 채우지만, **ROL, ROR**은 빈자리 없이 회전, 로테이션을 하게 된다.

즉 `ROL 1001 0000, 1` 의 연산이 있다면 결과는 **0010 0001**이 된다.

```C
if ( (i ^ (unsigned __int8)__ROL1__(*(_BYTE *)(a1 + i), i & 7)) != byte_140003000[i] )
```

연산을 따라가게 되면 입력 값 `a1`을 인덱스 `i`와 `7`의 `AND` 연산 값 만큼 `ROL`하고 인덱스 `i` 값으로 `XOR` 연산한 값이 `byte_3000`인지 확인한다.


* **$i\;\;xor\;\;input\;\;rol\;\;i\;\;=\;\;d$**

* **$input\;\;rol\;\;i\;\;=\;\;d\;\;xor\;\;i$**

* **$input\;\;=\;\;(d\;\;xor\;\;i)\;\;ror\;\;(i\;\;and\;\;7)$**

`XOR` 연산은 반대에 적용해도 동일한 값이 나오는 점과 `ROL`의 로테이션을 반대로 하면 동일한 값이 나오는 점을 이용하여 식을 변형하게 되면 이처럼 입력 값을 하나의 식으로 표현할 수 있게 된다.

```python
data = '''
52h, 0DFh, 0B3h, 60h, 0F1h, 8Bh, 1Ch, 0B5h, 57h, 0D1h
9Fh, 38h, 4Bh, 29h, 0D9h, 26h, 7Fh, 0C9h, 0A3h, 0E9h
53h, 18h, 4Fh, 0B8h, 6Ah, 0CBh, 87h, 58h, 5Bh, 39h, 1Eh,
'''

def ror(x, n):
    shiftBit = x >> n
    carryBit = x << (8 - n)
    carryBit &= 255
    return shiftBit | carryBit

rst = ''
lst_3000 = list(filter(None, data.replace('h', '').replace(',', '').replace('\n', ' ').split(' ')))
j = 0

for i in range(len(lst_3000)):
    if j > 7:
        j = 0
    val = ror(int(lst_3000[i], 16) ^ i, j)
    rst += chr(val)
    j += 1
   
print(rst)
```