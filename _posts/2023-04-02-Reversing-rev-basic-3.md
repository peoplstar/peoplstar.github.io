---
layout: post
title: Reversing | Dreamhack rev-basic-3
subtitle: rev-basic-3 문제 풀이
categories: Reversing
tags: [Reversing, dreamhack, Assembly]
use_math: true
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/227757122-96f5d71b-5447-462c-84bc-bc5a1c2f6f30.png" width = 550>
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

  for ( i = 0; (unsigned __int64)i < 0x18; ++i )
  {
    if ( byte_140003000[i] != (i ^ *(unsigned __int8 *)(a1 + i)) + 2 * i )
      return 0i64;
  }
  return 1i64;
}
```

입력 받은 값을 $i$와 $xor$ 연산한 값에 $2i$를 더한 값과 기본 값을 비교하게 된다.

XOR 연산은 아래와 같은 규칙이 있다.

$
a \oplus b = c\\
a \oplus c = b\\
b \oplus c = a
$

이러한 규칙을 이용하여 입력 값이 무엇이 되어야 하는지 알 수 있다.

$
b = (i \oplus a[i]) + 2i\\
b - 2i = (i \oplus a[i])\\
(b - 2i) \oplus i = a[i]
$

```python
data = '''
49h, 60h, 67h, 74h, 63h, 67h, 42h, 66h, 80h, 78h, 69h, 69h
7Bh, 99h, 6Dh, 88h, 68h, 94h, 9Fh, 8Dh, 4Dh, 0A5h, 9Dh
45h
'''
rst = ''
lst_3000 = list(filter(None, data.replace('h', '').replace(',', '').replace('\n', ' ').split(' ')))

for i in range(len(lst_3000)):
    rst += chr((int(lst_3000[i], 16) - 2 * i) ^ i)

print(rst)
```

해당 규칙을 이용하여 Python으로 수식을 만들면 위와 같게 되고 플래그를 뽑을 수 있다.